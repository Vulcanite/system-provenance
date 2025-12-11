package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================
// 1. PROCESS UUID GENERATION
// ============================================

// GenerateProcessUUID creates a unique process identifier that survives PID reuse
// Uses: hostname + PID + process_start_time (from /proc or eBPF)
// Returns 16-char hex string
func GenerateProcessUUID(hostname string, pid uint32, processStartTimeNs uint64) string {
	data := fmt.Sprintf("%s:%d:%d", hostname, pid, processStartTimeNs)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // 16 hex chars
}

// GenerateParentUUID creates UUID for parent process
func GenerateParentUUID(hostname string, ppid uint32, parentStartTimeNs uint64) string {
	return GenerateProcessUUID(hostname, ppid, parentStartTimeNs)
}

// ============================================
// 2. BATCHED FILE WRITER
// ============================================

// BatchedFileWriter buffers writes and flushes periodically or when buffer is full
// Reduces syscall overhead from 1 write per event to 1 write per batch
type BatchedFileWriter struct {
	file   *os.File
	buffer *bytes.Buffer
	mu     sync.Mutex

	// Configuration
	maxBufferSize int           // Flush when buffer exceeds this (bytes)
	flushInterval time.Duration // Max time between flushes

	// State
	lastFlush time.Time
	stopChan  chan struct{}
	wg        sync.WaitGroup

	// Metrics (atomic)
	bytesWritten   uint64
	flushCount     uint64
	eventsBuffered uint64
}

// NewBatchedFileWriter creates a new batched writer
// maxBufferSize: flush when buffer exceeds this (e.g., 64KB = 65536)
// flushInterval: flush at least this often (e.g., 5 seconds)
func NewBatchedFileWriter(path string, maxBufferSize int, flushInterval time.Duration) (*BatchedFileWriter, error) {
	if maxBufferSize <= 0 {
		maxBufferSize = 64 * 1024 // 64KB default
	}
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	bw := &BatchedFileWriter{
		file:          f,
		buffer:        bytes.NewBuffer(make([]byte, 0, maxBufferSize*2)),
		maxBufferSize: maxBufferSize,
		flushInterval: flushInterval,
		lastFlush:     time.Now(),
		stopChan:      make(chan struct{}),
	}

	// Start background flusher
	bw.wg.Add(1)
	go bw.backgroundFlusher()

	return bw, nil
}

func (bw *BatchedFileWriter) Rotate() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	// 1. Flush existing buffer to the old file
	if bw.buffer.Len() > 0 {
		bw.file.Write(bw.buffer.Bytes())
		bw.buffer.Reset()
	}

	// 2. Close the old file
	bw.file.Close()

	// 3. Open the new file (created by logrotate)
	newFile, err := os.OpenFile(bw.file.Name(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to rotate log: %v", err)
	}

	bw.file = newFile
	bw.lastFlush = time.Now()
	return nil
}

// Write adds JSON data to the buffer (non-blocking unless buffer is huge)
func (bw *BatchedFileWriter) Write(jsonBytes []byte) {
	bw.mu.Lock()
	bw.buffer.Write(jsonBytes)
	bw.buffer.WriteByte('\n')
	atomic.AddUint64(&bw.eventsBuffered, 1)

	// Flush if buffer is full
	shouldFlush := bw.buffer.Len() >= bw.maxBufferSize
	bw.mu.Unlock()

	if shouldFlush {
		bw.Flush()
	}
}

// WriteEvent marshals and writes an event
func (bw *BatchedFileWriter) WriteEvent(event interface{}) error {
	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}
	bw.Write(jsonBytes)
	return nil
}

// Flush writes buffer to disk
func (bw *BatchedFileWriter) Flush() {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	if bw.buffer.Len() == 0 {
		return
	}

	n, err := bw.file.Write(bw.buffer.Bytes())
	if err != nil {
		// Log error but don't lose data - keep in buffer for retry
		return
	}

	atomic.AddUint64(&bw.bytesWritten, uint64(n))
	atomic.AddUint64(&bw.flushCount, 1)
	bw.buffer.Reset()
	bw.lastFlush = time.Now()
}

// backgroundFlusher ensures data is written even under low volume
func (bw *BatchedFileWriter) backgroundFlusher() {
	defer bw.wg.Done()
	ticker := time.NewTicker(bw.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-bw.stopChan:
			bw.Flush() // Final flush
			return
		case <-ticker.C:
			bw.mu.Lock()
			timeSinceFlush := time.Since(bw.lastFlush)
			hasData := bw.buffer.Len() > 0
			bw.mu.Unlock()

			if hasData && timeSinceFlush >= bw.flushInterval {
				bw.Flush()
			}
		}
	}
}

// Close flushes remaining data and closes the file
func (bw *BatchedFileWriter) Close() error {
	close(bw.stopChan)
	bw.wg.Wait()
	bw.Flush()
	return bw.file.Close()
}

// GetStats returns writer statistics
func (bw *BatchedFileWriter) GetStats() (bytesWritten, flushCount, eventsBuffered uint64) {
	return atomic.LoadUint64(&bw.bytesWritten),
		atomic.LoadUint64(&bw.flushCount),
		atomic.LoadUint64(&bw.eventsBuffered)
}

// ============================================
// 3. DENOISER MODULE
// ============================================

// Denoiser filters repetitive events to reduce noise
// Uses sliding window frequency analysis
type Denoiser struct {
	// Pattern tracking
	patterns   map[string]*patternStats
	patternsMu sync.RWMutex

	// Configuration
	config DenoiseConfig

	// Metrics (atomic)
	totalEvents    uint64
	filteredEvents uint64

	// Lifecycle
	stopChan chan struct{}
	wg       sync.WaitGroup
}

type DenoiseConfig struct {
	WindowDuration time.Duration // Time window for frequency analysis (default: 60s)
	NoiseThreshold int           // Events in window to consider noise (default: 50)
	MaxPatterns    int           // Max patterns to track (default: 10000)

	// Process allowlist - never filter these (security-sensitive)
	AllowlistComms map[string]bool

	// Process blocklist - always filter these (known noisy)
	BlocklistComms map[string]bool

	// Only apply denoising to these event types (empty = all)
	// Recommended: only "filesystem" since process/network events are usually important
	ApplyToEventTypes map[string]bool
}

type patternStats struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
}

// DefaultDenoiseConfig returns sensible defaults
func DefaultDenoiseConfig() DenoiseConfig {
	return DenoiseConfig{
		WindowDuration: 60 * time.Second,
		NoiseThreshold: 50, // 50+ events in 60s = noise
		MaxPatterns:    10000,

		// Security-sensitive processes - NEVER filter
		AllowlistComms: map[string]bool{
			"sudo": true, "su": true, "ssh": true, "sshd": true,
			"passwd": true, "useradd": true, "usermod": true, "groupadd": true,
			"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
			"scp": true, "rsync": true, "ftp": true, "sftp": true,
			"bash": true, "sh": true, "zsh": true, "dash": true,
			"python": true, "python3": true, "perl": true, "ruby": true,
			"gcc": true, "g++": true, "make": true, "ld": true,
			"chmod": true, "chown": true, "chgrp": true,
			"mount": true, "umount": true,
			"iptables": true, "nft": true, "firewall-cmd": true,
			"crontab": true, "at": true, "systemctl": true,
		},

		// Known noisy processes - ALWAYS filter
		BlocklistComms: map[string]bool{
			"systemd-journal": true, "systemd-oomd": true, "systemd-resolve": true,
			"systemd-timesyn": true, "systemd-network": true, "systemd-udevd": true,
			"irqbalance": true, "thermald": true, "acpid": true,
			"snapd": true, "packagekitd": true, "unattended-upg": true,
			"NetworkManager": true, "wpa_supplicant": true, "dhclient": true,
			"dbus-daemon": true, "polkitd": true,
			"multipathd": true, "lvm": true,
			"gmain": true, "gdbus": true,
		},

		// Only denoise filesystem events by default
		// Process and network events are usually security-relevant
		ApplyToEventTypes: map[string]bool{
			"filesystem": true,
		},
	}
}

// NewDenoiser creates a new denoiser
func NewDenoiser(config DenoiseConfig) *Denoiser {
	d := &Denoiser{
		patterns: make(map[string]*patternStats),
		config:   config,
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	d.wg.Add(1)
	go d.cleanup()

	return d
}

// ShouldFilter returns true if the event should be DROPPED (is noise)
func (d *Denoiser) ShouldFilter(eventType, comm, syscall, filename string) bool {
	atomic.AddUint64(&d.totalEvents, 1)

	// Check if event type should be denoised
	if len(d.config.ApplyToEventTypes) > 0 && !d.config.ApplyToEventTypes[eventType] {
		return false // Don't filter this event type
	}

	// Allowlist check - never filter security-sensitive processes
	if d.config.AllowlistComms[comm] {
		return false
	}

	// Blocklist check - always filter known noisy processes
	if d.config.BlocklistComms[comm] {
		atomic.AddUint64(&d.filteredEvents, 1)
		return true
	}

	// Generate pattern key: comm + syscall + directory (not full filename)
	dir := extractDir(filename)
	patternKey := fmt.Sprintf("%s|%s|%s", comm, syscall, dir)

	now := time.Now()

	d.patternsMu.Lock()
	defer d.patternsMu.Unlock()

	stats, exists := d.patterns[patternKey]
	if !exists {
		// New pattern - track it
		if len(d.patterns) >= d.config.MaxPatterns {
			// Evict oldest
			d.evictOldestLocked()
		}
		d.patterns[patternKey] = &patternStats{
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		}
		return false // New patterns always pass
	}

	// Update existing pattern
	stats.Count++
	stats.LastSeen = now

	// Check if within window
	windowStart := now.Add(-d.config.WindowDuration)
	if stats.FirstSeen.Before(windowStart) {
		// Reset window
		stats.FirstSeen = now
		stats.Count = 1
		return false
	}

	// Check threshold
	if stats.Count >= d.config.NoiseThreshold {
		atomic.AddUint64(&d.filteredEvents, 1)
		return true // Filter as noise
	}

	return false
}

// evictOldestLocked removes oldest pattern (caller must hold lock)
func (d *Denoiser) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, stats := range d.patterns {
		if first || stats.LastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = stats.LastSeen
			first = false
		}
	}

	if oldestKey != "" {
		delete(d.patterns, oldestKey)
	}
}

// cleanup periodically removes stale patterns
func (d *Denoiser) cleanup() {
	defer d.wg.Done()
	ticker := time.NewTicker(d.config.WindowDuration)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopChan:
			return
		case <-ticker.C:
			d.patternsMu.Lock()
			cutoff := time.Now().Add(-d.config.WindowDuration * 2)
			for key, stats := range d.patterns {
				if stats.LastSeen.Before(cutoff) {
					delete(d.patterns, key)
				}
			}
			d.patternsMu.Unlock()
		}
	}
}

// GetStats returns denoiser statistics
func (d *Denoiser) GetStats() (total, filtered uint64, ratio float64) {
	total = atomic.LoadUint64(&d.totalEvents)
	filtered = atomic.LoadUint64(&d.filteredEvents)
	if total > 0 {
		ratio = float64(filtered) / float64(total) * 100
	}
	return
}

// Close stops the denoiser
func (d *Denoiser) Close() {
	close(d.stopChan)
	d.wg.Wait()
}

// extractDir gets directory from path (for pattern grouping)
func extractDir(path string) string {
	if path == "" {
		return ""
	}
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return ""
}
