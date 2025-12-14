package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
)

type AuditdCollector struct {
	cfg         Config
	bulkIndexer esutil.BulkIndexer
	client      *libaudit.AuditClient
	reassembler *libaudit.Reassembler
	stopChan    chan struct{}
	fileWriter  *BatchedFileWriter

	// Performance monitoring
	eventsReceived  uint64
	eventsProcessed uint64
	eventsDropped   uint64
}

func (ac *AuditdCollector) RotateLog() {
	if cfg.AuditdConfig.FileLoggingEnabled && ac.fileWriter != nil {
		if err := ac.fileWriter.Rotate(); err != nil {
			log.Printf("[!] auditd Log Rotation Failed: %v", err)
		} else {
			log.Println("[+] auditd Log Rotated")
		}
	}
}

type AuditEvent struct {
	// ECS: Base fields
	Module    string `json:"event.module"`
	HostName  string `json:"host.name"`
	Timestamp string `json:"@timestamp"`

	// ECS: Event fields
	EpochTimestamp int64  `json:"timestamp"`
	Type           string `json:"event.category"`
	Sequence       uint32 `json:"event.sequence"`
	Summary        string `json:"message"`

	// ECS: Process fields (ADDED)
	ProcessPID  string `json:"process.pid,omitempty"`
	ProcessPPID string `json:"process.parent.pid,omitempty"`
	ProcessName string `json:"process.name,omitempty"`
	ProcessExe  string `json:"process.executable,omitempty"`
	UserAUID    string `json:"user.id,omitempty"` // Audit User ID (login uid)

	// Process correlation fields
	ProcessUUID string `json:"process.entity_id,omitempty"`
	ParentUUID  string `json:"process.parent.entity_id,omitempty"`

	// Additional fields
	Category string                 `json:"category"`
	RawData  map[string]interface{} `json:"raw_data"`
	Tags     []string               `json:"tags"`
}

func NewAuditdCollector(cfg Config, bi esutil.BulkIndexer) *AuditdCollector {
	ac := &AuditdCollector{
		cfg:         cfg,
		bulkIndexer: bi,
		stopChan:    make(chan struct{}),
	}

	if cfg.AuditdConfig.FileLoggingEnabled {
		path := fmt.Sprintf("%s/auditd-events.jsonl", cfg.EventsDir)
		bw, err := NewBatchedFileWriter(path, 64*1024, 5*time.Second)
		if err != nil {
			log.Printf("[!] Warning: Failed to create batched writer: %v", err)
		} else {
			ac.fileWriter = bw
			log.Printf("[+] Batched file writer enabled: %s (64KB buffer, 5s flush)", path)
		}
	}

	return ac
}

// Filter noisy syscalls that don't add provenance value
func shouldSkipEvent(msgType auparse.AuditMessageType) bool {
	skipTypes := map[auparse.AuditMessageType]bool{
		auparse.AUDIT_PROCTITLE: true, // 1327 - verbose, low value for provenance
		auparse.AUDIT_EOE:       true, // 1320 - end of event marker
		// Add more based on your specific noise analysis from BEEP
	}
	return skipTypes[msgType]
}

func (ac *AuditdCollector) Start() error {
	var err error
	ac.client, err = libaudit.NewAuditClient(nil)
	if err != nil {
		return fmt.Errorf("failed to create audit client (requires root): %v", err)
	}

	status, err := ac.client.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get audit status: %v", err)
	}

	log.Printf("[*] Current Audit Status: Enabled=%d, PID=%d, Backlog=%d", status.Enabled, status.PID, status.BacklogLimit)
	if status.Enabled == 0 {
		log.Println("[*] Enabling kernel auditing...")
		if err := ac.client.SetEnabled(true, libaudit.WaitForReply); err != nil {
			return fmt.Errorf("failed to enable auditing: %v", err)
		}
	}

	// CRITICAL FIX: Increase buffer significantly to prevent "lost events" under load
	// 65536 is much larger than default 8192
	if err := ac.client.SetBacklogLimit(65536, libaudit.NoWait); err != nil {
		log.Printf("[!] Warning: Failed to increase backlog limit to 65536: %v", err)
	} else {
		log.Printf("[+] Set backlog limit to 65536")
	}

	if err := ac.client.SetPID(libaudit.NoWait); err != nil {
		log.Printf("[!] Warning: Failed to set audit PID: %v", err)
	}

	// Create handler with worker pool
	handler := newAuditStreamHandler(ac, 4, 10000) // 4 workers, 10k queue depth

	ac.reassembler, err = libaudit.NewReassembler(5, 2*time.Second, handler)
	if err != nil {
		return fmt.Errorf("failed to create reassembler: %v", err)
	}

	// Maintenance loop for the reassembler (cleans up old partial events)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ac.stopChan:
				return
			case <-ticker.C:
				if err := ac.reassembler.Maintain(); err != nil {
					log.Printf("[!] Reassembler maintenance error: %v", err)
				}
			}
		}
	}()

	// Performance monitoring loop
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ac.stopChan:
				return
			case <-ticker.C:
				received := atomic.LoadUint64(&ac.eventsReceived)
				processed := atomic.LoadUint64(&ac.eventsProcessed)
				dropped := atomic.LoadUint64(&ac.eventsDropped)
				log.Printf("[*] Audit Stats: received=%d processed=%d dropped=%d (%.2f%% loss)",
					received, processed, dropped,
					float64(dropped)/float64(received)*100)
			}
		}
	}()

	fmt.Printf("[+] Auditd Collector Running (PID: %d, Backlog: 65536)\n", status.PID)
	for {
		select {
		case <-ac.stopChan:
			handler.Stop()
			return nil
		default:
			// Receive raw Netlink message
			msg, err := ac.client.Receive(false)
			if err != nil {
				if strings.Contains(err.Error(), "interrupted system call") {
					continue
				}
				log.Printf("[!] Audit Receive Error: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			atomic.AddUint64(&ac.eventsReceived, 1)

			// Filter out non-audit messages (type < 1000 are system control messages)
			// and noisy low-value events
			if msg.Type < 1000 || shouldSkipEvent(msg.Type) {
				continue
			}

			if err := ac.reassembler.Push(msg.Type, msg.Data); err != nil {
				log.Printf("[!] Reassembler Push Error: %v (dropping raw message)", err)
				atomic.AddUint64(&ac.eventsDropped, 1)
			}
		}
	}
}

func (ac *AuditdCollector) Stop() {
	close(ac.stopChan)
	if ac.client != nil {
		log.Println("[*] Stopping audit client and unregistering...")
		if err := ac.client.Close(); err != nil {
			log.Printf("[!] Error closing audit client: %v", err)
		}
	}

	if ac.fileWriter != nil {
		ac.fileWriter.Close()
	}
}

type auditStreamHandler struct {
	collector *AuditdCollector
	workQueue chan []*auparse.AuditMessage
	workers   sync.WaitGroup
	stopChan  chan struct{}
}

func newAuditStreamHandler(collector *AuditdCollector, numWorkers, queueDepth int) *auditStreamHandler {
	h := &auditStreamHandler{
		collector: collector,
		workQueue: make(chan []*auparse.AuditMessage, queueDepth),
		stopChan:  make(chan struct{}),
	}

	// Start worker pool for parallel processing
	for i := 0; i < numWorkers; i++ {
		h.workers.Add(1)
		go h.processWorker(i)
	}

	log.Printf("[+] Started %d audit processing workers with queue depth %d", numWorkers, queueDepth)
	return h
}

func (h *auditStreamHandler) Stop() {
	close(h.stopChan)
	h.workers.Wait()
	close(h.workQueue)
}

func (h *auditStreamHandler) processWorker(id int) {
	defer h.workers.Done()

	for {
		select {
		case <-h.stopChan:
			return
		case msgs, ok := <-h.workQueue:
			if !ok {
				return
			}
			h.processEvent(msgs)
			atomic.AddUint64(&h.collector.eventsProcessed, 1)
		}
	}
}

// Process start time cache to avoid repeated /proc reads
var processStartCache struct {
	sync.RWMutex
	cache map[int]uint64
}

func init() {
	processStartCache.cache = make(map[int]uint64)
}

func getProcessStartTimeCached(pid int) uint64 {
	processStartCache.RLock()
	if cached, ok := processStartCache.cache[pid]; ok {
		processStartCache.RUnlock()
		return cached
	}
	processStartCache.RUnlock()

	startTime := GetProcessStartTime(pid)

	processStartCache.Lock()
	processStartCache.cache[pid] = startTime
	processStartCache.Unlock()

	return startTime
}

// Periodic cache cleanup to prevent unbounded growth
func cleanProcessStartCache() {
	processStartCache.Lock()
	defer processStartCache.Unlock()

	// Clear cache every N entries or use LRU if needed
	if len(processStartCache.cache) > 10000 {
		processStartCache.cache = make(map[int]uint64)
	}
}

// ReassemblyComplete is called when a set of kernel messages forms a complete event
func (h *auditStreamHandler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	if len(msgs) == 0 {
		return
	}

	// Non-blocking send to worker queue to avoid backpressure on reassembler
	select {
	case h.workQueue <- msgs:
		// Successfully queued
	default:
		// Queue full - drop event and increment counter
		atomic.AddUint64(&h.collector.eventsDropped, 1)
		if atomic.LoadUint64(&h.collector.eventsDropped)%1000 == 0 {
			log.Printf("[!] Work queue full, dropped event (total dropped: %d)",
				atomic.LoadUint64(&h.collector.eventsDropped))
		}
	}
}

func (h *auditStreamHandler) processEvent(msgs []*auparse.AuditMessage) {
	// Simplify the raw kernel messages into a high-level event
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		log.Printf("[!] Failed to coalesce audit messages: %v", err)
		return
	}

	// Resolve IDs (e.g. 1000 -> "student")
	aucoalesce.ResolveIDs(event)

	output := AuditEvent{
		Module:         "auditd",
		HostName:       h.collector.cfg.Hostname,
		Timestamp:      event.Timestamp.UTC().Format(time.RFC3339Nano),
		EpochTimestamp: event.Timestamp.UnixMilli(),
		Type:           event.Type.String(),
		Sequence:       event.Sequence,
		Category:       event.Category.String(),
		Summary:        event.Summary.Action,
		RawData:        make(map[string]interface{}),
		Tags:           []string{"auditd", "kernel"},
	}

	// Extract Actors and Objects for easier searching
	if event.Summary.Actor.Primary != "" {
		output.RawData["primary_actor"] = event.Summary.Actor.Primary
	}
	if event.Summary.Object.Primary != "" {
		output.RawData["object"] = event.Summary.Object.Primary
	}
	output.RawData["result"] = event.Result

	for _, msg := range msgs {
		data, err := msg.Data()
		if err == nil {
			for k, v := range data {
				output.RawData[k] = v
				switch k {
				case "pid":
					output.ProcessPID = v
				case "ppid":
					output.ProcessPPID = v
				case "exe":
					output.ProcessExe = v
				case "comm":
					// Remove quotes usually found in audit logs (e.g. "cat")
					output.ProcessName = strings.Trim(v, "\"")
				case "auid":
					output.UserAUID = v
				}
			}
		}
	}

	if output.ProcessName == "" && output.ProcessExe != "" {
		parts := strings.Split(output.ProcessExe, "/")
		if len(parts) > 0 {
			output.ProcessName = parts[len(parts)-1]
		}
	}

	// Generate process correlation UUIDs using cached /proc reads
	if output.ProcessPID != "" {
		if pid, err := strconv.Atoi(output.ProcessPID); err == nil && pid > 0 {
			processStartTime := getProcessStartTimeCached(pid)
			if processStartTime > 0 {
				output.ProcessUUID = GenerateProcessUUID(h.collector.cfg.Hostname, uint32(pid), processStartTime)
			}
		}
	}

	if output.ProcessPPID != "" {
		if ppid, err := strconv.Atoi(output.ProcessPPID); err == nil && ppid > 0 {
			parentStartTime := getProcessStartTimeCached(ppid)
			if parentStartTime > 0 {
				output.ParentUUID = GenerateParentUUID(h.collector.cfg.Hostname, uint32(ppid), parentStartTime)
			}
		}
	}

	// Marshal to JSON
	data, err := json.Marshal(output)
	if err != nil {
		log.Printf("[!] Failed to marshal audit event: %v", err)
		return
	}

	if h.collector.fileWriter != nil {
		h.collector.fileWriter.Write(data)
	}

	// Send to Elasticsearch (if configured)
	if h.collector.bulkIndexer != nil {
		h.collector.bulkIndexer.Add(
			context.Background(),
			esutil.BulkIndexerItem{
				Action: "index",
				Body:   strings.NewReader(string(data)),
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
					log.Printf("[!] Auditd Index Error: %v", err)
				},
			},
		)
	}
}

func (h *auditStreamHandler) EventsLost(count int) {
	atomic.AddUint64(&h.collector.eventsDropped, uint64(count))
	log.Printf("[!] Lost %d audit events (kernel buffer overflow) - consider increasing backlog or filtering more aggressively", count)
}
