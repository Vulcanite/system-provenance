package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"golang.org/x/sys/unix"
)

// eBPFEvent represents a syscall event captured by eBPF
type eBPFEvent struct {
	// ECS: Base fields
	Hostname string `json:"hostname"`
	Module   string `json:"event.module"`

	// ECS: @timestamp fields
	TimestampNs    int64  `json:"timestamp_ns"`
	EpochTimestamp int64  `json:"timestamp"`
	Datetime       string `json:"datetime"`

	// ECS: Process fields
	Pid              uint32 `json:"process.pid"`
	Ppid             uint32 `json:"process.parent.pid"`
	Uid              uint32 `json:"user.id"`
	ParentStartTime  uint64 `json:"parent_start_time"`
	ProcessStartTime uint64 `json:"process_start_time"`
	Comm             string `json:"process.name"`
	Syscall          string `json:"syscall"`
	Filename         string `json:"file.path,omitempty"`
	Fd               int64  `json:"fd"`
	Ret              int64  `json:"ret"`
	EventType        string `json:"event.type,omitempty"`
	Error            string `json:"error.message,omitempty"`
	ErrorCode        int64  `json:"error.code,omitempty"`
	UserUnset        bool   `json:"user_unset"`

	// ECS: Network fields
	SourceIP   string `json:"source.ip,omitempty"`
	DestIP     string `json:"destination.ip,omitempty"`
	SourceIPv6 string `json:"source.ipv6,omitempty"`
	DestIPv6   string `json:"destination.ipv6,omitempty"`
	SourcePort uint16 `json:"source.port,omitempty"`
	DestPort   uint16 `json:"destination.port,omitempty"`
	SaFamily   string `json:"network.type,omitempty"`
	Protocol   uint8  `json:"network.iana_number,omitempty"`
	SocketType uint8  `json:"socket_type,omitempty"`
	FlowID     string `json:"flow.id,omitempty"`

	// I/O fields
	Count   uint64 `json:"count,omitempty"`
	BytesRW int64  `json:"bytes_rw,omitempty"`

	// Process correlation fields
	ProcessUUID string `json:"process.entity_id,omitempty"`
	ParentUUID  string `json:"process.parent.entity_id,omitempty"`
}

// RuntimeMetrics tracks performance metrics
type RuntimeMetrics struct {
	EventsReceived   uint64
	EventsIndexed    uint64
	EventsFiltered   uint64
	LostSamples      uint64
	IndexingFailures uint64
	ChannelDrops     uint64
}

// EBPFCollector handles eBPF program loading and event processing
type EBPFCollector struct {
	cfg         Config
	bulkIndexer esutil.BulkIndexer
	objs        bpfObjects
	links       []link.Link
	perfReader  *perf.Reader
	stopChan    chan struct{}
	eventsChan  chan eBPFEvent
	indexerWg   sync.WaitGroup
	metrics     RuntimeMetrics
	bootTime    time.Time          // Boot time offset for accurate timestamp correlation
	fileWriter  *BatchedFileWriter // Replace outputFile
	denoiser    *Denoiser
}

func (ec *EBPFCollector) RotateLog() {
	if ec.fileWriter != nil {
		if err := ec.fileWriter.Rotate(); err != nil {
			log.Printf("[!] eBPF Log Rotation Failed: %v", err)
		} else {
			log.Println("[+] eBPF Log Rotated")
		}
	}
}

// NewEBPFCollector creates a new eBPF collector instance
func NewEBPFCollector(cfg Config, bulkIndexer esutil.BulkIndexer) (*EBPFCollector, error) {
	realtimeNow := time.Now()

	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return nil, fmt.Errorf("failed to get monotonic time: %v", err)
	}

	monotonicNow := time.Duration(mono.Sec)*time.Second + time.Duration(mono.Nsec)*time.Nanosecond
	bootTime := realtimeNow.Add(-monotonicNow)

	collector := &EBPFCollector{
		cfg:         cfg,
		bulkIndexer: bulkIndexer,
		stopChan:    make(chan struct{}),
		eventsChan:  make(chan eBPFEvent, 50000),
		bootTime:    bootTime,
	}
	log.Printf("[+] Boot time calculated: %s (for timestamp correlation)", bootTime.Format(time.RFC3339Nano))

	if cfg.EBPFConfig.FileLoggingEnabled {
		path := fmt.Sprintf("%s/ebpf-events.jsonl", cfg.EventsDir)
		bw, err := NewBatchedFileWriter(path, 64*1024, 5*time.Second)
		if err != nil {
			log.Printf("[!] Warning: Failed to create batched writer: %v", err)
		} else {
			collector.fileWriter = bw
			log.Printf("[+] Batched file writer enabled: %s (64KB buffer, 5s flush)", path)
		}
	}

	// Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %v", err)
	}

	// Load eBPF objects
	if err := loadBpfObjects(&collector.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %v", err)
	}

	// Attach tracepoints
	if err := collector.attachTracepoints(); err != nil {
		collector.objs.Close()
		return nil, fmt.Errorf("failed to attach tracepoints: %v", err)
	}

	// Populate whitelist rules
	if err := collector.populateWhitelist(); err != nil {
		log.Printf("[!] Warning: Failed to populate eBPF whitelist: %v", err)
	}

	// Populate ignored process names
	if err := collector.populateIgnoredComms(); err != nil {
		log.Printf("[!] Warning: Failed to populate ignored comms: %v", err)
	}

	// Create perf reader with larger buffer to prevent drops during high activity
	// Buffer size = pagesize * 16384 = 4KB * 16384 = 64MB per CPU
	rd, err := perf.NewReader(collector.objs.Events, os.Getpagesize()*16384)
	if err != nil {
		collector.cleanup()
		return nil, fmt.Errorf("failed to create perf reader: %v", err)
	}
	collector.perfReader = rd

	collector.denoiser = NewDenoiser(DefaultDenoiseConfig())
	return collector, nil
}

// populateWhitelist populates the eBPF whitelist map with rules
func (ac *EBPFCollector) populateWhitelist() error {
	// Add Elasticsearch host+port combination
	if ac.cfg.ESConfig.Host != "" && ac.cfg.ESConfig.Port > 0 {
		esHost := ac.cfg.ESConfig.Host
		esPort := ac.cfg.ESConfig.Port

		// Resolve hostname to IP
		ips, err := net.LookupIP(esHost)
		if err != nil {
			return fmt.Errorf("failed to resolve ES host %s: %v", esHost, err)
		}

		// Add all resolved IPs to whitelist
		for idx, ip := range ips {
			// Only handle IPv4 for now
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}

			// Convert IP to uint32 (network byte order)
			ipUint32 := binary.BigEndian.Uint32(ip4)

			// Convert port to network byte order (big endian)
			portUint16 := uint16(esPort)
			portBE := (portUint16 >> 8) | (portUint16 << 8)

			// Create whitelist rule
			rule := bpfWhitelistRule{
				Ip:   ipUint32,
				Port: portBE,
			}

			// Insert into map at index
			key := uint64(idx)
			if err := ac.objs.WhitelistRules.Put(&key, &rule); err != nil {
				return fmt.Errorf("failed to add whitelist rule: %v", err)
			}

			fmt.Printf("[+] eBPF whitelist: Excluding traffic to %s:%d (Elasticsearch)\n",
				ip4.String(), esPort)
		}
	}

	return nil
}

// populateIgnoredComms populates the eBPF ignored_comms map with default process names to ignore
func (ac *EBPFCollector) populateIgnoredComms() error {
	// Default list of process names to ignore
	ignoredComms := []string{
		"ebpf-exporter",
		"system-monitor",
	}

	for _, comm := range ignoredComms {
		// Create key (64-byte array)
		var key [64]byte
		copy(key[:], comm)
		value := uint8(1)

		if err := ac.objs.IgnoredComms.Put(&key, &value); err != nil {
			return fmt.Errorf("failed to add ignored comm %s: %v", comm, err)
		}
		fmt.Printf("[+] eBPF filter: Ignoring process '%s'\n", comm)
	}

	return nil
}

// attachTracepoints attaches all eBPF programs to kernel tracepoints
func (ac *EBPFCollector) attachTracepoints() error {
	attach := func(group, name string, prog *ebpf.Program) error {
		l, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			return fmt.Errorf("failed to attach %s/%s: %v", group, name, err)
		}
		ac.links = append(ac.links, l)
		return nil
	}

	// EXECVE
	if err := attach("syscalls", "sys_enter_execve", ac.objs.SysEnterExecve); err != nil {
		return err
	}

	if err := attach("syscalls", "sys_exit_execve", ac.objs.SysExitExecve); err != nil {
		return err
	}

	// OPEN
	if err := attach("syscalls", "sys_enter_openat", ac.objs.SysEnterOpenat); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_openat", ac.objs.SysExitOpenat); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_openat2", ac.objs.SysEnterOpenat2); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_openat2", ac.objs.SysExitOpenat2); err != nil {
		return err
	}

	// WRITE
	if err := attach("syscalls", "sys_enter_write", ac.objs.SysEnterWrite); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_write", ac.objs.SysExitWrite); err != nil {
		return err
	}

	// READ
	if err := attach("syscalls", "sys_enter_read", ac.objs.SysEnterRead); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_read", ac.objs.SysExitRead); err != nil {
		return err
	}

	// CLOSE (for FD cleanup)
	// NOTE: Requires `go generate` to be run after updating main.bpf.c
	if err := attach("syscalls", "sys_enter_close", ac.objs.SysEnterClose); err != nil {
		return err
	}

	// CLONE
	if err := attach("syscalls", "sys_enter_clone", ac.objs.SysEnterClone); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_clone3", ac.objs.SysEnterClone3); err != nil {
		return err
	}

	// OTHERS
	if err := attach("syscalls", "sys_enter_unlinkat", ac.objs.SysEnterUnlinkat); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_vfork", ac.objs.SysEnterVfork); err != nil {
		return err
	}

	// NETWORK SYSCALLS (Enhanced)
	if err := attach("syscalls", "sys_enter_socket", ac.objs.SysEnterSocket); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_connect", ac.objs.SysEnterConnect); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_connect", ac.objs.SysExitConnect); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_bind", ac.objs.SysEnterBind); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_listen", ac.objs.SysEnterListen); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_accept", ac.objs.SysEnterAccept); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_accept", ac.objs.SysExitAccept); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_accept4", ac.objs.SysEnterAccept4); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_accept4", ac.objs.SysExitAccept4); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_sendto", ac.objs.SysEnterSendto); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_sendto", ac.objs.SysExitSendto); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_recvfrom", ac.objs.SysEnterRecvfrom); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_recvfrom", ac.objs.SysExitRecvfrom); err != nil {
		return err
	}

	fmt.Printf("[+] eBPF monitoring started with %d probes active.\n", len(ac.links))
	return nil
}

func normalizeUID(uid uint32) (uint32, bool) {
	// Linux kernel uses -1 (UINT_MAX) to indicate "unset"
	if uid == ^uint32(0) {
		return 0, true // unset
	}
	return uid, false
}

// Start begins processing eBPF events
func (ac *EBPFCollector) Start() error {
	// Start multiple indexer goroutines for parallel processing
	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		ac.indexerWg.Add(1)
		go ac.indexerWorker()
	}

	// Start metrics reporter
	go ac.reportMetrics()

	// Read from perf buffer and push to channel
	for {
		select {
		case <-ac.stopChan:
			close(ac.eventsChan)
			ac.indexerWg.Wait()
			return nil
		default:
			if err := ac.readPerfEvent(); err != nil {
				if errors.Is(err, perf.ErrClosed) {
					close(ac.eventsChan)
					ac.indexerWg.Wait()
					return nil
				}
				log.Printf("[!] eBPF event processing error: %v", err)
			}
		}
	}
}

// indexerWorker consumes events from channel and indexes them
func (ac *EBPFCollector) indexerWorker() {
	defer ac.indexerWg.Done()

	for evt := range ac.eventsChan {
		if ac.denoiser != nil {
			if ac.denoiser.ShouldFilter(evt.EventType, evt.Comm, evt.Syscall, evt.Filename) {
				atomic.AddUint64(&ac.metrics.EventsFiltered, 1)
				continue // Skip this event
			}
		}

		jsonBytes, err := json.Marshal(evt)
		if err != nil {
			continue
		}

		if ac.fileWriter != nil {
			ac.fileWriter.Write(jsonBytes)
		}

		if ac.bulkIndexer != nil {
			err := ac.bulkIndexer.Add(context.Background(), esutil.BulkIndexerItem{
				Action: "index",
				Body:   bytes.NewReader(jsonBytes),
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
					atomic.AddUint64(&ac.metrics.IndexingFailures, 1)
					if err != nil {
						log.Printf("ES Index Error: %v", err)
					} else {
						log.Printf("ES Item Error: [%d] %s", res.Status, res.Error.Reason)
					}
				},
			})

			if err == nil {
				atomic.AddUint64(&ac.metrics.EventsIndexed, 1)
			}
		}
	}
}

// readPerfEvent reads a single event from the perf buffer and pushes to channel
func (ac *EBPFCollector) readPerfEvent() error {
	record, err := ac.perfReader.Read()
	if err != nil {
		return err
	}

	if record.LostSamples > 0 {
		atomic.AddUint64(&ac.metrics.LostSamples, record.LostSamples)
		log.Printf("[!] Buffer full: dropped %d events", record.LostSamples)
		return nil
	}

	if len(record.RawSample) < int(unsafe.Sizeof(bpfSoEvent{})) {
		log.Printf("[!] Event too small")
		return nil
	}

	raw := *(*bpfSoEvent)(unsafe.Pointer(&record.RawSample[0]))
	evt := ac.parseEvent(&raw)

	atomic.AddUint64(&ac.metrics.EventsReceived, 1)

	// Push to buffered channel (non-blocking)
	select {
	case ac.eventsChan <- evt:
	default:
		ac.metrics.ChannelDrops++
		atomic.AddUint64(&ac.metrics.ChannelDrops, 1)
		log.Printf("[!] Event channel full, dropping event")
	}

	return nil
}

// parseEvent converts raw eBPF event to eBPFEvent
func (ac *EBPFCollector) parseEvent(raw *bpfSoEvent) eBPFEvent {
	// Use kernel monotonic timestamp (bpf_ktime_get_ns) as canonical event time
	kernelTimeNs := int64(raw.Timestamp)
	eventWallclock := ac.bootTime.Add(time.Duration(kernelTimeNs))

	uid, uidUnset := normalizeUID(raw.Uid)

	evt := eBPFEvent{
		Hostname:       ac.cfg.Hostname,
		Module:         "ebpf",
		TimestampNs:    kernelTimeNs, // Canonical kernel event time (monotonic)
		EpochTimestamp: eventWallclock.UnixMilli(),
		Datetime:       eventWallclock.UTC().Format(time.RFC3339Nano),

		Pid:  raw.Pid,
		Ppid: raw.Ppid,

		// 🔧 FIX: normalized UID
		Uid:              uid,
		ParentStartTime:  raw.ParentStartTime,
		ProcessStartTime: raw.ProcessStartTime,
		Comm:             int8ToStr(raw.Comm[:]),
		Syscall:          int8ToStr(raw.Syscall[:]),
		Filename:         int8ToStr(raw.Filename[:]),
		Fd:               raw.Fd,
		Ret:              raw.Ret,
		Protocol:         raw.Protocol,
		SocketType:       raw.SocketType,
	}

	evt.UserUnset = uidUnset

	// Set event type classification
	switch raw.EventType {
	case 1:
		evt.EventType = "filesystem"
	case 2:
		evt.EventType = "network"
	case 3:
		evt.EventType = "process"
	}

	if raw.Ret < 0 {
		evt.Error, evt.ErrorCode = getErrno(raw.Ret)
	}

	if raw.SaFamily > 0 {
		switch raw.SaFamily {
		case 2: // AF_INET
			evt.SaFamily = "ipv4"
			if raw.SrcIp > 0 {
				evt.SourceIP = parseIPv4(raw.SrcIp)
			}
			if raw.DestIp > 0 {
				evt.DestIP = parseIPv4(raw.DestIp)
			}
		case 10: // AF_INET6
			evt.SaFamily = "ipv6"
			if raw.SrcIpv6[0] > 0 || raw.SrcIpv6[1] > 0 ||
				raw.SrcIpv6[2] > 0 || raw.SrcIpv6[3] > 0 {
				evt.SourceIPv6 = parseIPv6(raw.SrcIpv6)
			}
			if raw.DestIpv6[0] > 0 || raw.DestIpv6[1] > 0 ||
				raw.DestIpv6[2] > 0 || raw.DestIpv6[3] > 0 {
				evt.DestIPv6 = parseIPv6(raw.DestIpv6)
			}
		default:
			evt.SaFamily = fmt.Sprintf("AF_%d", raw.SaFamily)
		}

		evt.SourcePort = raw.SrcPort
		evt.DestPort = raw.DestPort

		if raw.Protocol == 6 || raw.Protocol == 17 {
			var srcIP, destIP string
			if evt.SourceIP != "" {
				srcIP = evt.SourceIP
			}

			if evt.SourceIPv6 != "" {
				srcIP = evt.SourceIPv6
			}

			if evt.DestIP != "" {
				destIP = evt.DestIP
			}

			if evt.DestIPv6 != "" {
				destIP = evt.DestIPv6
			}

			if srcIP != "" && destIP != "" {
				proto := map[uint8]string{6: "TCP", 17: "UDP"}[raw.Protocol]
				evt.FlowID = GenerateFlowID(
					srcIP, destIP,
					evt.SourcePort, evt.DestPort,
					proto,
				)
			}
		}
	}

	// I/O fields
	if evt.Syscall == "write" || evt.Syscall == "read" ||
		evt.Syscall == "sendto" || evt.Syscall == "recvfrom" {
		evt.Count = raw.Count
		evt.BytesRW = raw.BytesRw
	}

	evt.ProcessUUID = GenerateProcessUUID(ac.cfg.Hostname, raw.Pid, raw.ProcessStartTime)
	evt.ParentUUID = GenerateParentUUID(ac.cfg.Hostname, raw.Ppid, raw.ParentStartTime)
	return evt
}

func (ac *EBPFCollector) reportMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ac.stopChan:
			return
		case <-ticker.C:
			// No mutex needed - use atomic loads
			received := atomic.LoadUint64(&ac.metrics.EventsReceived)
			indexed := atomic.LoadUint64(&ac.metrics.EventsIndexed)
			filtered := atomic.LoadUint64(&ac.metrics.EventsFiltered)
			lost := atomic.LoadUint64(&ac.metrics.LostSamples)
			indexFail := atomic.LoadUint64(&ac.metrics.IndexingFailures)
			chanDrops := atomic.LoadUint64(&ac.metrics.ChannelDrops)

			log.Printf("[*] eBPF Metrics: recv=%d indexed=%d filtered=%d lost=%d fail=%d drops=%d",
				received, indexed, filtered, lost, indexFail, chanDrops)

			// Log denoiser stats
			if ac.denoiser != nil {
				total, filt, ratio := ac.denoiser.GetStats()
				log.Printf("[*] Denoiser: total=%d filtered=%d ratio=%.1f%%", total, filt, ratio)
			}

			// Log file writer stats
			if ac.fileWriter != nil {
				bytes, flushes, events := ac.fileWriter.GetStats()
				log.Printf("[*] FileWriter: bytes=%d flushes=%d events=%d", bytes, flushes, events)
			}
		}
	}
}

// Stop gracefully stops the eBPF collector
func (ac *EBPFCollector) Stop() {
	close(ac.stopChan)

	// Wait until Start() closes eventsChan and all workers exit
	ac.indexerWg.Wait()

	// Only now it is safe to close the bulk indexer
	if ac.bulkIndexer != nil {
		ac.bulkIndexer.Close(context.Background())
	}

	if ac.fileWriter != nil {
		ac.fileWriter.Close()
	}

	if ac.denoiser != nil {
		ac.denoiser.Close()
	}

	ac.cleanup()
}

// cleanup releases all eBPF resources
func (ac *EBPFCollector) cleanup() {
	if ac.perfReader != nil {
		ac.perfReader.Close()
	}
	for _, l := range ac.links {
		l.Close()
	}
	ac.objs.Close()
}

// Helper functions

func int8ToStr(bs []int8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		if v == 0 {
			return string(b[:i])
		}
		b[i] = byte(v)
	}
	return string(b)
}

// parseIPv4 converts a uint32 IP address to string in correct byte order
func parseIPv4(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

// parseIPv6 converts IPv6 address parts to formatted string
func parseIPv6(parts [4]uint32) string {
	buf := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(buf[i*4:], parts[i])
	}
	return net.IP(buf).String()
}

func getErrno(ret int64) (string, int64) {
	if ret >= 0 {
		return "", 0
	}
	errCode := -ret
	return fmt.Sprintf("ERR_%d", errCode), errCode
}
