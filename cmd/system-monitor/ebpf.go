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
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/go-elasticsearch/v8/esutil"
)

// AuditEvent represents a syscall event captured by eBPF
type AuditEvent struct {
	Hostname         string `json:"hostname"`
	TimestampNs      int64  `json:"timestamp_ns"`
	EpochTimestamp   int64  `json:"epoch_timestamp"`
	Datetime         string `json:"datetime"`
	Pid              uint32 `json:"pid"`
	Ppid             uint32 `json:"ppid"`
	Uid              uint32 `json:"uid"`
	ParentStartTime  uint64 `json:"parent_start_time"`
	ProcessStartTime uint64 `json:"process_start_time"`
	Comm             string `json:"comm"`
	Syscall          string `json:"syscall"`
	Filename         string `json:"filename"`
	Fd               int64  `json:"fd"`
	Ret              int64  `json:"ret"`
	EventType        string `json:"event_type,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorCode        int64  `json:"error_code,omitempty"`

	// Enhanced network fields
	SrcIP      string `json:"src_ip,omitempty"`
	DestIP     string `json:"dest_ip,omitempty"`
	SrcIPv6    string `json:"src_ipv6,omitempty"`
	DestIPv6   string `json:"dest_ipv6,omitempty"`
	SrcPort    uint16 `json:"src_port,omitempty"`
	DestPort   uint16 `json:"dest_port,omitempty"`
	SaFamily   string `json:"sa_family,omitempty"`
	Protocol   uint8  `json:"protocol,omitempty"`
	SocketType uint8  `json:"socket_type,omitempty"`

	// I/O fields
	Count   uint64 `json:"count,omitempty"`
	BytesRW int64  `json:"bytes_rw,omitempty"`
}

// RuntimeMetrics tracks performance metrics
type RuntimeMetrics struct {
	EventsReceived   uint64
	EventsIndexed    uint64
	LostSamples      uint64
	IndexingFailures uint64
	ChannelDrops     uint64
	mu               sync.Mutex
}

// EBPFCollector handles eBPF program loading and event processing
type EBPFCollector struct {
	cfg         Config
	outputFile  *os.File
	fileLock    sync.Mutex
	bulkIndexer esutil.BulkIndexer
	objs        bpfObjects
	links       []link.Link
	perfReader  *perf.Reader
	stopChan    chan struct{}
	eventsChan  chan AuditEvent
	indexerWg   sync.WaitGroup
	metrics     RuntimeMetrics
}

// NewEBPFCollector creates a new eBPF collector instance
func NewEBPFCollector(cfg Config, outputFile *os.File, bulkIndexer esutil.BulkIndexer) (*EBPFCollector, error) {
	collector := &EBPFCollector{
		cfg:         cfg,
		outputFile:  outputFile,
		bulkIndexer: bulkIndexer,
		stopChan:    make(chan struct{}),
		eventsChan:  make(chan AuditEvent, 50000),
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

	return collector, nil
}

// populateWhitelist populates the eBPF whitelist map with rules
func (ec *EBPFCollector) populateWhitelist() error {
	// Add Elasticsearch host+port combination
	if ec.cfg.ESConfig.Host != "" && ec.cfg.ESConfig.Port > 0 {
		esHost := ec.cfg.ESConfig.Host
		esPort := ec.cfg.ESConfig.Port

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
			if err := ec.objs.WhitelistRules.Put(&key, &rule); err != nil {
				return fmt.Errorf("failed to add whitelist rule: %v", err)
			}

			fmt.Printf("[+] eBPF whitelist: Excluding traffic to %s:%d (Elasticsearch)\n",
				ip4.String(), esPort)
		}
	}

	return nil
}

// populateIgnoredComms populates the eBPF ignored_comms map with default process names to ignore
func (ec *EBPFCollector) populateIgnoredComms() error {
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

		if err := ec.objs.IgnoredComms.Put(&key, &value); err != nil {
			return fmt.Errorf("failed to add ignored comm %s: %v", comm, err)
		}
		fmt.Printf("[+] eBPF filter: Ignoring process '%s'\n", comm)
	}

	return nil
}

// attachTracepoints attaches all eBPF programs to kernel tracepoints
func (ec *EBPFCollector) attachTracepoints() error {
	attach := func(group, name string, prog *ebpf.Program) error {
		l, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			return fmt.Errorf("failed to attach %s/%s: %v", group, name, err)
		}
		ec.links = append(ec.links, l)
		return nil
	}

	// EXECVE
	if err := attach("syscalls", "sys_enter_execve", ec.objs.SysEnterExecve); err != nil {
		return err
	}

	// OPEN
	if err := attach("syscalls", "sys_enter_openat", ec.objs.SysEnterOpenat); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_openat", ec.objs.SysExitOpenat); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_openat2", ec.objs.SysEnterOpenat2); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_openat2", ec.objs.SysExitOpenat2); err != nil {
		return err
	}

	// WRITE
	if err := attach("syscalls", "sys_enter_write", ec.objs.SysEnterWrite); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_write", ec.objs.SysExitWrite); err != nil {
		return err
	}

	// READ
	if err := attach("syscalls", "sys_enter_read", ec.objs.SysEnterRead); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_read", ec.objs.SysExitRead); err != nil {
		return err
	}

	// CLONE
	if err := attach("syscalls", "sys_enter_clone", ec.objs.SysEnterClone); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_clone3", ec.objs.SysEnterClone3); err != nil {
		return err
	}

	// OTHERS
	if err := attach("syscalls", "sys_enter_unlinkat", ec.objs.SysEnterUnlinkat); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_vfork", ec.objs.SysEnterVfork); err != nil {
		return err
	}

	// NETWORK SYSCALLS (Enhanced)
	if err := attach("syscalls", "sys_enter_socket", ec.objs.SysEnterSocket); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_connect", ec.objs.SysEnterConnect); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_connect", ec.objs.SysExitConnect); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_bind", ec.objs.SysEnterBind); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_listen", ec.objs.SysEnterListen); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_accept", ec.objs.SysEnterAccept); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_accept", ec.objs.SysExitAccept); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_accept4", ec.objs.SysEnterAccept4); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_accept4", ec.objs.SysExitAccept4); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_sendto", ec.objs.SysEnterSendto); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_sendto", ec.objs.SysExitSendto); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_enter_recvfrom", ec.objs.SysEnterRecvfrom); err != nil {
		return err
	}
	if err := attach("syscalls", "sys_exit_recvfrom", ec.objs.SysExitRecvfrom); err != nil {
		return err
	}

	fmt.Printf("[+] eBPF monitoring started with %d probes active.\n", len(ec.links))
	return nil
}

// Start begins processing eBPF events
func (ec *EBPFCollector) Start() error {
	// Start multiple indexer goroutines for parallel processing
	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		ec.indexerWg.Add(1)
		go ec.indexerWorker()
	}

	// Start metrics reporter
	go ec.reportMetrics()

	// Read from perf buffer and push to channel
	for {
		select {
		case <-ec.stopChan:
			close(ec.eventsChan)
			ec.indexerWg.Wait()
			return nil
		default:
			if err := ec.readPerfEvent(); err != nil {
				if errors.Is(err, perf.ErrClosed) {
					close(ec.eventsChan)
					ec.indexerWg.Wait()
					return nil
				}
				log.Printf("[!] eBPF event processing error: %v", err)
			}
		}
	}
}

// reportMetrics periodically logs runtime metrics
func (ec *EBPFCollector) reportMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ec.stopChan:
			return
		case <-ticker.C:
			ec.metrics.mu.Lock()
			log.Printf("[*] Metrics: Received=%d Indexed=%d Lost=%d IndexFail=%d ChanDrops=%d",
				ec.metrics.EventsReceived,
				ec.metrics.EventsIndexed,
				ec.metrics.LostSamples,
				ec.metrics.IndexingFailures,
				ec.metrics.ChannelDrops)
			ec.metrics.mu.Unlock()
		}
	}
}

// indexerWorker consumes events from channel and indexes them
func (ec *EBPFCollector) indexerWorker() {
	defer ec.indexerWg.Done()

	for evt := range ec.eventsChan {
		// Write to file
		if ec.cfg.EBPFConfig.FileLoggingEnabled && ec.outputFile != nil {
			jsonBytes, _ := json.Marshal(evt)
			ec.fileLock.Lock()
			ec.outputFile.Write(jsonBytes)
			ec.outputFile.WriteString("\n")
			ec.fileLock.Unlock()
		}

		// Write to Elasticsearch
		if ec.bulkIndexer != nil {
			jsonBytes, _ := json.Marshal(evt)
			err := ec.bulkIndexer.Add(context.Background(), esutil.BulkIndexerItem{
				Action: "index",
				Body:   bytes.NewReader(jsonBytes),
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
					ec.metrics.mu.Lock()
					ec.metrics.IndexingFailures++
					ec.metrics.mu.Unlock()
					if err != nil {
						log.Printf("ES Index Error: %v", err)
					} else {
						log.Printf("ES Item Error: [%d] %s", res.Status, res.Error.Reason)
					}
				},
			})
			if err == nil {
				ec.metrics.mu.Lock()
				ec.metrics.EventsIndexed++
				ec.metrics.mu.Unlock()
			}
		}
	}
}

// readPerfEvent reads a single event from the perf buffer and pushes to channel
func (ec *EBPFCollector) readPerfEvent() error {
	record, err := ec.perfReader.Read()
	if err != nil {
		return err
	}

	if record.LostSamples > 0 {
		ec.metrics.mu.Lock()
		ec.metrics.LostSamples += record.LostSamples
		ec.metrics.mu.Unlock()
		log.Printf("[!] Buffer full: dropped %d events", record.LostSamples)
		return nil
	}

	if len(record.RawSample) < int(unsafe.Sizeof(bpfSoEvent{})) {
		log.Printf("[!] Event too small")
		return nil
	}

	raw := *(*bpfSoEvent)(unsafe.Pointer(&record.RawSample[0]))
	evt := ec.parseEvent(&raw)

	ec.metrics.mu.Lock()
	ec.metrics.EventsReceived++
	ec.metrics.mu.Unlock()

	// Push to buffered channel (non-blocking)
	select {
	case ec.eventsChan <- evt:
	default:
		ec.metrics.mu.Lock()
		ec.metrics.ChannelDrops++
		ec.metrics.mu.Unlock()
		log.Printf("[!] Event channel full, dropping event")
	}

	return nil
}

// parseEvent converts raw eBPF event to AuditEvent
func (ec *EBPFCollector) parseEvent(raw *bpfSoEvent) AuditEvent {
	// Use kernel monotonic timestamp (bpf_ktime_get_ns) as canonical event time
	kernelTimeNs := int64(raw.Timestamp)

	// For correlation, also capture userspace processing time
	userspaceTime := time.Now()

	evt := AuditEvent{
		Hostname:         ec.cfg.Hostname,
		TimestampNs:      kernelTimeNs, // Canonical kernel event time
		EpochTimestamp:   userspaceTime.UnixMilli(),
		Datetime:         userspaceTime.UTC().Format(time.RFC3339Nano),
		Pid:              raw.Pid,
		Ppid:             raw.Ppid,
		Uid:              raw.Uid,
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

	// Parse network fields
	if raw.SaFamily > 0 {
		switch raw.SaFamily {
		case 2: // AF_INET
			evt.SaFamily = "IPv4"
			if raw.SrcIp > 0 {
				evt.SrcIP = parseIPv4(raw.SrcIp)
			}
			if raw.DestIp > 0 {
				evt.DestIP = parseIPv4(raw.DestIp)
			}
		case 10: // AF_INET6
			evt.SaFamily = "IPv6"
			if raw.SrcIpv6[0] > 0 || raw.SrcIpv6[1] > 0 || raw.SrcIpv6[2] > 0 || raw.SrcIpv6[3] > 0 {
				evt.SrcIPv6 = parseIPv6(raw.SrcIpv6)
			}
			if raw.DestIpv6[0] > 0 || raw.DestIpv6[1] > 0 || raw.DestIpv6[2] > 0 || raw.DestIpv6[3] > 0 {
				evt.DestIPv6 = parseIPv6(raw.DestIpv6)
			}
		default:
			evt.SaFamily = fmt.Sprintf("AF_%d", raw.SaFamily)
		}

		evt.SrcPort = raw.SrcPort
		evt.DestPort = raw.DestPort
	}

	// Parse I/O fields
	if evt.Syscall == "write" || evt.Syscall == "read" || evt.Syscall == "sendto" || evt.Syscall == "recvfrom" {
		evt.Count = raw.Count
		evt.BytesRW = raw.BytesRw
		// FD is now properly set from the BPF event, no hack needed
	}

	return evt
}

// Stop gracefully stops the eBPF collector
func (ec *EBPFCollector) Stop() {
	close(ec.stopChan)
	ec.cleanup()
}

// cleanup releases all eBPF resources
func (ec *EBPFCollector) cleanup() {
	if ec.perfReader != nil {
		ec.perfReader.Close()
	}
	for _, l := range ec.links {
		l.Close()
	}
	ec.objs.Close()
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
	// IP is stored in host byte order (big-endian network order)
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip))
}

// parseIPv6 converts IPv6 address parts to formatted string
func parseIPv6(parts [4]uint32) string {
	buf := new(bytes.Buffer)
	for _, p := range parts {
		// Write in network byte order (big-endian)
		binary.Write(buf, binary.BigEndian, p)
	}
	ip := net.IP(buf.Bytes())
	// Use net.IP.String() for proper IPv6 formatting with :: compression
	return ip.String()
}

func getErrno(ret int64) (string, int64) {
	if ret >= 0 {
		return "", 0
	}
	errCode := -ret
	return fmt.Sprintf("ERR_%d", errCode), errCode
}
