package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// FlowKey represents a 5-tuple identifier for a network flow
type FlowKey struct {
	SrcIP    string `json:"source.ip"`
	DstIP    string `json:"destination.ip"`
	SrcPort  uint16 `json:"source.port"`
	DstPort  uint16 `json:"destination.port"`
	Protocol string `json:"network.transport"`
}

// FlowStats tracks statistics for a network flow
type FlowStats struct {
	// ECS: Base fields
	HostName  string `json:"host.name"`
	Module    string `json:"event.module"`
	Timestamp string `json:"@timestamp"`
	FlowKey
	FlowID      string `json:"flow.id"`
	PacketCount uint64 `json:"network.packets"`
	ByteCount   uint64 `json:"network.bytes"`

	// ECS: Time fields
	EventStart string `json:"event.start"`
	EventEnd   string `json:"event.end"`

	// Internal time fields (for flow management)
	FirstSeen  time.Time `json:"-"`
	LastSeen   time.Time `json:"-"`
	EpochFirst int64     `json:"epoch_first"`
	EpochLast  int64     `json:"epoch_last"`

	// Additional fields
	Direction   string   `json:"network.direction,omitempty"`
	TCPFlags    []string `json:"network.tcp_flags,omitempty"`
	DomainName  string   `json:"destination.domain,omitempty"`
	DNSResolved bool     `json:"dns_resolved"`
}

// DNSCacheEntry represents a cached DNS resolution
type DNSCacheEntry struct {
	Domain    string
	ExpiresAt time.Time
}

// WhitelistRule represents a combined IP+Port whitelist rule
type WhitelistRule struct {
	IP   string
	Port uint16
}

// PCAPCollector handles packet capture and flow aggregation
type PCAPCollector struct {
	cfg            Config
	flows          map[FlowKey]*FlowStats
	flowsMutex     sync.RWMutex
	dnsCache       map[string]*DNSCacheEntry
	dnsCacheMutex  sync.RWMutex
	bulkIndexer    esutil.BulkIndexer
	stopChan       chan struct{}
	whitelistRules []WhitelistRule // Combined IP+Port rules to exclude
	whitelistIPs   map[string]bool // IPs to exclude (for localhost only)
	localIPs       map[string]bool // Local IP addresses for direction inference
	fileWriter     *BatchedFileWriter
}

// NewPCAPCollector creates a new PCAP collector instance
func NewPCAPCollector(cfg Config, bi esutil.BulkIndexer) *PCAPCollector {
	pc := &PCAPCollector{
		cfg:            cfg,
		flows:          make(map[FlowKey]*FlowStats),
		dnsCache:       make(map[string]*DNSCacheEntry),
		bulkIndexer:    bi,
		stopChan:       make(chan struct{}),
		whitelistRules: make([]WhitelistRule, 0),
		whitelistIPs:   make(map[string]bool),
		localIPs:       make(map[string]bool),
	}

	if cfg.PCAPConfig.FileLoggingEnabled {
		path := fmt.Sprintf("%s/pcap-events.jsonl", cfg.EventsDir)
		bw, err := NewBatchedFileWriter(path, 64*1024, 5*time.Second)
		if err != nil {
			log.Printf("[!] Warning: Failed to create batched writer: %v", err)
		} else {
			pc.fileWriter = bw
			log.Printf("[+] Batched file writer enabled: %s (64KB buffer, 5s flush)", path)
		}
	}

	// Build whitelist from Elasticsearch config
	pc.buildWhitelist()

	// Detect local IP addresses for direction inference
	pc.detectLocalIPs()

	return pc
}

func (pc *PCAPCollector) RotateLog() {
	if pc.fileWriter != nil {
		if err := pc.fileWriter.Rotate(); err != nil {
			log.Printf("[!] PCAP Log Rotation Failed: %v", err)
		} else {
			log.Println("[+] PCAP Log Rotated")
		}
	}
}

// detectLocalIPs detects local IP addresses for direction inference
func (pc *PCAPCollector) detectLocalIPs() {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[!] Failed to get network interfaces: %v", err)
		return
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && !ip.IsLoopback() {
				ipStr := ip.String()
				pc.localIPs[ipStr] = true
				fmt.Printf("[+] PCAP detected local IP: %s (for direction inference)\n", ipStr)
			}
		}
	}
}

// inferDirection determines if a flow is inbound or outbound based on local IPs
func (pc *PCAPCollector) inferDirection(srcIP, dstIP string) string {
	srcIsLocal := pc.localIPs[srcIP]
	dstIsLocal := pc.localIPs[dstIP]

	if srcIsLocal && !dstIsLocal {
		return "outbound"
	} else if !srcIsLocal && dstIsLocal {
		return "inbound"
	} else if srcIsLocal && dstIsLocal {
		return "internal"
	}
	// If neither is local, we can't determine (external traffic being routed through)
	return "unknown"
}

// buildWhitelist creates whitelist of IPs and ports to exclude from capture
func (pc *PCAPCollector) buildWhitelist() {
	// Add Elasticsearch host+port combination (must match BOTH)
	if pc.cfg.ESConfig.Host != "" && pc.cfg.ESConfig.Port > 0 {
		esHost := pc.cfg.ESConfig.Host
		esPort := uint16(pc.cfg.ESConfig.Port)

		rule := WhitelistRule{
			IP:   esHost,
			Port: esPort,
		}
		pc.whitelistRules = append(pc.whitelistRules, rule)

		fmt.Printf("[+] PCAP whitelist: Excluding traffic to %s:%d (Elasticsearch)\n", esHost, esPort)
	}

	// Add localhost addresses (ANY port on localhost - internal system traffic)
	pc.whitelistIPs["127.0.0.1"] = true
	pc.whitelistIPs["::1"] = true
	fmt.Printf("[+] PCAP whitelist: Excluding all localhost traffic (127.0.0.1, ::1)\n")
}

// isWhitelisted checks if a flow should be excluded from capture
func (pc *PCAPCollector) isWhitelisted(srcIP, dstIP string, srcPort, dstPort uint16) bool {
	// Check if any IP is localhost (exclude all localhost traffic regardless of port)
	if pc.whitelistIPs[srcIP] || pc.whitelistIPs[dstIP] {
		return true
	}

	// Check combined IP+Port rules (both must match)
	for _, rule := range pc.whitelistRules {
		// Check if source matches rule (IP AND port)
		if rule.IP == srcIP && rule.Port == srcPort {
			return true
		}
		// Check if destination matches rule (IP AND port)
		if rule.IP == dstIP && rule.Port == dstPort {
			return true
		}
	}

	return false
}

// Start begins packet capture and processing
func (pc *PCAPCollector) Start() error {
	// Open network interface
	handle, err := pcap.OpenLive(
		pc.cfg.PCAPConfig.Interface,
		1600, // snapshot length
		true, // promiscuous mode
		pcap.BlockForever,
	)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", pc.cfg.PCAPConfig.Interface, err)
	}
	defer handle.Close()

	// Set BPF filter
	if pc.cfg.PCAPConfig.BPFFilter != "" {
		if err := handle.SetBPFFilter(pc.cfg.PCAPConfig.BPFFilter); err != nil {
			return fmt.Errorf("failed to set BPF filter: %v", err)
		}
		fmt.Printf("[+] PCAP BPF filter: %s\n", pc.cfg.PCAPConfig.BPFFilter)
	}

	fmt.Printf("[+] PCAP capture started on %s\n", pc.cfg.PCAPConfig.Interface)

	// Start periodic flush goroutine
	go pc.periodicFlush()

	// Start DNS cache cleanup goroutine
	go pc.cleanupDNSCache()

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-pc.stopChan:
			pc.flushFlows()
			return nil
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			pc.processPacket(packet)
		}
	}
}

// Stop gracefully stops the PCAP collector
func (pc *PCAPCollector) Stop() {
	close(pc.stopChan)

	if pc.fileWriter != nil {
		pc.fileWriter.Close()
	}
}

// processPacket extracts flow information from a packet
func (pc *PCAPCollector) processPacket(packet gopacket.Packet) {
	// Check for DNS packets first
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		pc.processDNS(dnsLayer.(*layers.DNS))
	}

	// Extract network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Extract transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	var flowKey FlowKey
	var tcpFlags []string

	// Parse network layer (IPv4 or IPv6)
	switch net := networkLayer.(type) {
	case *layers.IPv4:
		flowKey.SrcIP = net.SrcIP.String()
		flowKey.DstIP = net.DstIP.String()
	case *layers.IPv6:
		flowKey.SrcIP = net.SrcIP.String()
		flowKey.DstIP = net.DstIP.String()
	default:
		return
	}

	// Parse transport layer (TCP or UDP)
	switch trans := transportLayer.(type) {
	case *layers.TCP:
		flowKey.SrcPort = uint16(trans.SrcPort)
		flowKey.DstPort = uint16(trans.DstPort)
		flowKey.Protocol = "TCP"
		tcpFlags = extractTCPFlags(trans)
	case *layers.UDP:
		flowKey.SrcPort = uint16(trans.SrcPort)
		flowKey.DstPort = uint16(trans.DstPort)
		flowKey.Protocol = "UDP"
	default:
		return
	}

	// Update flow statistics
	pc.updateFlow(flowKey, packet.Metadata().Length, tcpFlags)
}

// extractTCPFlags extracts TCP flag names from a TCP layer
func extractTCPFlags(tcp *layers.TCP) []string {
	var flags []string
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	return flags
}

// updateFlow updates or creates flow statistics
func (pc *PCAPCollector) updateFlow(key FlowKey, packetLen int, tcpFlags []string) {
	// Check if this flow should be excluded (whitelist check)
	if pc.isWhitelisted(key.SrcIP, key.DstIP, key.SrcPort, key.DstPort) {
		return // Skip whitelisted traffic
	}

	pc.flowsMutex.Lock()
	defer pc.flowsMutex.Unlock()

	now := time.Now()
	flow, exists := pc.flows[key]

	if !exists {
		// Create new flow with Flow ID for correlation
		flowID := GenerateFlowID(key.SrcIP, key.DstIP, key.SrcPort, key.DstPort, key.Protocol)
		direction := pc.inferDirection(key.SrcIP, key.DstIP)
		flow = &FlowStats{
			HostName:    pc.cfg.Hostname,
			Module:      "pcap",
			Timestamp:   now.UTC().Format(time.RFC3339Nano),
			FlowKey:     key,
			FlowID:      flowID,
			Direction:   direction,
			PacketCount: 1,
			ByteCount:   uint64(packetLen),
			FirstSeen:   now,
			LastSeen:    now,
			EventStart:  now.UTC().Format(time.RFC3339Nano),
			EventEnd:    now.UTC().Format(time.RFC3339Nano),
			TCPFlags:    tcpFlags,
			EpochFirst:  now.UnixMilli(),
			EpochLast:   now.UnixMilli(),
		}

		// Try to resolve domain name from DNS cache
		pc.dnsCacheMutex.RLock()
		if entry, found := pc.dnsCache[key.DstIP]; found {
			flow.DomainName = entry.Domain
			flow.DNSResolved = true
		}
		pc.dnsCacheMutex.RUnlock()

		pc.flows[key] = flow
	} else {
		// Update existing flow
		flow.PacketCount++
		flow.ByteCount += uint64(packetLen)
		flow.LastSeen = now
		flow.Timestamp = now.UTC().Format(time.RFC3339Nano)
		flow.EventEnd = now.UTC().Format(time.RFC3339Nano)
		flow.EpochLast = now.UnixMilli()

		// Merge TCP flags
		if len(tcpFlags) > 0 {
			flagMap := make(map[string]bool)
			for _, f := range flow.TCPFlags {
				flagMap[f] = true
			}
			for _, f := range tcpFlags {
				if !flagMap[f] {
					flow.TCPFlags = append(flow.TCPFlags, f)
					flagMap[f] = true
				}
			}
		}

		// Try to resolve domain if not already resolved
		if !flow.DNSResolved {
			pc.dnsCacheMutex.RLock()
			if entry, found := pc.dnsCache[key.DstIP]; found {
				flow.DomainName = entry.Domain
				flow.DNSResolved = true
			}
			pc.dnsCacheMutex.RUnlock()
		}
	}
}

// processDNS extracts DNS responses and updates the cache
func (pc *PCAPCollector) processDNS(dns *layers.DNS) {
	if !dns.QR { // QR=0 means query, QR=1 means response
		return
	}

	ttl := time.Duration(pc.cfg.PCAPConfig.DNSCacheTTL) * time.Second
	expiresAt := time.Now().Add(ttl)

	pc.dnsCacheMutex.Lock()
	defer pc.dnsCacheMutex.Unlock()

	// Process answers
	for _, answer := range dns.Answers {
		var domain string
		var ip string

		// Extract domain name
		domain = string(answer.Name)

		// Extract IP from answer
		switch answer.Type {
		case layers.DNSTypeA:
			if answer.IP != nil {
				ip = answer.IP.String()
			}
		case layers.DNSTypeAAAA:
			if answer.IP != nil {
				ip = answer.IP.String()
			}
		default:
			continue
		}

		if ip != "" && domain != "" {
			pc.dnsCache[ip] = &DNSCacheEntry{
				Domain:    domain,
				ExpiresAt: expiresAt,
			}
		}
	}
}

// cleanupDNSCache periodically removes expired DNS cache entries
func (pc *PCAPCollector) cleanupDNSCache() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pc.stopChan:
			return
		case <-ticker.C:
			pc.dnsCacheMutex.Lock()
			now := time.Now()
			for ip, entry := range pc.dnsCache {
				if now.After(entry.ExpiresAt) {
					delete(pc.dnsCache, ip)
				}
			}
			pc.dnsCacheMutex.Unlock()
		}
	}
}

// periodicFlush flushes flow statistics at configured intervals
func (pc *PCAPCollector) periodicFlush() {
	interval := time.Duration(pc.cfg.PCAPConfig.FlushInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-pc.stopChan:
			return
		case <-ticker.C:
			pc.flushFlows()
		}
	}
}

// flushFlows writes aggregated flows to storage and clears the map
func (pc *PCAPCollector) flushFlows() {
	pc.flowsMutex.Lock()
	defer pc.flowsMutex.Unlock()

	if len(pc.flows) == 0 {
		return
	}

	// Flush flows to storage
	// Strategy: Send ALL flows to Elasticsearch for near real-time visibility
	// Only remove from memory if they've been inactive for FlowTimeout
	now := time.Now()
	timeout := time.Duration(pc.cfg.PCAPConfig.FlowTimeout) * time.Second

	flushedCount := 0
	removedCount := 0

	for key, flow := range pc.flows {
		// Check if flow has been inactive
		inactive := now.Sub(flow.LastSeen) >= timeout

		// Serialize flow
		jsonBytes, err := json.Marshal(flow)
		if err != nil {
			log.Printf("[!] Failed to marshal flow: %v", err)
			continue
		}

		// Always send to Elasticsearch for real-time visibility
		if pc.bulkIndexer != nil {
			pc.bulkIndexer.Add(context.Background(), esutil.BulkIndexerItem{
				Action: "index",
				Body:   bytes.NewReader(jsonBytes),
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
					if err != nil {
						log.Printf("ES PCAP Index Error: %v", err)
					} else {
						log.Printf("ES PCAP Item Error: [%d] %s", res.Status, res.Error.Reason)
					}
				},
			})
			flushedCount++
		}

		if pc.fileWriter != nil {
			pc.fileWriter.Write(jsonBytes)
		}

		// Remove from memory if inactive
		if inactive {
			delete(pc.flows, key)
			removedCount++
		}
	}

	if flushedCount > 0 {
		fmt.Printf("[+] Sent %d PCAP flows to ES (%d removed, %d active remain)\n", flushedCount, removedCount, len(pc.flows))
	}
}
