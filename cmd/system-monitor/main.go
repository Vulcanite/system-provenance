package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
)

type ESConfig struct {
	Host        string `json:"es_host"`
	Port        int    `json:"es_port"`
	User        string `json:"es_user"`
	Password    string `json:"es_password"`
	AuditdIndex string `json:"auditd_index"`
	EBPFIndex   string `json:"ebpf_index"`
	PCAPIndex   string `json:"pcap_index"`
	BatchSize   int    `json:"batch_size"`
	SslEnabled  bool   `json:"secure"`
}

type EBPFConfig struct {
	Enabled            bool `json:"enabled"`
	FileLoggingEnabled bool `json:"file_logging_enabled"`
}

type AuditdConfig struct {
	Enabled            bool `json:"enabled"`
	FileLoggingEnabled bool `json:"file_logging_enabled"`
}

type PCAPConfig struct {
	Enabled            bool   `json:"enabled"`
	FileLoggingEnabled bool   `json:"file_logging_enabled"`
	Interface          string `json:"interface"`
	BPFFilter          string `json:"bpf_filter"`
	FlowTimeout        int    `json:"flow_timeout"`
	DNSCacheTTL        int    `json:"dns_cache_ttl"`
	FlushInterval      int    `json:"flush_interval"`
}

type Config struct {
	Hostname     string       `json:"hostname"`
	EventsDir    string       `json:"events_dir"`
	OutputDir    string       `json:"output_dir"`
	StorageType  string       `json:"storage_type"`
	ESConfig     ESConfig     `json:"es_config"`
	AuditdConfig AuditdConfig `json:"auditd_config"`
	EBPFConfig   EBPFConfig   `json:"ebpf_config"`
	PCAPConfig   PCAPConfig   `json:"pcap_config"`
}

var (
	outputFile       *os.File
	fileLock         sync.Mutex
	bulkIndexer      esutil.BulkIndexer
	pcapBulkIndexer  esutil.BulkIndexer
	auditBulkIndexer esutil.BulkIndexer
	cfg              Config
)

// GenerateFlowID creates a Community ID hash for flow correlation
// Based on sorted 4-tuple (srcIP, dstIP, srcPort, dstPort, protocol)
func GenerateFlowID(srcIP, dstIP string, srcPort, dstPort uint16, protocol string) string {
	// Normalize protocol to uppercase
	proto := strings.ToUpper(protocol)

	// Sort the tuple to ensure consistent hashing regardless of direction
	var lowIP, highIP string
	var lowPort, highPort uint16

	if srcIP < dstIP {
		lowIP, highIP = srcIP, dstIP
		lowPort, highPort = srcPort, dstPort
	} else if srcIP > dstIP {
		lowIP, highIP = dstIP, srcIP
		lowPort, highPort = dstPort, srcPort
	} else {
		// IPs are equal, sort by port
		lowIP, highIP = srcIP, dstIP
		if srcPort < dstPort {
			lowPort, highPort = srcPort, dstPort
		} else {
			lowPort, highPort = dstPort, srcPort
		}
	}

	// Create the tuple string for hashing
	tuple := fmt.Sprintf("%s:%d-%s:%d-%s", lowIP, lowPort, highIP, highPort, proto)

	// Generate SHA1 hash
	h := sha1.New()
	h.Write([]byte(tuple))
	hash := h.Sum(nil)

	// Return as hex string
	return hex.EncodeToString(hash)
}

func setupLogging() {
	if cfg.EventsDir == "" {
		cfg.EventsDir = "/var/monitoring/events"
	}

	os.MkdirAll(cfg.EventsDir, 0755)

	path := fmt.Sprintf("%s/events.jsonl", cfg.EventsDir)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	outputFile = f
	fmt.Printf("[+] Local logging: %s\n", path)
}

func setupES() {
	protocol := "http"
	if cfg.ESConfig.SslEnabled {
		protocol = "https"
	}

	host := cfg.ESConfig.Host

	url := fmt.Sprintf("%s://%s:%d", protocol, host, cfg.ESConfig.Port)
	fmt.Printf("Connecting to Elasticsearch at %s ...\n", url)

	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{url},
		Username:  cfg.ESConfig.User,
		Password:  cfg.ESConfig.Password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	})

	if err != nil {
		log.Printf("[!] ES Client Create Failed: %v", err)
		return
	}

	info, err := es.Info()
	if err != nil {
		log.Printf("[!] ES Connection Failed: %v", err)
		log.Printf("[!] Check your Password, Host, and SSL settings")
		return
	}
	defer info.Body.Close()
	fmt.Printf("[+] Connected to ES: %s\n", info.Status())

	// Setup eBPF events bulk indexer
	if cfg.EBPFConfig.Enabled {
		bi, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
			Client:        es,
			Index:         cfg.ESConfig.EBPFIndex,
			FlushBytes:    1000000, // 1MB
			FlushInterval: 1 * time.Second,
			OnError: func(ctx context.Context, err error) {
				log.Printf("[!] eBPF Bulk Indexer Error: %v", err)
			},
		})

		if err != nil {
			log.Printf("[!] eBPF Bulk Indexer Init Failed: %v", err)
		} else {
			bulkIndexer = bi
			fmt.Println("[+] eBPF Bulk Indexer Ready")
		}
	}

	// Setup PCAP flows bulk indexer
	if cfg.PCAPConfig.Enabled {
		pcapBI, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
			Client:        es,
			Index:         cfg.ESConfig.PCAPIndex,
			FlushBytes:    1000000, // 1MB
			FlushInterval: 1 * time.Second,
			OnError: func(ctx context.Context, err error) {
				log.Printf("[!] PCAP Bulk Indexer Error: %v", err)
			},
		})

		if err != nil {
			log.Printf("[!] PCAP Bulk Indexer Init Failed: %v", err)
		} else {
			pcapBulkIndexer = pcapBI
			fmt.Println("[+] PCAP Bulk Indexer Ready")
		}
	}

	if cfg.AuditdConfig.Enabled {
		auditBI, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
			Client:        es,
			Index:         cfg.ESConfig.AuditdIndex,
			FlushBytes:    1000000,
			FlushInterval: 1 * time.Second,
			OnError: func(ctx context.Context, err error) {
				log.Printf("[!] Auditd Bulk Indexer Error: %v", err)
			},
		})

		if err != nil {
			log.Printf("[!] Auditd Bulk Indexer Init Failed: %v", err)
		} else {
			auditBulkIndexer = auditBI
			fmt.Println("[+] Auditd Bulk Indexer Ready")
		}
	}
}

func main() {
	configPath := "/var/monitoring/config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("[!] Config not found at %s", configPath)
	}
	json.Unmarshal(data, &cfg)

	// Auto-detect hostname if not set
	if cfg.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Printf("[!] Failed to get hostname: %v, using 'unknown'", err)
			cfg.Hostname = "unknown"
		} else {
			cfg.Hostname = hostname
		}
	}
	log.Printf("[+] Hostname: %s", cfg.Hostname)

	if cfg.EBPFConfig.FileLoggingEnabled || cfg.PCAPConfig.FileLoggingEnabled {
		setupLogging()
	}

	if strings.EqualFold(cfg.StorageType, "elasticsearch") {
		setupES()
	}

	// Start PCAP collector if enabled
	var pcapCollector *PCAPCollector
	if cfg.PCAPConfig.Enabled {
		pcapCollector = NewPCAPCollector(cfg, pcapBulkIndexer)
		go func() {
			if err := pcapCollector.Start(); err != nil {
				log.Printf("[!] PCAP collector error: %v", err)
			}
		}()
	}

	var auditCollector *AuditdCollector
	if cfg.AuditdConfig.Enabled {
		auditCollector = NewAuditdCollector(cfg, auditBulkIndexer)
		go func() {
			if err := auditCollector.Start(); err != nil {
				log.Printf("[!] Auditd collector error: %v", err)
			}
		}()
	}

	// Declare collectors
	var ebpfCollector *EBPFCollector

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigChan {
			if sig == syscall.SIGHUP {
				fmt.Println("SIGHUP: Rotating logs...")
				fileLock.Lock()
				if outputFile != nil {
					outputFile.Close()
				}
				if cfg.EBPFConfig.FileLoggingEnabled || cfg.PCAPConfig.FileLoggingEnabled {
					setupLogging()
				}
				fileLock.Unlock()
			} else {
				fmt.Println("\n[!] Stopping...")
				if pcapCollector != nil {
					pcapCollector.Stop()
				}

				if ebpfCollector != nil {
					ebpfCollector.Stop()
				}

				fmt.Println("[+] Shutdown complete")
				os.Exit(0)
			}
		}
	}()

	// Start eBPF collector if enabled
	if cfg.EBPFConfig.Enabled {
		ec, err := NewEBPFCollector(cfg, outputFile, bulkIndexer)
		if err != nil {
			log.Fatalf("[!] Failed to create eBPF collector: %v", err)
		}
		ebpfCollector = ec
		defer ebpfCollector.Stop()

		go func() {
			if err := ebpfCollector.Start(); err != nil {
				log.Printf("[!] eBPF collector error: %v", err)
			}
		}()
	}

	select {}
}
