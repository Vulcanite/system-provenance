package main

import (
	"context"
	"crypto/tls"
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
	Host       string `json:"es_host"`
	Port       int    `json:"es_port"`
	User       string `json:"es_user"`
	Password   string `json:"es_password"`
	EBPFIndex  string `json:"ebpf_index"`
	PCAPIndex  string `json:"pcap_index"`
	BatchSize  int    `json:"batch_size"`
	SslEnabled bool   `json:"secure"`
}

type MonitoringConfig struct {
	EBPFEnabled bool `json:"ebpf_enabled"`
	PCAPEnabled bool `json:"pcap_enabled"`
}

type StorageConfig struct {
	FileLoggingEnabled bool   `json:"file_logging_enabled"`
	StorageType        string `json:"storage_type"`
}

type PCAPConfig struct {
	Interface     string `json:"interface"`
	BPFFilter     string `json:"bpf_filter"`
	FlowTimeout   int    `json:"flow_timeout"`
	DNSCacheTTL   int    `json:"dns_cache_ttl"`
	FlushInterval int    `json:"flush_interval"`
}

type Config struct {
	Hostname   string           `json:"hostname"`
	EventsDir  string           `json:"events_dir"`
	OutputDir  string           `json:"output_dir"`
	Monitoring MonitoringConfig `json:"monitoring"`
	Storage    StorageConfig    `json:"storage"`
	ESConfig   ESConfig         `json:"es_config"`
	PCAPConfig PCAPConfig       `json:"pcap_config"`
}

var (
	outputFile      *os.File
	fileLock        sync.Mutex
	bulkIndexer     esutil.BulkIndexer
	pcapBulkIndexer esutil.BulkIndexer
	cfg             Config
)

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
	if cfg.Monitoring.EBPFEnabled {
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
	if cfg.Monitoring.PCAPEnabled {
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
}

func main() {
	configPath := "/var/config.json"
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

	if cfg.Storage.FileLoggingEnabled {
		setupLogging()
	}

	if strings.EqualFold(cfg.Storage.StorageType, "elasticsearch") {
		setupES()
	}

	// Start PCAP collector if enabled
	var pcapCollector *PCAPCollector
	if cfg.Monitoring.PCAPEnabled {
		pcapCollector = NewPCAPCollector(cfg, pcapBulkIndexer)
		go func() {
			if err := pcapCollector.Start(); err != nil {
				log.Printf("[!] PCAP collector error: %v", err)
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
				if cfg.Storage.FileLoggingEnabled {
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
				os.Exit(0)
			}
		}
	}()

	// Start eBPF collector if enabled
	if cfg.Monitoring.EBPFEnabled {
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
	} else {
		fmt.Println("[+] eBPF monitoring disabled. Only PCAP collection active.")
	}

	// Block forever
	select {}
}
