package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
)

type AuditdCollector struct {
	cfg         Config
	bulkIndexer esutil.BulkIndexer
	outputFile  *os.File
	client      *libaudit.AuditClient
	reassembler *libaudit.Reassembler
	stopChan    chan struct{}
	fileMutex   sync.Mutex
}

type AuditEvent struct {
	Timestamp int64                  `json:"timestamp"`
	Type      string                 `json:"type"`
	Hostname  string                 `json:"hostname"`
	Sequence  uint32                 `json:"sequence"`
	Category  string                 `json:"category"`
	Summary   string                 `json:"summary"`
	RawData   map[string]interface{} `json:"raw_data"`
	Tags      []string               `json:"tags"`
}

func NewAuditdCollector(cfg Config, bi esutil.BulkIndexer) *AuditdCollector {
	return &AuditdCollector{
		cfg:         cfg,
		bulkIndexer: bi,
		stopChan:    make(chan struct{}),
	}
}

func (ac *AuditdCollector) Start() error {
	if err := ac.setupLogging(); err != nil {
		log.Printf("[!] Warning: Failed to setup Auditd file logging: %v", err)
	}

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

	// Increase buffer to prevent "lost events" under load
	if err := ac.client.SetBacklogLimit(8192, libaudit.NoWait); err != nil {
		log.Printf("[!] Warning: Failed to increase backlog limit: %v", err)
	}

	if err := ac.client.SetPID(libaudit.NoWait); err != nil {
		log.Printf("[!] Warning: Failed to set audit PID: %v", err)
	}

	ac.reassembler, err = libaudit.NewReassembler(5, 2*time.Second, &auditStreamHandler{collector: ac})
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

	fmt.Printf("[+] Auditd Collector Running (PID: %d)\n", status.PID)
	for {
		select {
		case <-ac.stopChan:
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

			// Filter out non-audit messages (type < 1000 are system control messages)
			if err := ac.reassembler.Push(msg.Type, msg.Data); err != nil {
				log.Printf("[!] Reassembler Push Error: %v (dropping raw message)", err)
			}
		}
	}
}

func (ac *AuditdCollector) Stop() {
	close(ac.stopChan)
	if ac.outputFile != nil {
		ac.outputFile.Close()
	}

	if ac.client != nil {
		log.Println("[*] Stopping audit client and unregistering...")
		if err := ac.client.Close(); err != nil {
			log.Printf("[!] Error closing audit client: %v", err)
		}
	}
}

func (ac *AuditdCollector) setupLogging() error {
	if ac.cfg.EventsDir == "" {
		ac.cfg.EventsDir = "/var/monitoring/events"
	}

	if err := os.MkdirAll(ac.cfg.EventsDir, 0755); err != nil {
		return err
	}

	path := fmt.Sprintf("%s/auditd-events.jsonl", ac.cfg.EventsDir)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	ac.outputFile = f
	fmt.Printf("[+] Auditd logging enabled: %s\n", path)
	return nil
}

type auditStreamHandler struct {
	collector *AuditdCollector
}

// ReassemblyComplete is called when a set of kernel messages forms a complete event
func (h *auditStreamHandler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	if len(msgs) == 0 {
		return
	}

	// Simplify the raw kernel messages into a high-level event
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		return
	}

	// Resolve IDs (e.g. 1000 -> "student")
	aucoalesce.ResolveIDs(event)

	output := AuditEvent{
		Timestamp: event.Timestamp.UnixMilli(),
		Type:      event.Type.String(),
		Hostname:  h.collector.cfg.Hostname,
		Sequence:  event.Sequence,
		Category:  event.Category.String(),
		Summary:   event.Summary.Action,
		RawData:   make(map[string]interface{}),
		Tags:      []string{"auditd", "kernel"},
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
			}
		}
	}

	// Marshal to JSON
	data, err := json.Marshal(output)
	if err != nil {
		log.Printf("[!] Failed to marshal audit event: %v", err)
		return
	}

	if h.collector.outputFile != nil {
		h.collector.fileMutex.Lock()
		if _, err := h.collector.outputFile.Write(data); err != nil {
			log.Printf("[!] Failed to write audit event to file: %v", err)
		}
		if _, err := h.collector.outputFile.WriteString("\n"); err != nil {
			log.Printf("[!] Failed to write newline to file: %v", err)
		}
		h.collector.fileMutex.Unlock()
	}

	// Send to Elasticsearch
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

func (h *auditStreamHandler) EventsLost(count int) {
	log.Printf("[!] Lost %d audit events (kernel buffer overflow)", count)
}
