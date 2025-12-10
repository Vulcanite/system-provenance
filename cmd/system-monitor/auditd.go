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
	"github.com/elastic/go-libaudit/v2/rule"
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

func (ac *AuditdCollector) loadAuditRules() error {
	// Clear any existing audit rules first
	deleted, err := ac.client.DeleteRules()
	if err != nil {
		log.Printf("[!] Warning: Failed to clear existing audit rules: %v", err)
	} else if deleted > 0 {
		log.Printf("[*] Cleared %d existing audit rules", deleted)
	}

	// Small delay to ensure the delete operation completes
	time.Sleep(100 * time.Millisecond)

	ruleCount := 0

	for i, auditRule := range ac.cfg.AuditdConfig.Rules {
		var err error

		switch auditRule.Type {
		case "watch":
			log.Printf("[*] Adding watch rule %d/%d: %s (key=%s)", i+1, len(ac.cfg.AuditdConfig.Rules), auditRule.Path, auditRule.Key)
			err = ac.applyWatchRule(auditRule)
		case "syscall":
			log.Printf("[*] Adding syscall rule %d/%d: %v (key=%s)", i+1, len(ac.cfg.AuditdConfig.Rules), auditRule.Syscalls, auditRule.Key)
			err = ac.applySyscallRule(auditRule)
		default:
			log.Printf("[!] Warning: Unknown rule type '%s', skipping", auditRule.Type)
			continue
		}

		if err != nil {
			log.Printf("[!] Warning: Failed to apply %s rule (key=%s): %v", auditRule.Type, auditRule.Key, err)
			continue
		}

		// Small delay between rules to allow kernel to process ACKs
		time.Sleep(50 * time.Millisecond)
		ruleCount++
	}

	log.Printf("[+] Successfully loaded %d audit rules", ruleCount)
	return nil
}

func (ac *AuditdCollector) applyWatchRule(auditRule AuditRule) error {
	if auditRule.Path == "" {
		return fmt.Errorf("watch rule requires path")
	}

	// Build the watch rule
	r := &rule.FileWatchRule{
		Type: rule.FileWatchRuleType,
		Path: auditRule.Path,
	}

	// Convert permissions
	if strings.Contains(auditRule.Permissions, "r") {
		r.Permissions = append(r.Permissions, rule.ReadAccessType)
	}
	if strings.Contains(auditRule.Permissions, "w") {
		r.Permissions = append(r.Permissions, rule.WriteAccessType)
	}
	if strings.Contains(auditRule.Permissions, "x") {
		r.Permissions = append(r.Permissions, rule.ExecuteAccessType)
	}
	if strings.Contains(auditRule.Permissions, "a") {
		r.Permissions = append(r.Permissions, rule.AttributeChangeAccessType)
	}

	if auditRule.Key != "" {
		r.Keys = []string{auditRule.Key}
	}

	// Convert to wire format and add
	ruleData, err := rule.Build(r)
	if err != nil {
		return fmt.Errorf("failed to build watch rule: %v", err)
	}

	if err := ac.client.AddRule(ruleData); err != nil {
		return fmt.Errorf("failed to add watch rule: %v", err)
	}

	return nil
}

func (ac *AuditdCollector) applySyscallRule(auditRule AuditRule) error {
	if auditRule.Action == "" || auditRule.List == "" {
		return fmt.Errorf("syscall rule requires action and list")
	}

	r := &rule.SyscallRule{
		Type:     rule.AppendSyscallRuleType,
		Action:   auditRule.Action,
		List:     auditRule.List,
		Syscalls: auditRule.Syscalls,
	}

	// Add arch filter if specified
	if auditRule.Arch != "" {
		r.Filters = append(r.Filters, rule.FilterSpec{
			Type:       rule.ValueFilterType,
			LHS:        "arch",
			Comparator: "=",
			RHS:        auditRule.Arch,
		})
	}

	// Parse and add additional filters
	for _, filter := range auditRule.Filters {
		// Parse filter into LHS, operator, RHS
		var lhs, comparator, rhs string
		if strings.Contains(filter, "!=") {
			parts := strings.Split(filter, "!=")
			lhs = parts[0]
			comparator = "!="
			rhs = parts[1]
		} else if strings.Contains(filter, "=") {
			parts := strings.Split(filter, "=")
			lhs = parts[0]
			comparator = "="
			rhs = parts[1]
		}

		if lhs != "" {
			r.Filters = append(r.Filters, rule.FilterSpec{
				Type:       rule.ValueFilterType,
				LHS:        lhs,
				Comparator: comparator,
				RHS:        rhs,
			})
		}
	}

	if auditRule.Key != "" {
		r.Keys = []string{auditRule.Key}
	}

	// Build and add the rule
	ruleData, err := rule.Build(r)
	if err != nil {
		return fmt.Errorf("failed to build syscall rule: %v", err)
	}

	if err := ac.client.AddRule(ruleData); err != nil {
		return fmt.Errorf("failed to add syscall rule: %v", err)
	}

	return nil
}

func (ac *AuditdCollector) Start() error {
	if err := ac.setupLogging(); err != nil {
		log.Printf("[!] Warning: Failed to setup Auditd file logging: %v", err)
	}

	var err error
	// Note: NewAuditClient requires root privileges (sudo)
	ac.client, err = libaudit.NewAuditClient(nil)
	if err != nil {
		return fmt.Errorf("failed to create audit client (requires root): %v", err)
	}
	defer ac.client.Close()

	status, err := ac.client.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get audit status: %v", err)
	}

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

	// Load audit rules from config
	if err := ac.loadAuditRules(); err != nil {
		log.Printf("[!] Warning: Failed to load audit rules: %v", err)
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

	// Main Event Loop
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

			// Push to reassembler -> triggers ReassemblyComplete
			// Filter out non-audit messages (type < 1000 are system control messages)
			if msg != nil && msg.Type >= 1000 {
				ac.reassembler.Push(msg.Type, msg.Data)
			}
		}
	}
}

func (ac *AuditdCollector) Stop() {
	close(ac.stopChan)
	if ac.outputFile != nil {
		ac.outputFile.Close()
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
		log.Printf("[!] DEBUG: Coalesce Failed (dropping event): %v", err)
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

	// Capture all raw key-values from the kernel
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

	fmt.Printf("[+] Writing event: %s\n", event.Summary.Action)
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
