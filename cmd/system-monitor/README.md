# System Monitor - Go Application

User-space application that loads eBPF programs, captures network packets, processes events, and manages storage.

## Overview

The system-monitor application provides comprehensive system and network monitoring through two integrated collectors:

1. **eBPF Collector** - Captures syscalls (process, file, network operations) at the kernel level
2. **PCAP Collector** - Captures and aggregates network packet flows with DNS enrichment

Both collectors run concurrently and can be independently enabled/disabled via configuration.

## Files

- **main.go** - Main application logic, configuration, signal handling, orchestration (~238 lines)
- **ebpf.go** - eBPF collector: program loading, event processing, enrichment (~394 lines)
- **pcap.go** - PCAP collector: packet capture, flow aggregation, DNS enrichment (~428 lines)
- **gen.go** - Code generation directive for bpf2go
- **bpf_bpf.go** - Auto-generated Go bindings for eBPF programs (generated)
- **bpf_bpf.o** - Compiled eBPF object file (generated)

## Architecture

```
Kernel Tracepoints                Network Interface
      |                                   |
      v                                   v
[eBPF Programs (C)]              [PCAP Capture]
  bpf/main.bpf.c                  gopacket/libpcap
      |                                   |
      | perf event buffer                 |
      v                                   v
[eBPF Collector]                 [Flow Aggregator]
  ebpf.go                           pcap.go
  - Event reader                    - 5-tuple grouping
  - Parser                          - DNS enrichment
  - IP formatting                   - TCP flag extraction
  - Errno translation               - Periodic flushing
      |                                   |
      +-----------------------------------+
                      |
                      | JSON events
                      v
              [Storage Layer]
                 /         \
                v           v
            JSONL        Elasticsearch
            Files        (bulk indexing)
          - ebpf-events.jsonl   ebpf-events index
          - pcap-flows.jsonl    pcap-flows index
```

## Dependencies

From `go.mod`:

```go
require (
    github.com/cilium/ebpf v0.20.0              // eBPF program loading
    github.com/elastic/go-elasticsearch/v8 v8.19.0  // Event indexing
    github.com/google/gopacket v1.1.19          // Packet capture
)
```

### Key Libraries

- **cilium/ebpf** - Load and manage eBPF programs
- **go-elasticsearch** - Elasticsearch client for event indexing
- **gopacket** - Packet capture and parsing (libpcap wrapper)
- **gopacket/layers** - Protocol dissection (TCP, UDP, DNS, IPv4, IPv6)

## Usage

### Running Manually

```bash
# Ensure config exists
sudo mkdir -p /var/monitoring/events
sudo cp config/config.json /var/monitoring/config.json

# Run as root (required for eBPF and PCAP)
sudo ./system-monitor
```

### Running as Service

```bash
# Start service
sudo systemctl start system-monitor

# Enable on boot
sudo systemctl enable system-monitor

# View status
sudo systemctl status system-monitor

# View logs
sudo journalctl -u system-monitor -f
```

### Log Rotation

```bash
# Trigger log rotation
sudo systemctl kill -s HUP system-monitor

# Or use logrotate (automatic)
sudo logrotate -f /etc/logrotate.d/ebpf-provenance
```

## Configuration

Edit `/var/monitoring/config.json`:

```json
{
  "hostname": "",
  "events_dir": "/var/monitoring/events/",
  "output_dir": "/var/monitoring/outputs/",
  "monitoring": {
    "ebpf_enabled": true,
    "pcap_enabled": true
  },
  "storage": {
    "file_logging_enabled": true,
    "type": "elasticsearch"
  },
  "es_config": {
    "es_host": "localhost",
    "es_port": 9200,
    "es_user": "elastic",
    "es_password": "changeme",
    "ebpf_index": "ebpf-events",
    "pcap_index": "pcap-flows",
    "batch_size": 500,
    "secure": true
  },
  "pcap_config": {
    "interface": "eth0",
    "bpf_filter": "tcp or udp",
    "flow_timeout": 300,
    "dns_cache_ttl": 300,
    "flush_interval": 60
  }
}
```

### Configuration Options

**Monitoring Control:**
- `monitoring.ebpf_enabled`: Enable/disable eBPF syscall monitoring
- `monitoring.pcap_enabled`: Enable/disable packet capture
- `hostname`: Override hostname (empty = auto-detect)

**Storage:**
- `storage.type`: `"elasticsearch"` or `"local"` (file-only)
- `storage.file_logging_enabled`: Write JSONL files regardless of storage type
- `es_config.secure`: `true` for HTTPS, `false` for HTTP
- `es_config.batch_size`: Events per bulk indexing batch

**PCAP Collector:**
- `pcap_config.interface`: Network interface to capture (e.g., eth0, wlan0)
- `pcap_config.bpf_filter`: Berkeley Packet Filter expression (default: "tcp or udp")
- `pcap_config.flow_timeout`: Seconds before flushing inactive flows (default: 300)
- `pcap_config.dns_cache_ttl`: DNS cache entry lifetime in seconds (default: 300)
- `pcap_config.flush_interval`: How often to flush active flows in seconds (default: 60)

### Modular Monitoring

Run eBPF-only (no packet capture):
```json
{
  "monitoring": {
    "ebpf_enabled": true,
    "pcap_enabled": false
  }
}
```

Run PCAP-only (no syscall monitoring):
```json
{
  "monitoring": {
    "ebpf_enabled": false,
    "pcap_enabled": true
  }
}
```
