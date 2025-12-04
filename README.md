# System Monitor with Provenance Analysis

A comprehensive security forensics platform that combines **eBPF syscall monitoring** and **PCAP network capture** to build provenance graphs for attack analysis and threat hunting.

[![Linux](https://img.shields.io/badge/OS-Linux-blue.svg)](https://www.kernel.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Kernel%205.8%2B-green.svg)](https://ebpf.io/)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://golang.org/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg)](https://www.python.org/)

## 🎯 Overview

**System-Monitor** captures security-relevant system activity at two levels:
- **eBPF Layer**: Kernel-level syscall monitoring (execve, file I/O, network syscalls, process creation)
- **PCAP Layer**: Network packet capture with flow aggregation and DNS enrichment

Events are correlated into **provenance graphs** showing:
- 🔗 Process execution chains
- 📂 File access patterns
- 🌐 Network connections
- 🔍 Attack progression timelines

## ✨ Key Features

### Real-Time Monitoring
- ✅ **Dual-Layer Capture**: eBPF syscalls + PCAP network flows
- ✅ **Intelligent Filtering**: Three-stage filtering (process → path → network whitelist)
- ✅ **Self-Protection**: Prevents infinite loops from monitoring own traffic
- ✅ **Multi-Host Support**: Hostname tagging for centralized deployments

### Interactive Web Interface
- 📊 **12+ Visualizations**: Protocol distribution, traffic heatmaps, timeline analysis
- 🔍 **Event Search**: Filter by time range, hostname, syscall, process, PID
- 🕸️ **Provenance Graphs**: Interactive, color-coded graphs with BEEP noise reduction
- 🤖 **AI Analysis**: Ollama integration for threat narrative generation
- 📥 **Offline Analysis**: PCAP/audit log correlation for post-mortem forensics

### Production-Ready
- 📦 **Systemd Services**: Auto-restart, log rotation, graceful shutdown
- 🔧 **Flexible Storage**: Elasticsearch or local JSONL files
- 🛡️ **Security-Aware**: Designed to prevent evasion and bypass attempts
- 📈 **Scalable**: Handles high-volume environments with configurable batching

## 🚀 Quick Start

### Prerequisites

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y \
    linux-headers-$(uname -r) \
    clang llvm \
    libpcap-dev \
    golang-1.22 \
    python3-pip

# Verify kernel version (need 5.8+)
uname -r
```

### Option 1: Build from Source

```bash
# Clone repository
git clone https://github.com/yourusername/ebpf-provenance.git
cd ebpf-provenance

# Build binary
make build

# Install (creates systemd service)
sudo make install

# Start monitoring
sudo systemctl start system-monitor
sudo systemctl enable system-monitor

# View logs
sudo journalctl -u system-monitor -f
```

### Option 2: Install from Package

```bash
# Build package
make package VERSION=1.0.0

# Install
sudo dpkg -i build/system-monitor_1.0.0_amd64.deb

# Start service
sudo systemctl start system-monitor
```

### Launch Web Interface

```bash
cd web
pip install -r requirements.txt
streamlit run webapp.py --server.port=8501

# Access at: http://localhost:8501
```

### Run as Service

```bash
# Install and start webapp service
sudo cp scripts/streamlit-webapp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start streamlit-webapp
sudo systemctl enable streamlit-webapp
```

## 📋 Configuration

### Main Configuration (`/var/monitoring/config.json`)

```json
{
  "hostname": "",
  "events_dir": "/var/monitoring/events/",
  "output_dir": "/var/monitoring/outputs/",
  "storage_type": "elasticsearch",
  "es_config": {
    "es_host": "localhost",
    "es_port": 9200,
    "es_user": "elastic",
    "es_password": "changeme",
    "ebpf_index": "ebpf-events",
    "pcap_index": "pcap-flows",
    "batch_size": 1000,
    "secure": true
  },
  "ebpf_config": {
    "enabled": true,
    "file_logging_enabled": false
  },
  "pcap_config": {
    "enabled": true,
    "file_logging_enabled": true,
    "interface": "eth0",
    "bpf_filter": "tcp or udp",
    "flow_timeout": 300,
    "dns_cache_ttl": 300,
    "flush_interval": 60
  }
}
```

### Configuration Options

| Field                                  | Description                                    | Default         |
| -------------------------------------- | ---------------------------------------------- | --------------- |
| `hostname`                             | Hostname tag for events (auto-detect if empty) | `""`            |
| `storage_type`                         | Storage backend: `elasticsearch` or `local`    | `elasticsearch` |
| `ebpf_config.enabled`                  | Enable eBPF syscall monitoring                 | `true`          |
| `ebpf_config.file_logging_enabled`     | Enable eBPF events JSONL file logging          | `false`         |
| `pcap_config.enabled`                  | Enable PCAP network capture                    | `true`          |
| `pcap_config.file_logging_enabled`     | Enable PCAP flows JSONL file logging           | `true`          |
| `pcap_config.interface`                | Network interface to capture                   | `eth0`          |
| `pcap_config.bpf_filter`               | Berkeley Packet Filter expression              | `tcp or udp`    |
| `pcap_config.flow_timeout`             | Flow inactivity timeout (seconds)              | `300`           |
| `pcap_config.dns_cache_ttl`            | DNS cache entry lifetime (seconds)             | `300`           |
| `pcap_config.flush_interval`           | Flow flush interval (seconds)                  | `60`            |

### Elasticsearch Setup

```bash
# Index mappings are auto-created on first run
# Two indices:
# - ebpf-events: Syscall events
# - pcap-flows: Network flows

# Verify indices
curl -u elastic:password http://localhost:9200/_cat/indices
```

## 🏗️ Architecture

### Data Flow

```
┌────────────────────────────────────────────────────────────┐
│                       KERNEL SPACE                         │
│  ┌──────────────────┐              ┌──────────────────┐    │
│  │ Syscall          │              │ Network          │    │
│  │ Tracepoints      │              │ Interface        │    │
│  └────────┬─────────┘              └────────┬─────────┘    │
│           │                                 │              │
│  ┌────────▼─────────┐              ┌────────▼─────────┐    │
│  │ eBPF Programs    │              │ libpcap/BPF      │    │
│  │ (main.bpf.c)     │              │ Filter           │    │
│  └────────┬─────────┘              └────────┬─────────┘    │
└───────────┼─────────────────────────────────┼──────────────┘
            │ perf buffer                     │ packets
            │                                 │
┌───────────▼─────────────────────────────────▼──────────────┐
│                      USER SPACE                            │
│  ┌──────────────────┐              ┌──────────────────┐    │
│  │ eBPF Collector   │              │ PCAP Collector   │    │
│  │ (ebpf.go)        │              │ (pcap.go)        │    │
│  │                  │              │                  │    │
│  │ - Parse events   │              │ - Flow           │    │
│  │ - Enrich data    │              │   aggregation    │    │
│  │ - Filter noise   │              │ - DNS enrichment │    │
│  │ - Whitelist      │              │ - TCP flags      │    │
│  └────────┬─────────┘              └────────┬─────────┘    │
│           │                                 │              │
│           └──────────────┬──────────────────┘              │
│                          │ JSON events                     │
│                 ┌────────▼─────────┐                       │
│                 │  Storage Layer   │                       │
│                 │  - Elasticsearch │                       │
│                 │  - JSONL Files   │                       │
│                 └────────┬─────────┘                       │
│                          │                                 │
│                 ┌────────▼─────────┐                       │
│                 │  Web Interface   │                       │
│                 │  (Streamlit)     │                       │
│                 │                  │                       │
│                 │ - Event Viewer   │                       │
│                 │ - Flow Viz       │                       │
│                 │ - Provenance     │                       │
│                 │ - AI Analysis    │                       │
│                 └──────────────────┘                       │
└────────────────────────────────────────────────────────────┘
```

### Three-Stage Filtering

**Stage 1: Process-Based (Early Drop)**
- Filters: `system-monitor`, `ebpf-*`, `systemd-*`, `snapd`, `node_exporter`
- **Security**: Attackers accessing `/var/monitoring/*` are CAPTURED (different comm)

**Stage 2: Path-Based (Context-Aware)**
- Filters: `/usr/lib*`, `/lib*`, `/proc/*`, `/sys/*`, `/dev/null`
- **Never filters**: `execve` syscalls (critical security invariant)

**Stage 3: Network Whitelist (IP+Port)**
- Filters: Combined IP+Port rules (BOTH must match)
- **Security**: Prevents attackers using whitelisted ports to other hosts
- Example: ES at `192.168.1.50:9200` → Only that exact destination filtered

## 🔧 Components

### 1. eBPF Collector (`bpf/main.bpf.c` + `cmd/system-monitor/ebpf.go`)

**Monitored Syscalls**:
- Process: `execve`, `clone`, `clone3`, `vfork`
- File I/O: `openat`, `openat2`, `read`, `write`, `unlinkat`
- Network: `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`, `sendto`, `recvfrom`

**Key Features**:
- Perf buffer for event passing (64MB per CPU)
- Network byte order handling for IP addresses
- Errno translation for error analysis
- Process start time for correlation

### 2. PCAP Collector (`cmd/system-monitor/pcap.go`)

**Features**:
- 5-tuple flow aggregation (src_ip, dst_ip, src_port, dst_port, protocol)
- Passive DNS resolution from captured traffic
- TCP flag extraction (SYN, ACK, FIN, RST, PSH, URG)
- Configurable BPF filtering at kernel level
- Periodic flushing based on inactivity timeout

**Output Format** (pcap-flows.jsonl):
```json
{
  "hostname": "server-01",
  "src_ip": "192.168.1.100",
  "dst_ip": "93.184.216.34",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "packet_count": 150,
  "byte_count": 45000,
  "tcp_flags": ["SYN", "ACK", "PSH", "FIN"],
  "domain_name": "example.com",
  "dns_resolved": true,
  "first_seen": "2025-12-03T10:30:00Z",
  "last_seen": "2025-12-03T10:32:15Z"
}
```

### 3. Web Interface (`web/`)

**Multi-Page Application**:

📊 **Dashboard** (`pages/home.py`)
- System status and monitoring mode
- 24-hour activity metrics
- Top syscalls and processes
- Quick navigation buttons

📝 **eBPF Events** (`pages/ebpf_events.py`)
- Tabular view: 500-5000 events per page (default: 1000)
- Filters: Time range, hostname, syscall, process, PID, PPID
- Smart "Target" column (filename or IP:Port)
- Summary statistics: Unique syscalls, processes, errors

🌐 **PCAP Flows** (`pages/pcap_flows.py`)
- **Dual Dataset Architecture**:
  - Table: Top 100 flows (sortable)
  - Visualizations: ALL flows in time range (up to 10k)
- 12+ interactive visualizations:
  - Protocol distribution
  - Traffic over time (5-min intervals)
  - Top source/destination IPs
  - Port analysis (by flow count and bytes)
  - Duration distribution
  - Bytes vs Packets scatter plot
  - TCP flags distribution
  - Traffic heatmap by hour
  - Domain analysis (if DNS resolved)

🕸️ **Provenance Analysis** (`pages/provenance.py`)
- Interactive graph generation
- BEEP algorithm for noise reduction
- Color-coded nodes by security relevance
- AI-powered attack narrative (Ollama)
- PNG export and attack summary

📦 **Offline Analysis** (`pages/offline_analysis.py`)
- Upload PCAP + audit logs
- Time-based correlation (configurable tolerance)
- Process attribution for network flows
- Visualizations: Timeline, top processes, protocol distribution
- AI insights: Anomaly detection, severity scoring

### 4. Activity Generator (`scripts/generate_activity.sh`)

**Test script for forensics validation**:
- 10 activity categories: Normal (File I/O, Network, Process, System) + Suspicious (Recon, Lateral Movement, Persistence, Exfiltration, Credential Access, Evasion)
- Rotates through 6 patterns every 2-5 seconds
- Generates ~500-1000 eBPF events and ~50-100 PCAP flows per iteration

**Usage**:
```bash
# Run for 60 seconds (default)
sudo bash scripts/generate_activity.sh

# Run for custom duration
sudo bash scripts/generate_activity.sh 300
```

## 📊 Use Cases

### 1. Real-Time Threat Hunting
Monitor live systems for suspicious activity patterns:
- Port scanning
- Lateral movement attempts
- Data exfiltration
- Privilege escalation

### 2. Incident Response
Post-mortem analysis of compromised systems:
- Reconstruct attack timeline
- Identify persistence mechanisms
- Trace data access and exfiltration
- Generate forensic reports

### 3. Compliance Auditing
Log and audit system activity:
- Track privileged access
- Monitor file integrity
- Network connection logs
- Process execution history

### 4. Security Research
Study malware behavior in controlled environments:
- Trace execution flow
- Identify C2 communication
- Analyze evasion techniques
- Build detection signatures

## 🛡️ Security Considerations

### Whitelist Architecture

**Combined IP+Port Rules**: Prevents bypass attacks
```
✅ System-monitor → 192.168.1.50:9200 (ES) → FILTERED
❌ Attacker → 1.2.3.4:9200 → CAPTURED (IP doesn't match)
❌ Attacker → 192.168.1.50:8080 → CAPTURED (port doesn't match)
```

**Process-Based Self-Protection**: No blind spots
```
✅ system-monitor writes /var/monitoring/events/* → FILTERED (by comm)
✅ Attacker reads /var/monitoring/events/* → CAPTURED (different comm)
```

### eBPF Verifier Constraints

**Max 8 Whitelist Rules**: Technical limitation
- eBPF verifier cannot prove loop termination
- Function manually unrolled to check 8 rules explicitly
- Sufficient for typical use (1-2 rules: ES + localhost)

### Attack Surface Minimization

- Runs as root (required for eBPF/PCAP)
- No web interface in privileged process
- Elasticsearch credentials configurable
- File permissions: 0644 for events, 0755 for directories

## 🐛 Troubleshooting

### eBPF Program Won't Load

```bash
# Check kernel version (need 5.8+)
uname -r

# Verify BTF support
ls /sys/kernel/btf/vmlinux

# Check verifier errors
sudo journalctl -u system-monitor -n 50

# Common issue: Verifier error with whitelist
# Solution: Ensure is_whitelisted_network() has no loops (manually unrolled)
```

### No Events in Web Interface

```bash
# Check service status
sudo systemctl status system-monitor

# Verify Elasticsearch connectivity
curl http://localhost:9200/_cat/indices

# Check file logging
ls -la /var/monitoring/events/

# Verify time range in web UI
# Ensure hostname filter matches your system
```

### High CPU Usage

```bash
# Adjust eBPF filtering (add more noise filters)
# Edit bpf/main.bpf.c → should_drop_comm()

# Tune Elasticsearch batch size
# Edit config.json → es_config.batch_size (increase)

# Tighten PCAP BPF filter
# Edit config.json → pcap_config.bpf_filter
# Example: "tcp port 443" (HTTPS only)

# Increase flush interval
# Edit config.json → pcap_config.flush_interval
```

### PCAP Collector Issues

```bash
# Permission denied
sudo setcap cap_net_raw,cap_net_admin=eip ./system-monitor

# No such device
ip link show  # Verify interface name
# Update config.json → pcap_config.interface

# High memory usage
# Reduce flow_timeout (flush more aggressively)
# Reduce flush_interval (write more frequently)
cat /proc/$(pidof system-monitor)/status | grep VmRSS
```

## 📦 Building Packages

```bash
# Install nfpm
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

# Build Debian package
make package VERSION=1.2.3

# Output: build/system-monitor_1.2.3_amd64.deb

# Install package
sudo dpkg -i build/system-monitor_1.2.3_amd64.deb

# Package includes:
# - Binary: /usr/bin/system-monitor
# - Config: /var/monitoring/config.json
# - Service: /etc/systemd/system/system-monitor.service
# - Directories: /var/monitoring/events, /var/monitoring/outputs
```

## 🧪 Testing

### Generate Test Activity

```bash
# Start monitoring
sudo systemctl start system-monitor

# Generate activity for 2 minutes
sudo bash scripts/generate_activity.sh 120

# View in web UI
cd web && streamlit run webapp.py

# Expected:
# - eBPF Events: ~500-1000 per iteration
# - PCAP Flows: ~50-100 per iteration
# - Provenance graphs showing process trees
```

### Verify Capture

```bash
# Check event files
tail -f /var/monitoring/events/forensic-events.jsonl
tail -f /var/monitoring/events/pcap-flows.jsonl

# Check Elasticsearch
curl -u elastic:password http://localhost:9200/ebpf-events/_count
curl -u elastic:password http://localhost:9200/pcap-flows/_count

# View logs
sudo journalctl -u system-monitor -f
```

## 📚 Documentation

- **Project Guide**: [CLAUDE.md](CLAUDE.md) - Comprehensive developer documentation
- **eBPF Details**: [bpf/README.md](bpf/README.md) - Kernel program specifics
- **Web Interface**: [web/README.md](web/README.md) - UI architecture
- **Configuration**: See "Configuration" section above

## 🤝 Contributing

Contributions welcome! Please:
1. Read [CLAUDE.md](CLAUDE.md) for architecture details
2. Follow existing code style
3. Test with `scripts/generate_activity.sh`
4. Update documentation for new features

## 📄 License

MIT License - See [LICENSE](LICENSE) for details

## 🙏 Acknowledgments

- [eBPF](https://ebpf.io/) - Extended Berkeley Packet Filter
- [cilium/ebpf](https://github.com/cilium/ebpf) - Go eBPF library
- [gopacket](https://github.com/google/gopacket) - Packet processing
- [Streamlit](https://streamlit.io/) - Web framework
- [Elasticsearch](https://www.elastic.co/) - Search and analytics
- [Ollama](https://ollama.ai/) - Local LLM inference

## 🔗 Links

- **Documentation**: [Full Developer Guide](CLAUDE.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/ebpf-provenance/issues)
- **eBPF Resources**: [ebpf.io](https://ebpf.io/), [Cilium Docs](https://docs.cilium.io/en/stable/bpf/)

---

**Built with ❤️ for security researchers, incident responders, and threat hunters.**
