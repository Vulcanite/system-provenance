# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eBPF Provenance Monitor is a security forensics tool that captures system calls at the kernel level using eBPF and network traffic using PCAP, building provenance graphs for attack analysis. The system has three main components:

1. **eBPF + PCAP Collector** (C + Go) - Dual monitoring system:
   - eBPF: Kernel-space syscall monitoring with intelligent filtering
   - PCAP: Network packet capture with flow aggregation and DNS enrichment
2. **Web Interface** (Python/Streamlit) - Interactive graph visualization and analysis
3. **Deployment Scripts** - Systemd services and package management

## Build and Development Commands

### eBPF Collector (Go)

```bash
# Generate eBPF Go bindings from C code (required after editing bpf/main.bpf.c)
make generate

# Build the binary
make build

# Clean generated files and binary
make clean

# Run manually (requires root)
sudo ./ebpf-monitor

# Run with custom config
sudo ./ebpf-monitor --config=/path/to/config.json
```

### Package Management

```bash
# Build Debian package
make package VERSION=1.2.3

# Install to system (installs binary + systemd service)
sudo make install

# Uninstall (removes binary and service, keeps config)
sudo make uninstall
```

### Service Management

```bash
# Start/stop/restart the monitor
sudo systemctl start ebpf-monitor
sudo systemctl stop ebpf-monitor
sudo systemctl restart ebpf-monitor

# View logs
sudo journalctl -u ebpf-monitor -f
make logs

# Trigger log rotation
sudo systemctl kill -s HUP ebpf-monitor
```

### Web Interface (Python)

```bash
cd web

# Install dependencies
pip install -r requirements.txt

# Run webapp
streamlit run webapp.py --server.port=8501 --server.address=0.0.0.0

# Run as service
sudo systemctl start streamlit-webapp
sudo journalctl -u streamlit-webapp -f
```

### Testing

There are currently no automated tests in the repository. When adding tests:
- Go tests should use standard `go test` framework
- Python tests should use pytest

## Architecture

### Data Flow

```
Kernel Tracepoints               Network Interface
       |                                |
       v                                v
[eBPF Programs (C)]            [PCAP Capture (Go)]
   bpf/main.bpf.c              cmd/ebpf-monitor/pcap.go
       |                                |
       | perf event buffer              | gopacket
       v                                v
[eBPF Event Processor]         [Flow Aggregator]
       |                           - 5-tuple flows
       |                           - DNS enrichment
       |                           - TCP flags
       |                                |
       +--------------------------------+
                    |
                    | JSON events
                    v
            [Storage Layer]
               /         \
              v           v
            JSONL    Elasticsearch
            Files    (2 indices)
              |      - ebpf-events
              |      - pcap-flows
              +-----------|
                    |
                    v
          [Streamlit Web UI]     <-- web/webapp.py
                    |                 web/analyzer.py
                    v
          [Provenance Graphs]
```

### Component Details

#### 1. eBPF Programs (`bpf/main.bpf.c`)

Kernel-space monitoring with two-stage filtering:

**Stage 1 (Early)**: Process-based filtering in `init_event()`
- Drops self-monitoring (ebpf-* processes)
- Filters noisy system daemons (systemd-*, snapd, node_exporter)
- Smart kernel thread detection (checks PF_KTHREAD flag to avoid malware bypass)

**Stage 2 (Late)**: Context-aware filtering in `submit()`
- NEVER filters execve (malware may execute from /tmp, /var/log)
- Filters library loads (/usr/lib*, /lib*) for non-exec syscalls
- Filters pseudo-filesystems (/proc, /sys, /dev/null)

**Monitored syscalls**: execve, clone/clone3/vfork, openat/openat2, read, write, connect, unlinkat

**Key data structure**: `struct so_event` (defined in bpf/main.bpf.c)
- Must match the Go struct in cmd/ebpf-monitor/main.go
- Contains: pid, ppid, uid, comm, syscall, filename, network info, etc.

**eBPF Maps**:
- `events` - Perf buffer for passing events to userspace
- `event_heap` - Per-CPU storage to avoid stack allocation
- `open_data`, `read_data`, `write_data` - Correlate enter/exit syscalls

#### 2. Go Collector (`cmd/ebpf-monitor/main.go`)

**Build process**:
1. `gen.go` contains `//go:generate` directive
2. `bpf2go` generates `bpf_bpf.go` (Go bindings) and `bpf_bpf.o` (compiled eBPF)
3. Main app loads `bpf_bpf.o` into kernel

**Event processing**:
- Reads from perf buffer using cilium/ebpf library
- Enriches events (timestamp formatting, IP parsing, errno translation)
- Dual output: JSONL files + Elasticsearch bulk indexing

**Configuration**: `/var/config.json`
- `storage_type`: "elasticsearch" or "local"
- `events_dir`: Directory for JSONL output
- `es_config`: Elasticsearch connection details

**Dependencies** (go.mod):
- `github.com/cilium/ebpf` - eBPF program loading and management
- `github.com/elastic/go-elasticsearch/v8` - Event indexing
- `github.com/google/gopacket` - Packet capture and parsing

#### 3. PCAP Collector (`cmd/ebpf-monitor/pcap.go`)

**Packet capture and flow aggregation**:
- Uses gopacket/libpcap to capture packets from network interface
- Implements in-memory flow aggregation with 5-tuple keys
- Periodic flushing based on configurable intervals

**Flow tracking**:
- **FlowKey**: (src_ip, dst_ip, src_port, dst_port, protocol)
- **FlowStats**: packet_count, byte_count, first_seen, last_seen, tcp_flags
- Flows are flushed after `flow_timeout` seconds of inactivity

**DNS enrichment**:
- Passively extracts DNS A/AAAA responses from captured traffic
- Builds in-memory cache: IP → domain name mapping
- Cache entries expire after configurable TTL (default 300s)
- Automatically enriches flows with domain names when available

**TCP flag extraction**:
- Captures: SYN, ACK, FIN, RST, PSH, URG
- Tracks unique flags seen across all packets in a flow
- Useful for detecting connection patterns and anomalies

**BPF filtering**:
- Applies Berkeley Packet Filter at capture time (default: "tcp or udp")
- Reduces CPU overhead by dropping irrelevant packets in kernel

**Concurrency**:
- Runs in separate goroutine from eBPF collector
- Periodic flush every `flush_interval` seconds (default 60s)
- DNS cache cleanup runs every minute
- Thread-safe flow map and DNS cache with RWMutex

**Output format** (pcap-flows.jsonl):
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "93.184.216.34",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "packet_count": 150,
  "byte_count": 45000,
  "first_seen": "2025-12-02T10:30:00Z",
  "last_seen": "2025-12-02T10:32:15Z",
  "tcp_flags": ["SYN", "ACK", "PSH", "FIN"],
  "domain_name": "example.com",
  "dns_resolved": true
}
```

#### 4. Web Interface (`web/`)

**webapp.py**: Streamlit UI
- Event search with time ranges and filters
- Provenance graph generation (DOT, GraphML, Interactive HTML)
- Elasticsearch query builder

**analyzer.py**: Graph construction and filtering
- Implements BEEP algorithm (Bursty Event Elimination for Provenance)
- Context-aware noise reduction using `NOISE_CATEGORIES`
- Color-coded nodes by security relevance

**BEEP Algorithm**:
- Compresses repetitive events (e.g., log daemon writing 1000 times)
- Parameters: `time_window` (default 2000ms), `threshold` (min events to compress)
- Groups edges between same nodes if timestamps within window
- Creates summary edges with count metadata

**Noise Categories** (analyzer.py):
- Authentication (sshd, .ssh/*, shadow)
- System logging (/var/log/*)
- Package management (dpkg, apt)
- Shared libraries (*.so)
- Kernel pseudo-fs (/proc, /sys)

**Graph pruning**:
1. Tag nodes by sensitivity (benign/low/high)
2. Find connected components
3. Remove components containing ONLY benign nodes
4. Result: Preserves background noise only if connected to suspicious activity

## Configuration

### Default Config Location

`/var/config.json` (production) or `config/config.json` (development)

### Config Structure

```json
{
  "events_dir": "/var/monitoring/events/",
  "output_dir": "/var/monitoring/outputs/",
  "monitoring": {
    "ebpf_enabled": true,
    "pcap_enabled": true
  },
  "storage": {
    "file_logging_enabled": true,
    "storage_type": "elasticsearch"
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

**Modular monitoring**:
- Set `ebpf_enabled: false` to run PCAP only
- Set `pcap_enabled: false` to run eBPF only
- Set `file_logging_enabled: false` to disable JSONL output
- Set `storage_type: "local"` to use file-only storage without Elasticsearch

**PCAP configuration**:
- `interface`: Network interface to capture from (e.g., eth0, wlan0)
- `bpf_filter`: Berkeley Packet Filter expression (default: "tcp or udp")
- `flow_timeout`: Seconds of inactivity before flushing a flow (default: 300)
- `dns_cache_ttl`: DNS cache entry lifetime in seconds (default: 300)
- `flush_interval`: How often to flush active flows in seconds (default: 60)

## Code Modification Guidelines

### Modifying eBPF Programs

When editing `bpf/main.bpf.c`:

1. **Always run `make generate`** after changes to regenerate Go bindings
2. **Test filtering logic carefully** - over-filtering loses security events, under-filtering creates noise
3. **Never filter execve syscalls** - critical security invariant
4. **Maintain struct so_event compatibility** between C and Go
5. **Use `BPF_CORE_READ` macros** for kernel structure access (BTF portability)
6. **Check verifier limits** - eBPF has instruction count limits

### Adding New Syscalls

To monitor a new syscall:

1. Add tracepoint hooks in `bpf/main.bpf.c`:
   - `SEC("tp/syscalls/sys_enter_SYSCALL")`
   - `SEC("tp/syscalls/sys_exit_SYSCALL")` (if return value needed)
2. Update `struct so_event` if new fields required
3. Run `make generate` to update Go bindings
4. Update Go parser in `main.go` if new fields need formatting
5. Update web/analyzer.py to handle new edge types in graph

### Modifying Graph Analysis

When editing `web/analyzer.py`:

1. **Filtering changes**: Update `NOISE_CATEGORIES` dict
2. **BEEP tuning**: Adjust `time_window` or `threshold` parameters
3. **New node types**: Update coloring logic in graph visualization
4. **Export formats**: Modify DOT/GraphML generation functions

### Modifying PCAP Collector

When editing `cmd/ebpf-monitor/pcap.go`:

1. **Adding protocol support**:
   - Update `processPacket()` to handle new transport layers
   - Add new fields to `FlowStats` struct if needed
   - Update JSON output format

2. **Tuning aggregation**:
   - Adjust `flow_timeout` in config for faster/slower flushing
   - Modify `flushFlows()` logic to change flush behavior
   - Consider memory usage vs. accuracy tradeoff

3. **DNS parsing**:
   - `processDNS()` currently handles A and AAAA records only
   - Add CNAME, MX, etc. if needed for richer enrichment
   - DNS cache is map[IP]Domain - change if reverse lookup needed

4. **Performance considerations**:
   - Flow map grows unbounded until flush - monitor memory usage
   - RWMutex contention possible under high packet rates
   - Consider sharded maps for very high throughput

5. **BPF filter examples**:
   - `"tcp or udp"` - Default, captures most traffic
   - `"tcp port 443"` - HTTPS only
   - `"not port 22"` - Exclude SSH
   - `"host 192.168.1.100"` - Specific host only

### Go Code Structure

The codebase follows a modular design with three main components:

**`main.go`** (~238 lines):
- Configuration loading and validation
- Elasticsearch connection setup (dual bulk indexers)
- File logging setup
- Signal handling (SIGINT, SIGTERM, SIGHUP)
- Orchestration of eBPF and PCAP collectors

**`ebpf.go`** (~300 lines):
- `EBPFCollector` struct and methods
- eBPF program loading and tracepoint attachment
- Perf buffer event reading and parsing
- AuditEvent struct and helper functions (int8ToStr, parseIPv4, etc.)
- Event enrichment and output (file + Elasticsearch)

**`pcap.go`** (~428 lines):
- `PCAPCollector` struct and methods
- Packet capture using gopacket/libpcap
- Flow aggregation with 5-tuple keys
- DNS parsing and caching
- TCP flag extraction
- Periodic flushing logic

**Important**:
- Both collectors run in separate goroutines
- Each collector has its own `Start()` and `Stop()` methods
- Thread-safe with mutex protection where needed
- Elasticsearch bulk indexers run async with configurable batch size
- All collectors can be independently enabled/disabled via config

## Requirements

### Build Requirements

- Linux kernel 5.8+ (BTF support required)
- Go 1.22+
- clang, llvm (for eBPF compilation via bpf2go)
- make

### Runtime Requirements

- Root privileges (CAP_BPF, CAP_NET_ADMIN for eBPF, CAP_NET_RAW for PCAP)
- BTF-enabled kernel (check: `ls /sys/kernel/btf/vmlinux`)
- libpcap (for packet capture): `sudo apt install libpcap-dev`
- Python 3.8+ (web interface)
- Elasticsearch 9.x (optional, for web interface queries)

### Python Dependencies

From `web/requirements.txt`:
- streamlit (web framework)
- elasticsearch (client)
- networkx (graph analysis)
- pyvis (interactive visualization)
- pydot (DOT format export)

## Deployment

### systemd Services

- `ebpf-monitor.service` - Main eBPF collector (scripts/ebpf-monitor.service)
- `streamlit-webapp.service` - Web interface (scripts/streamlit-webapp.service)

Both services restart on failure and log to systemd journal.

### Package Building

Uses `nfpm` (package: https://nfpm.goreleaser.com/)
- Generates .deb packages
- Runs postinstall/preremove scripts
- Installs to `/usr/bin/ebpf-monitor`
- Config to `/var/config.json` (only if not exists)

## Security Considerations

1. **eBPF verifier**: All eBPF programs must pass kernel verifier - avoid unbounded loops
2. **PID recycling**: Process nodes use `{pid}:{start_time}` to avoid confusion
3. **Malware evasion**: Filtering logic designed to prevent bypass (e.g., smart kworker detection)
4. **Credential exposure**: Never commit Elasticsearch passwords - use environment variables in production
5. **Root access**: Monitor runs as root - minimize attack surface

## Common Issues

### eBPF Program Won't Load

- Check kernel version: `uname -r` (need 5.8+)
- Verify BTF: `ls /sys/kernel/btf/vmlinux`
- Check for verifier errors in journal: `journalctl -u ebpf-monitor`
- Ensure proper includes: headers/vmlinux.h must match kernel

### Web Interface Shows No Events

- Check storage_type in config.json
- For Elasticsearch: verify connectivity (`curl http://localhost:9200`)
- For local: check events_dir contains .jsonl files
- Verify time range in query (events may be outside window)

### High CPU Usage

- Adjust eBPF filtering in `bpf/main.bpf.c` (add more noise filters)
- Tune Elasticsearch batch_size (increase to reduce overhead)
- Consider BEEP parameters (increase threshold to compress more)
- For PCAP: Tighten BPF filter to reduce packet volume
- Increase PCAP `flush_interval` to reduce I/O operations

### PCAP Collector Issues

**"Permission denied" when starting**:
- Ensure running as root or with CAP_NET_RAW capability
- Check interface name in config matches system: `ip link show`

**"No such device" error**:
- Verify network interface exists: `ip addr show`
- Common interfaces: eth0, ens33, wlan0, wlp2s0
- Use `lo` for loopback testing

**High memory usage**:
- Reduce `flow_timeout` to flush flows more aggressively
- Reduce `flush_interval` for more frequent writes
- Tighten BPF filter to capture fewer packets
- Monitor with: `cat /proc/$(pidof ebpf-monitor)/status | grep VmRSS`

**DNS cache not working**:
- Ensure DNS traffic is captured (check BPF filter includes UDP port 53)
- Verify DNS responses are seen: Look for QR=1 in packet logs
- Cache TTL may be too short - increase `dns_cache_ttl`

**Missing flows in output**:
- Check `flow_timeout` - flows may not have reached timeout
- Force flush by sending SIGTERM (graceful shutdown triggers flush)
- Verify Elasticsearch connectivity if using ES storage

## File Generation

The following files are auto-generated and should NOT be edited directly:
- `cmd/ebpf-monitor/bpf_bpf.go` - Generated by `go generate` (bpf2go)
- `cmd/ebpf-monitor/bpf_bpf.o` - Compiled eBPF bytecode
- `build/` - Package build artifacts

Run `make clean` to remove all generated files.
