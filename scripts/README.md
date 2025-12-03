# Installation and Setup Scripts

Collection of scripts for installing, configuring, and managing the eBPF Provenance Monitor system.

## Overview

These scripts automate the installation and configuration of all system components, including dependencies, services, and auxiliary tools.

## Files

### Setup Scripts

- **build-setup.sh** - Install build dependencies (Go, Clang, LLVM, headers)
- **streamlit-setup.sh** - Install and configure web application
- **es-setup.sh** - Install and configure Elasticsearch
- **ollama-setup.sh** - Install Ollama for AI analysis

### Service Files

- **ebpf-monitor.service** - Systemd service for eBPF monitor
- **streamlit-webapp.service** - Systemd service for web application
- **streamlit-webapp.env** - Environment template for web service

### Maintenance

- **ebpf-provenance-logrotate** - Logrotate configuration
- **postinstall.sh** - Post-installation tasks (for .deb package)
- **preremove.sh** - Pre-removal tasks (for .deb package)
- **logrotate-setup.sh** - Install logrotate configuration

### Forensic Testing & Data Generation

- **generate_activity.sh** - Generate realistic system activity for testing
- **generate_attack_scenario.sh** - Simulate attack patterns (reconnaissance, exfiltration, etc.)
- **generate_forensic_activity.sh** - Generate activity while system-monitor service captures
- **capture_forensics.sh** - Capture PCAP + audit logs with activity generation
- **capture_with_ebpf.sh** - Capture PCAP + eBPF events (better than auditd for network correlation)
- **convert_audit_to_json.py** - Convert ausearch output to JSON for offline analysis

## Setup Scripts Usage

### build-setup.sh

Installs all build dependencies for compiling the eBPF monitor.

**Usage:**
```bash
sudo ./build-setup.sh
```

**What it installs:**
- Go 1.25+
- Clang 10+
- LLVM 10+
- libbpf-dev
- Linux headers for current kernel
- bpftool
- make and build essentials

**When to use:**
- Before first build from source
- Setting up development environment
- After kernel upgrade (to install matching headers)

**Example:**
```bash
cd scripts
sudo ./build-setup.sh

# Then build the project
cd ..
make generate
make build
```

### streamlit-setup.sh

Installs and configures the Streamlit web application.

**Usage:**
```bash
sudo ./streamlit-setup.sh
```

**What it does:**
1. Checks for Python 3.12 (installs if missing via deadsnakes PPA)
2. Creates Python virtual environment in `web/venv`
3. Installs Python dependencies from `web/requirements.txt`
4. Creates monitoring directories (`/var/monitoring/events`, `/var/monitoring/outputs`)
5. Copies default config to `/var/config.json` (if not exists)
6. Sets up systemd service for web app
7. Creates environment file at `/etc/default/streamlit-webapp`
8. Installs logrotate configuration

**Environment Configuration:**

The script automatically creates `/etc/default/streamlit-webapp`:
```bash
PROJECT_ROOT=/path/to/ebpf-provenance
```

**Service management:**
```bash
sudo systemctl start streamlit-webapp
sudo systemctl enable streamlit-webapp
sudo systemctl status streamlit-webapp
```

### es-setup.sh

Installs and configures Elasticsearch.

**Usage:**
```bash
sudo ./es-setup.sh
```

**What it does:**
1. Adds Elasticsearch GPG key and repository
2. Installs Elasticsearch 9.x
3. Configures for local access
4. Enables and starts service
5. Displays initial elastic password
6. Tests connection

### ollama-setup.sh

Installs Ollama for AI-powered analysis.

**Usage:**
```bash
sudo ./ollama-setup.sh
```

**What it does:**
1. Downloads and installs Ollama
2. Starts Ollama service
3. Instructions for pulling models

**Post-installation:**
```bash
# Pull a model (choose one)
ollama pull llama3        # General purpose (4.7GB)
```

**Using with web app:**
- AI analysis tab will automatically detect Ollama
- Upload graph files for automated threat analysis
- Models run locally (no data sent externally)

## Service Files

### ebpf-monitor.service

Systemd service for the eBPF monitor.

**Location:** `/lib/systemd/system/ebpf-monitor.service`

**Content:**
```ini
[Unit]
Description=eBPF System Call Monitor
After=network.target auditd.service

[Service]
Type=simple
ExecStart=/usr/bin/ebpf-monitor
Restart=always
RestartSec=5s
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

**Management:**
```bash
sudo systemctl start ebpf-monitor
sudo systemctl stop ebpf-monitor
sudo systemctl restart ebpf-monitor
sudo systemctl status ebpf-monitor
sudo systemctl enable ebpf-monitor   # Start on boot
sudo systemctl disable ebpf-monitor  # Don't start on boot
```

**Logs:**
```bash
# Follow live logs
sudo journalctl -u ebpf-monitor -f

# View last 100 lines
sudo journalctl -u ebpf-monitor -n 100

# View logs since boot
sudo journalctl -u ebpf-monitor -b
```

### streamlit-webapp.service

Systemd service for the web application.

**Location:** `/lib/systemd/system/streamlit-webapp.service`

**Content:**
```ini
[Unit]
Description=Streamlit eBPF Forensic Web Application
After=network.target elasticsearch.service

[Service]
Type=simple
EnvironmentFile=-/etc/default/streamlit-webapp
WorkingDirectory=${PROJECT_ROOT}/web
ExecStart=${PROJECT_ROOT}/web/venv/bin/python -m streamlit run webapp.py --server.port=8501 --server.address=0.0.0.0
Restart=always
RestartSec=5s
User=root
Group=root
Environment="PATH=${PROJECT_ROOT}/web/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
```

**Key features:**
- Uses `${PROJECT_ROOT}` from environment file
- Runs from virtual environment
- Auto-restarts on failure
- Waits for Elasticsearch (if installed)

**Environment file:** `/etc/default/streamlit-webapp`
```bash
PROJECT_ROOT=/path/to/your/ebpf-provenance
```

### streamlit-webapp.env

Template for the environment file.

## Log Rotation

### ebpf-provenance-logrotate

Logrotate configuration for automatic log management.

**Location:** `/etc/logrotate.d/ebpf-provenance`

**What it manages:**
1. eBPF monitor events (`/var/monitoring/events/events.jsonl`)
2. Output files (`/var/monitoring/outputs/*.log`)
3. Streamlit logs (`/var/log/streamlit-webapp/*.log`)

**Configuration:**
```
/var/monitoring/events/events.jsonl {
    daily                    # Rotate daily
    rotate 30                # Keep 30 days
    compress                 # Compress old logs
    delaycompress            # Don't compress most recent
    missingok                # Don't error if missing
    notifempty               # Don't rotate empty logs
    create 0644 root root    # Create new file with permissions
    dateext                  # Add date to filename
    dateformat -%Y%m%d       # Date format
    postrotate
        # Send SIGHUP to reopen log file
        if systemctl is-active --quiet ebpf-monitor.service; then
            systemctl kill -s HUP ebpf-monitor.service
        fi
    endscript
}
```

## Package Scripts

### postinstall.sh

Runs after .deb package installation.

**Actions:**
- Reload systemd daemon
- Enable ebpf-monitor service
- Display installation summary

**Location:** Called by nfpm during package installation

### preremove.sh

Runs before .deb package removal.

**Actions:**
- Stop ebpf-monitor service
- Disable service
- Clean up (but preserve config)

**Location:** Called by nfpm during package removal

## Forensic Testing & Data Generation Scripts

These scripts generate realistic system activity and capture forensic data for testing the offline analysis features.

### generate_activity.sh

Generates realistic system activity patterns for testing.

**Usage:**
```bash
./generate_activity.sh [duration_in_seconds]

# Example: Generate 60 seconds of activity
./generate_activity.sh 60
```

**What it generates:**
1. **File I/O Operations:**
   - Create, read, write, delete operations
   - Various file types (JSON, XML, binary)
   - Copy and move operations

2. **Network Activity:**
   - DNS lookups (google.com, github.com, amazon.com, etc.)
   - HTTPS requests to legitimate sites
   - API calls (POST/GET)
   - HTTP requests

3. **Process Operations:**
   - Standard system commands (whoami, hostname, uname, etc.)
   - Process listing (ps, top)
   - Child process spawning (fork/exec)

4. **System Monitoring:**
   - Disk usage checks
   - Memory information
   - Network interface stats
   - Connection listing

5. **Suspicious Activity (for detection testing):**
   - Reconnaissance (port scanning, network enumeration)
   - Lateral movement simulation (SSH attempts)
   - Persistence simulation (cron enumeration, service listing)
   - Credential access (shadow file reads, SSH key enumeration)
   - Data exfiltration (compression, upload simulation, DNS tunneling)
   - Evasion techniques (hidden files, log deletion)

**Output:** Generates activity captured by monitoring tools

**Use cases:**
- Testing eBPF event capture
- Testing PCAP flow aggregation
- Validating correlation logic
- Training ML models
- Demonstrating detection capabilities

### generate_attack_scenario.sh

Simulates a realistic 5-phase attack scenario for testing detection and forensic analysis.

**Usage:**
```bash
./generate_attack_scenario.sh [duration_in_seconds]

# Example: 45-second attack simulation
./generate_attack_scenario.sh 45
```

**Attack Phases:**

**Phase 1: Reconnaissance (0-15s)**
- System information gathering (uname, whoami, id)
- Network configuration mapping
- Running process enumeration
- Network connection scanning

**Phase 2: Data Collection (15-30s)**
- SSH key enumeration
- Browser data location checking
- Environment variable collection
- Command history extraction
- Data aggregation

**Phase 3: C2 Communication (30-40s)**
- DNS tunneling attempts
- HTTP/HTTPS beacon signals
- Pastebin-like communication

**Phase 4: Data Exfiltration (40-50s)**
- Data compression
- DNS exfiltration simulation
- HTTP upload attempts
- HTTPS exfiltration to suspicious ports

**Phase 5: Persistence & Cleanup (50+s)**
- Cron job creation attempts
- Log tampering attempts
- Artifact deletion

**Expected Anomalies:**
- Unusual port connections
- High volume DNS queries to suspicious domains
- Large HTTP POST requests
- Access to sensitive file locations
- Multiple curl processes from single parent

**Use cases:**
- Testing offline analysis anomaly detection
- Demonstrating attack pattern recognition
- Training security analysts
- Validating SIEM rules
- Incident response practice

### generate_forensic_activity.sh

Generates activity while the system-monitor service is running (requires service to be active).

**Usage:**
```bash
sudo ./generate_forensic_activity.sh [duration_in_seconds]

# Example: Generate activity for 60 seconds
sudo ./generate_forensic_activity.sh 60
```

**Prerequisites:**
- system-monitor service must be running
- Service automatically captures eBPF events and PCAP flows

**What it does:**
1. Checks if system-monitor service is active
2. Runs generate_activity.sh for specified duration
3. Waits for system-monitor to flush events
4. Displays summary of captured data

**Output locations:**
- eBPF events: `/var/monitoring/events/ebpf-events.jsonl`
- PCAP flows: `/var/monitoring/events/pcap-flows.jsonl`

**Analysis options:**
1. **Web Interface (Real-time):** View in eBPF Events or PCAP Flows pages
2. **Offline Analysis:** Upload PCAP file from separate capture
3. **Command Line:** Use `jq` to analyze JSONL files

**Use cases:**
- Testing live monitoring
- Generating real-world datasets
- Performance testing under load
- Demonstrating real-time correlation

### capture_forensics.sh

Captures PCAP and audit logs while generating activity (standalone, doesn't require service).

**Usage:**
```bash
sudo ./capture_forensics.sh [duration_in_seconds]

# Example: Capture for 60 seconds
sudo ./capture_forensics.sh 60
```

**Prerequisites:**
- Root privileges (for tcpdump and auditd)
- tcpdump installed
- auditd or strace installed (for syscall monitoring)
- generate_activity.sh present

**What it does:**
1. Starts PCAP capture on default network interface
2. Configures auditd rules for network syscalls (connect, bind, socket, etc.)
3. Runs generate_activity.sh
4. Collects audit logs from auditd
5. Converts audit logs to JSON format

**Output files:**
- `./forensic_captures/capture_TIMESTAMP.pcap`
- `./forensic_captures/audit_TIMESTAMP.log` (raw)
- `./forensic_captures/audit_TIMESTAMP.json` (JSON format)

**Audit syscalls monitored:**
- Network: connect, bind, socket
- File: openat
- Process: execve

**Fallback behavior:**
- If auditd not available, uses strace as fallback
- If neither available, captures PCAP only

**Use cases:**
- Organizations without eBPF deployment
- Testing offline analysis feature
- Forensic data collection
- Incident response scenarios
- Compliance audits

### capture_with_ebpf.sh

Captures PCAP + eBPF events using the project's system-monitor binary (better than auditd for network correlation).

**Usage:**
```bash
sudo ./capture_with_ebpf.sh [duration_in_seconds]

# Example: Capture for 60 seconds
sudo ./capture_with_ebpf.sh 60
```

**Prerequisites:**
- Root privileges
- system-monitor binary compiled (`make build`)
- tcpdump installed
- generate_activity.sh present

**What it does:**
1. Starts PCAP capture
2. Starts system-monitor in foreground mode
3. Runs generate_activity.sh
4. Stops both captures gracefully
5. Saves eBPF events to JSONL

**Output files:**
- `./forensic_captures/capture_TIMESTAMP.pcap`
- `./forensic_captures/ebpf_events_TIMESTAMP.jsonl`

**Advantages over auditd:**
- Captures network IP addresses and ports in eBPF events
- Better correlation with PCAP flows (same 5-tuple)
- Process start time included (PID reuse protection)
- More detailed network information
- No kernel audit support required

**Use cases:**
- Testing offline analysis with eBPF+PCAP
- Generating correlated datasets
- Network-process attribution testing
- Demonstrating correlation accuracy

### convert_audit_to_json.py

Python utility to convert ausearch interpreted output to JSON format compatible with offline analysis.

**Usage:**
```bash
# First, extract audit logs
sudo ausearch -i --start recent > audit.log

# Convert to JSON
./convert_audit_to_json.py audit.log audit.json
```

**What it does:**
- Parses multi-line ausearch -i output
- Groups related audit records (SYSCALL, SOCKADDR, EXECVE, PATH)
- Extracts network information from SOCKADDR records
- Parses timestamps to ISO format
- Outputs JSONL (one JSON object per line)

**Extracted fields:**
- `timestamp`: ISO 8601 format
- `syscall`: System call name
- `pid`, `ppid`, `uid`: Process identifiers
- `comm`: Process name
- `dst_ip`, `dst_port`: Network destination (from SOCKADDR)
- `filename`: File path (from PATH)

**Use cases:**
- Convert existing audit logs for offline analysis
- Process historical audit data
- Import audit data into visualization tools
- Integrate with SIEM platforms

**Example pipeline:**
```bash
# Capture audit events
sudo ausearch -i --start "12/01/25 10:00:00" --end "12/01/25 11:00:00" > audit.log

# Convert to JSON
./convert_audit_to_json.py audit.log audit.json

# Upload audit.json to Offline Analysis page in web interface
```

## Workflow Examples

### Example 1: Testing Network-Process Correlation

```bash
# Step 1: Capture with eBPF
sudo ./capture_with_ebpf.sh 60

# Step 2: Upload files to web interface
# - Navigate to "Correlation" page
# - Select time range matching capture
# - Observe correlated flows
```

### Example 2: Offline Forensic Analysis

```bash
# Step 1: Capture forensic data
sudo ./capture_forensics.sh 120

# Step 2: Upload to Offline Analysis
# - Open web interface
# - Navigate to "Offline Analysis"
# - Upload PCAP file
# - Upload audit JSON file
# - Run correlation and view visualizations
```

### Example 3: Attack Simulation Testing

```bash
# Step 1: Start monitoring service
sudo systemctl start system-monitor

# Step 2: Run attack scenario
sudo ./generate_forensic_activity.sh 60
# OR for attack patterns:
sudo ./generate_attack_scenario.sh 45

# Step 3: Analyze in web interface
# - View eBPF Events page
# - View PCAP Flows page
# - Generate Provenance Graph
# - Run AI Analysis
```