# Installation and Setup Scripts

Collection of scripts for installing, configuring, testing, and managing the eBPF Provenance Monitor system.

## Overview

These scripts automate the installation and configuration of all system components, including dependencies, services, and forensic testing tools. Scripts are organized into subdirectories by function.

## Directory Structure

```
scripts/
├── system-setup/              # Installation and configuration scripts
│   ├── build-setup.sh         # Build dependencies (Go, Clang, LLVM)
│   ├── es-setup.sh            # Elasticsearch installation
│   ├── ollama-setup.sh        # Ollama AI installation
│   ├── streamlit-setup.sh     # Web application setup
│   └── logrotate-setup.sh     # Log rotation configuration
│
├── event-generation/          # Forensic testing and data generation
│   ├── generate_activity.sh         # Realistic system activity
│   ├── generate_attack_scenario.sh  # Attack simulation (5 phases)
│   ├── generate_forensic_activity.sh # Activity with service capture
│   └── capture_forensics.sh         # PCAP + audit log capture
│
├── system-monitor.service     # Systemd service file
├── system-provenance-logrotate # Logrotate configuration
├── postinstall.sh             # Post-installation tasks (.deb)
└── preremove.sh               # Pre-removal tasks (.deb)
```

---

## System Setup Scripts

Located in `system-setup/` directory.

### build-setup.sh

Installs all build dependencies for compiling the system-monitor binary.

**Location:** `system-setup/build-setup.sh`

**Usage:**
```bash
cd scripts/system-setup
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
- libpcap-dev (for packet capture)

**When to use:**
- Before first build from source
- Setting up development environment
- After kernel upgrade (to install matching headers)

**Example workflow:**
```bash
cd scripts/system-setup
sudo ./build-setup.sh

# Then build the project
cd ../..
make generate
make build
```

### streamlit-setup.sh

Installs and configures the Streamlit web application.

**Location:** `system-setup/streamlit-setup.sh`

**Usage:**
```bash
cd scripts/system-setup
sudo ./streamlit-setup.sh
```

**What it does:**
1. Checks for Python 3.12 (installs if missing via deadsnakes PPA)
2. Creates Python virtual environment in `../../web/venv`
3. Installs Python dependencies from `requirements.txt`
4. Creates monitoring directories:
   - `/var/monitoring/events`
   - `/var/monitoring/outputs`
5. Copies default config to `/var/monitoring/config.json` (if not exists)
6. Installs logrotate configuration

**Note:** This script does NOT install a systemd service. The web application is designed to be run manually or via user-specific service configuration.

**Starting the web app:**
```bash
cd web
source venv/bin/activate
streamlit run webapp.py --server.port=8501 --server.address=0.0.0.0
```

### es-setup.sh

Installs and configures Elasticsearch 9.x.

**Location:** `system-setup/es-setup.sh`

**Usage:**
```bash
cd scripts/system-setup
sudo ./es-setup.sh
```

**What it does:**
1. Adds Elasticsearch GPG key and repository
2. Installs Elasticsearch 9.x
3. Configures for local access
4. Enables and starts service
5. Displays initial elastic password
6. Tests connection

**Post-installation:**
```bash
# Update config with Elasticsearch credentials
sudo nano /var/monitoring/config.json

# Update es_config section:
#   "es_host": "localhost",
#   "es_port": 9200,
#   "es_user": "elastic",
#   "es_password": "<password_from_setup>"
```

### ollama-setup.sh

Installs Ollama for AI-powered analysis.

**Location:** `system-setup/ollama-setup.sh`

**Usage:**
```bash
cd scripts/system-setup
sudo ./ollama-setup.sh
```

**What it does:**
1. Downloads and installs Ollama
2. Starts Ollama service
3. Provides instructions for pulling models

**Post-installation:**
```bash
# Pull a model (choose one)
ollama pull llama3        # General purpose (4.7GB)
ollama pull mistral       # Alternative (4.1GB)
ollama pull llama3.2      # Newer version (3.2GB)
```

**Using with web app:**
- AI analysis tab will automatically detect Ollama at `http://localhost:11434`
- Upload provenance graphs for automated threat analysis
- Models run locally (no data sent externally)

### logrotate-setup.sh

Installs logrotate configuration for automated log management.

**Location:** `system-setup/logrotate-setup.sh`

**Usage:**
```bash
cd scripts/system-setup
sudo ./logrotate-setup.sh
```

**What it installs:**
- Copies `../system-provenance-logrotate` to `/etc/logrotate.d/system-provenance`
- Configures rotation for:
  - `/var/monitoring/events/*.jsonl`
  - `/var/monitoring/outputs/*.log`

**Configuration:**
- Daily rotation
- Keep 30 days
- Compress old logs
- Send SIGHUP to system-monitor on rotation

---

## Event Generation Scripts

Located in `event-generation/` directory. These scripts generate realistic system activity and capture forensic data for testing.

### generate_activity.sh

Generates realistic system activity patterns for testing.

**Location:** `event-generation/generate_activity.sh`

**Usage:**
```bash
cd scripts/event-generation
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

**Output:** Generates activity that can be captured by monitoring tools

**Use cases:**
- Testing eBPF event capture
- Testing PCAP flow aggregation
- Validating correlation logic
- Training ML models
- Demonstrating detection capabilities

### generate_attack_scenario.sh

Simulates a realistic 5-phase attack scenario for testing detection and forensic analysis.

**Location:** `event-generation/generate_attack_scenario.sh`

**Usage:**
```bash
cd scripts/event-generation
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

**Location:** `event-generation/generate_forensic_activity.sh`

**Usage:**
```bash
cd scripts/event-generation
sudo ./generate_forensic_activity.sh [duration_in_seconds]

# Example: Generate activity for 60 seconds
sudo ./generate_forensic_activity.sh 60
```

**Prerequisites:**
- system-monitor service must be running
- Service automatically captures eBPF events and PCAP flows

**What it does:**
1. Checks if system-monitor service is active
2. Runs `generate_activity.sh` for specified duration
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

**Location:** `event-generation/capture_forensics.sh`

**Usage:**
```bash
cd scripts/event-generation
sudo ./capture_forensics.sh [duration_in_seconds]

# Example: Capture for 60 seconds
sudo ./capture_forensics.sh 60
```

**Prerequisites:**
- Root privileges (for tcpdump and auditd)
- tcpdump installed
- auditd or strace installed (for syscall monitoring)
- `generate_activity.sh` in same directory

**What it does:**
1. Starts PCAP capture on default network interface
2. Configures auditd rules for network syscalls (connect, bind, socket, etc.)
3. Runs `generate_activity.sh`
4. Collects audit logs from auditd
5. Converts audit logs to JSON format

**Output files:**
- `./forensic_captures/capture_TIMESTAMP.pcap`
- `./forensic_captures/audit_TIMESTAMP.log` (raw)
- `./forensic_captures/audit_TIMESTAMP.json` (JSON format)

**Audit syscalls monitored:**
- Network: connect, bind, socket, sendto, recvfrom, accept, accept4
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

---

## Service Files

### system-monitor.service

Systemd service file for the system-monitor daemon.

**Location:** `system-monitor.service`

**Installation:**
```bash
sudo cp scripts/system-monitor.service /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable system-monitor
sudo systemctl start system-monitor
```

**Service configuration:**
```ini
[Unit]
Description=System Provenance Monitor (eBPF + PCAP)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/system-monitor
Restart=always
RestartSec=5s
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

**Management:**
```bash
# Start/stop service
sudo systemctl start system-monitor
sudo systemctl stop system-monitor
sudo systemctl restart system-monitor

# View status
sudo systemctl status system-monitor

# View logs
sudo journalctl -u system-monitor -f

# Trigger log rotation
sudo systemctl kill -s HUP system-monitor
```

### system-provenance-logrotate

Logrotate configuration for automatic log management.

**Location:** `system-provenance-logrotate`

**Installed to:** `/etc/logrotate.d/system-provenance`

**What it manages:**
- eBPF events: `/var/monitoring/events/ebpf-events.jsonl`
- PCAP flows: `/var/monitoring/events/pcap-flows.jsonl`
- Output files: `/var/monitoring/outputs/*.log`

**Configuration:**
```
/var/monitoring/events/*.jsonl {
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
        if systemctl is-active --quiet system-monitor.service; then
            systemctl kill -s HUP system-monitor.service
        fi
    endscript
}
```

---

## Package Management Scripts

### postinstall.sh

Runs after .deb package installation.

**Location:** `postinstall.sh`

**Actions:**
- Reload systemd daemon
- Enable system-monitor service
- Display installation summary

**When executed:** Called by nfpm during package installation

### preremove.sh

Runs before .deb package removal.

**Location:** `preremove.sh`

**Actions:**
- Stop system-monitor service
- Disable service
- Clean up (but preserve config)

**When executed:** Called by nfpm during package removal

---

## Workflow Examples

### Example 1: Fresh Installation

```bash
# Step 1: Install build dependencies
cd scripts/system-setup
sudo ./build-setup.sh

# Step 2: Build the project
cd ../..
make generate
make build

# Step 3: Install the binary
sudo cp system-monitor /usr/bin/
sudo chmod +x /usr/bin/system-monitor

# Step 4: Set up configuration
sudo mkdir -p /var/monitoring/events /var/monitoring/outputs
sudo cp config/config.json /var/monitoring/config.json
sudo nano /var/monitoring/config.json  # Edit as needed

# Step 5: Install service
cd scripts
sudo cp system-monitor.service /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable system-monitor
sudo systemctl start system-monitor

# Step 6: Set up web interface
cd system-setup
sudo ./streamlit-setup.sh

# Step 7: (Optional) Install Elasticsearch
sudo ./es-setup.sh

# Step 8: (Optional) Install Ollama for AI analysis
sudo ./ollama-setup.sh
ollama pull llama3
```

### Example 2: Testing Network-Process Correlation

```bash
# Start monitoring service
sudo systemctl start system-monitor

# Generate forensic activity
cd scripts/event-generation
sudo ./generate_forensic_activity.sh 60

# View results in web interface
# Navigate to: http://localhost:8501
# - View "eBPF Events" page
# - View "PCAP Flows" page
# - View "Correlation" page to see matched flows
```

### Example 3: Offline Forensic Analysis

```bash
# Capture forensic data (doesn't require service)
cd scripts/event-generation
sudo ./capture_forensics.sh 120

# Files created in ./forensic_captures/
# - capture_TIMESTAMP.pcap
# - audit_TIMESTAMP.json

# Upload to web interface
# Navigate to: http://localhost:8501
# - Go to "Offline Analysis" page
# - Upload PCAP file
# - Upload audit JSON file
# - Run correlation and view visualizations
```

### Example 4: Attack Simulation Testing

```bash
# Start monitoring
sudo systemctl start system-monitor

# Run attack scenario
cd scripts/event-generation
sudo ./generate_attack_scenario.sh 45

# Wait for events to flush
sleep 5

# Analyze in web interface
# - View attack phases in "eBPF Events" page
# - Check network exfiltration in "PCAP Flows" page
# - Generate provenance graph of attacker process
# - Run AI analysis to identify attack patterns
```

---

## Troubleshooting

### Script Permissions

If you get "Permission denied" errors:
```bash
chmod +x scripts/system-setup/*.sh
chmod +x scripts/event-generation/*.sh
```

### Missing Dependencies

**For capture_forensics.sh:**
```bash
# Install tcpdump
sudo apt-get install tcpdump

# Install auditd (preferred)
sudo apt-get install auditd

# OR install strace (fallback)
sudo apt-get install strace
```

**For event generation:**
```bash
# Install network tools
sudo apt-get install curl dnsutils netcat-openbsd
```

### Service Issues

**system-monitor won't start:**
```bash
# Check logs
sudo journalctl -u system-monitor -n 50

# Check config
sudo cat /var/monitoring/config.json

# Check binary exists
ls -la /usr/bin/system-monitor

# Check permissions
sudo chmod +x /usr/bin/system-monitor
```

**Logrotate not working:**
```bash
# Test logrotate
sudo logrotate -f /etc/logrotate.d/system-provenance

# Check if config installed
ls -la /etc/logrotate.d/system-provenance
```

---

## Notes

- All setup scripts should be run with `sudo` for proper installation
- Event generation scripts can run without `sudo` (except capture scripts which need root for PCAP)
- The web application does NOT require a systemd service and runs in user space
- Captured forensic data is stored in `./forensic_captures/` relative to script location
- System-monitor service logs to `/var/monitoring/events/` by default
