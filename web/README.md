# Web Application - Streamlit Interface

Multi-page interactive web interface for system and network monitoring, correlation analysis, provenance graphs, and AI-powered security analysis.

## Overview

The Streamlit web application provides a comprehensive forensic analysis platform with real-time monitoring, network-process correlation, offline PCAP analysis, and provenance graph generation.

## Files

### Core Application
- **webapp.py** - Main entry point with navigation and routing
- **utils.py** - Shared utilities (ES connection, queries, hostname aggregation)
- **analyzer.py** - Provenance graph generation with BEEP algorithm
- **requirements.txt** - Python dependencies

### Pages (Multi-Page App)
- **pages/home.py** - Dashboard with system status and metrics
- **pages/ebpf_events.py** - eBPF syscall event viewer
- **pages/pcap_flows.py** - Network flow viewer with DNS enrichment
- **pages/correlation.py** - Network-process correlation (Who made this connection?)
- **pages/provenance.py** - Provenance graph generation and AI analysis
- **pages/offline_analysis.py** - PCAP/audit log correlation for forensics

## Features

### 1. Home Dashboard
- System status (monitoring mode, storage, Elasticsearch connection)
- Multi-host overview (number of monitored hosts)
- 24-hour activity metrics (events, flows, connections, file opens)
- Top syscalls and processes in last hour
- Quick navigation to analysis pages

### 2. eBPF Events Viewer
- Real-time syscall event monitoring
- Time range filtering (1h, 6h, 24h, 7d, custom)
- Hostname, syscall, comm, PID, PPID filters
- Pagination (100-2000 events per page)
- Expandable event cards with detailed info
- JSON export functionality

### 3. PCAP Flows Viewer
- Aggregated network traffic analysis
- Time range and hostname filtering
- Protocol (TCP/UDP), IP, port filters
- DNS enrichment (domain names)
- TCP flag extraction
- Flow statistics (top destinations, top ports)
- JSON export

### 4. Network-Process Correlation
- Matches network flows (PCAP) to processes (eBPF)
- Answers: "Who made this connection?"
- Time-based correlation with configurable window (1-30 seconds)
- PID reuse protection using process_start_time
- Confidence scoring (High/Medium/Low based on time delta)
- Hostname filtering for multi-host deployments
- Sankey diagram visualization
- Ghost flow detection (unidentified traffic)

### 5. Provenance Graph Analysis
- Target selection (by process name or PID)
- Advanced filtering options (disable filters, prune high-degree files)
- BEEP edge grouping algorithm for noise reduction
- Interactive PyVis graph visualization
- PNG export
- AI-powered analysis with Ollama integration
- Chat interface for discussing results

### 6. Offline PCAP/Audit Analysis
- Four-tab interface for forensic investigations
- PCAP file upload (.pcap, .pcapng) with tshark parsing
- Audit log upload (JSON: auditbeat/auditd)
- Time-based correlation with multiple methods
- Process attribution for network flows
- Interactive visualizations (timeline, top processes, protocols)
- AI-powered anomaly detection

## Dependencies

From `requirements.txt`:

```
streamlit==1.51.0       # Web framework
elasticsearch==9.2.0    # ES client
networkx==3.1           # Graph analysis
pydot==4.0.1            # DOT format support
pyvis==0.3.1            # Interactive graph visualization
plotly==5.18.0          # Charts and visualizations
pandas==2.1.4           # Data analysis
```

## Architecture

```
User Browser
      |
      v
+-------------------+
| Streamlit UI      |
| - Event filters   |
| - Graph controls  |
+-------------------+
      |
      v
+-------------------+
| Query Engine      |
| - ES queries      |
| - Time windows    |
+-------------------+
      |
      v
+-------------------+
| Analyzer          |
| - Graph building  |
| - Noise filtering |
| - Coloring        |
+-------------------+
      |
      v
+-------------------+
| Visualization     |
| - PyVis (HTML)    |
| - DOT export      |
| - GraphML export  |
+-------------------+
      |
      v (optional)
+-------------------+
| Ollama Agent      |
| - AI analysis     |
+-------------------+
```

## Installation

### Automatic (Recommended)

```bash
cd ../scripts
sudo ./streamlit-setup.sh
```

This will:
- Install Python 3.12
- Create virtual environment
- Install dependencies
- Configure systemd service
- Set up environment variables

## Usage

### Starting the Application

**As a Service:**
```bash
sudo systemctl start streamlit-webapp
sudo systemctl status streamlit-webapp
```

**Manually:**
```bash
source venv/bin/activate
streamlit run webapp.py --server.port=8501 --server.address=0.0.0.0
```

Access at: `http://localhost:8501`

### Using the Interface

#### Event Search Tab

1. **Set Time Range**
   - Select relative time (last 1h, 6h, 24h) or custom range
   - Click "Search Events"

2. **Apply Filters**
   - Filter by syscall: `execve`, `openat`, `connect`, etc.
   - Filter by process: Enter exact process name
   - Filter by PID or PPID

3. **View Results**
   - Scroll through paginated events
   - View event details (timestamp, process, file, network, etc.)
   - Export results (copy JSON)

#### Provenance Graph Tab

1. **Select Target**
   - By PID: Analyze specific process
   - By Process Name: Find and analyze by comm
   - By Time Window: Analyze recent activity

2. **Choose Output Format**
   - **Interactive**: Zoomable HTML visualization
   - **DOT**: Graphviz format (for external tools)
   - **GraphML**: NetworkX XML format (for Gephi, etc.)

3. **Generate Graph**
   - Click "Generate Graph"
   - Wait for processing
   - View/download results

4. **Interpret Colors**
   - **Blue (#40A8D1)**: Suspicious processes
   - **Gray (#888888)**: Benign processes
   - **Red (#D14040)**: Sensitive files
   - **Orange (#D18C40)**: Downloads/temp files
   - **Pink (#FF69B4)**: Network connections
   - **Light Gray**: Normal files

#### AI Analysis Tab (if Ollama enabled)

1. **Generate Graph First**
   - Create provenance graph in DOT format

2. **Upload for Analysis**
   - Select graph file
   - Click "Analyze with Ollama"

3. **Review Results**
   - Read natural language threat assessment
   - Follow security recommendations

## Analyzer: Context-Aware Filtering

The analyzer implements intelligent noise reduction while preserving security-relevant events.

### Noise Categories

Events are categorized and filtered based on context:

**Authentication** (low sensitivity)
- Processes: `sshd`, `login`, `su`
- Files: `.ssh/*`, `shadow`, `passwd`
- Preserves anomalous auth activity

**System Logging** (low sensitivity)
- Processes: `systemd-journald`, `rsyslog`
- Files: `/var/log/*`
- Filters routine log operations

**Package Management** (low sensitivity)
- Processes: `dpkg`, `apt`, `yum`
- Files: `/var/lib/dpkg/*`, `/var/cache/apt/*`

**Shared Libraries** (medium sensitivity)
- Files: `/usr/lib/*.so`, `/lib/*.so`
- Filters routine library loads
- Preserves unusual library usage

**Kernel Pseudo-FS** (low sensitivity)
- Files: `/proc/*`, `/sys/*`, `/dev/null`
- Always filtered (high noise, low value)

**Terminal/Pager** (low sensitivity)
- Processes: `less`, `more`
- Files: `.less*`

### Filtering Logic

```python
def should_filter_event(event, category_filters):
    """
    Multi-factor filtering decision:
    1. Match against noise categories
    2. Check burst patterns (repeated ops)
    3. Consider syscall type
    4. Evaluate sensitivity level
    """
    # Check category match
    category = match_noise_category(event)
    if category:
        # Apply burst detection
        if is_burst_event(event):
            return True
        # Consider sensitivity
        if category['sensitivity'] == 'low':
            return True
    return False
```

### Graph Coloring

Nodes are colored based on security relevance:

```python
def assign_node_color(node, node_type):
    if node_type == 'process':
        if is_suspicious(node):
            return '#40A8D1'  # Blue
        else:
            return '#AAAAAA'  # Gray
    elif node_type == 'file':
        if is_sensitive_path(node):
            return '#D14040'  # Red
        elif is_download_temp(node):
            return '#D18C40'  # Orange
        else:
            return '#CCCCCC'  # Light Gray
    elif node_type == 'network':
        return '#FF69B4'  # Pink
```

## Configuration

### Elasticsearch Connection

Configured via `/var/config.json`:

```json
{
  "events_dir": "/var/monitoring/events/",
  "output_dir": "/var/monitoring/outputs/",
  "storage_type": "elasticsearch",
  "es_config": {
    "es_host": "localhost",
    "es_port": 9200,
    "es_user": "elastic",
    "es_password": "changeme",
    "es_index": "ebpf-events",
    "batch_size": 500,
    "secure": true
  }
}
```