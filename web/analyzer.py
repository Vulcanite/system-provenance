#!/usr/bin/env python3

import re
import os
import sys
import json
import argparse
import traceback
import networkx as nx
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from collections import defaultdict, Counter

TIME_WINDOW_MS = 2000

NOISE_CATEGORIES = {
    'authentication': {
        'processes': [r'^sshd$', r'^login$', r'^su$'],
        'files': [
            r'.*/\.ssh/.*',
            r'.*ssh_host_.*',
            r'.*\.user$',
            r'.*/pam\.d/.*',
            r'.*/shadow.*',
            r'.*/passwd$',
        ],
        'syscalls': ['connect'],
        'sensitivity': 'low',
    },

    'system_logging': {
        'processes': [r'^systemd-journal.*', r'^rsyslog.*', r'^auditd.*'],
        'files': [
            r'^/var/log/.*',
            r'.*\.journal$',
            r'.*/machine-id$',
            r'^/run/log/.*',
        ],
        'syscalls': ['openat', 'read', 'write'],
        'sensitivity': 'low',
    },

    'package_management': {
        'processes': [r'^dpkg.*', r'^apt.*', r'^yum.*', r'^dnf.*'],
        'files': [
            r'^/var/lib/dpkg/.*',
            r'^/var/cache/apt/.*',
            r'^/var/lib/apt/.*',
        ],
        'sensitivity': 'low',
    },

    'shared_libraries': {
        'files': [
            r'^(/usr/lib|/lib|/usr/lib64|/lib64).*\.so(\.\d+)*$',
            r'^/etc/ld\.so\.cache$',
        ],
        'syscalls': ['openat', 'read'],
        'sensitivity': 'medium',
    },

    'locale_fonts': {
        'files': [
            r'^/usr/share/(locale|icons|themes|fonts)/.*',
            r'^/usr/lib.*/locale/.*',
            r'.*\.mo$',
        ],
        'sensitivity': 'low',
    },

    'temp_build_artifacts': {
        'files': [
            r'/tmp/cc.*\.(s|o|res|ld|le)$',
            r'.*\.(o|a)$',
            r'.*\.gch$',
        ],
        'sensitivity': 'low',
    },

    'kernel_pseudo_fs': {
        'files': [
            r'^/proc/.*',
            r'^/sys/.*',
            r'^/dev/(null|zero|random|urandom|pts/.*)$',
        ],
        'sensitivity': 'low',
    },

    'terminal_pager': {
        'processes': [r'^less$', r'^more$', r'^pager$'],
        'files': [
            r'.*/\.less.*',
            r'.*lesskey$',
        ],
        'sensitivity': 'low',
    },

    'desktop_environment': {
        'processes': [r'^gnome-.*', r'^kde-.*', r'^update-.*'],
        'files': [
            r'.*\.desktop$',
            r'^/tmp/\.X11-unix/.*',
            r'^/run/user/.*',
        ],
        'sensitivity': 'low',
    },

    'system_utilities': {
        'processes': [r'^systemctl$', r'^basename$', r'^sed$', r'^service$', r'^apport$'],
        'sensitivity': 'medium',
    },
}

# Sensitivity levels for attack context
SENSITIVITY_LEVELS = {
    'low': {
        'filter_reads': True,
        'filter_writes': False,
        'filter_executions': False,
        'filter_spawns': False,
    },
    'medium': {
        'filter_reads': True,
        'filter_writes': False,
        'filter_executions': False,
        'filter_spawns': False,
    },
    'high': {
        'filter_reads': False,
        'filter_writes': False,
        'filter_executions': False,
        'filter_spawns': False,
    },
}

# Known benign processes (minimal set)
BENIGN_PROCESS_PATTERNS = [
    r'^systemd.*',
    r'^dbus.*',
    r'^kworker.*',
    r'^rcu_.*',
    r'^migration.*',
    r'^ksoftirqd.*',
    r'^watchdog.*',
    r'^cpuhp_.*',
    r'^kdevtmpfs.*',
    r'^netns.*',
    r'^kthreadd.*',
    r'^irq/.*',
]

# Sensitive paths that should NEVER be filtered
SENSITIVE_FILE_PATTERNS = [
    r'/etc/shadow',
    r'/etc/sudoers',
    r'.*/\.ssh/.*',
    r'.*/\.aws/.*',
    r'.*/\.env$',
    r'/root/.*',
    r'.*/secrets?.*',
    r'.*/credentials?.*',
    r'/home/attacker/.*',  # Preserve all attack-related files
]

# HOLMES-specific: Files that trigger alerts
HOLMES_ALERT_PATTERNS = [
    r'.*/secret/.*',
    r'.*/attacker/.*',
    r'.*/\.ssh/.*',
    r'.*/\.aws/.*',
]

BENIGN_PROCS = [
    r'^systemd.*',
    r'^dbus.*',
    r'^journald.*',
    r'^rsyslog.*',
    r'^cron.*',
    # r'^bash$',    <-- REMOVE THIS
    # r'^sh$',      <-- REMOVE THIS
    r'^apt.*',
    r'^dpkg.*',
    # r'^python.*', <-- REMOVE THIS
    r'^gjs$',  # GNOME JavaScript - benign desktop process (loads many theme/icon files)
    r'^fprintd$',
    # r'^node.*',   <-- REMOVE THIS
]

def is_quiet_benign(comm):
    for p in BENIGN_PROCS:
        if re.match(p, comm):
            return True
    return False

HOLMES_TTPS = {
    "UNTRUSTED_EXEC": {
        "name": "Untrusted Code Execution",
        "stage": "Initial Compromise",
        "severity": 3,
        "description": "Execution of binaries/scripts from untrusted locations such as /tmp or user downloads."
    },
    "SENSITIVE_READ": {
        "name": "Sensitive File Read",
        "stage": "Complete Mission",
        "severity": 3,
        "description": "Process reads files that look sensitive (credentials, secrets, keys, etc.)."
    },
    "PRIV_ESC_WRITE": {
        "name": "Privilege-Escalation Write",
        "stage": "Privilege Escalation",
        "severity": 4,
        "description": "Process writes to critical auth/identity/boot files (sudoers, pam, cron, etc.)."
    },
    "C2_COMMUNICATION": {
        "name": "Outbound C2/Command Channel",
        "stage": "Establish Foothold",
        "severity": 2,
        "description": "Suspicious outbound network connection to non-local address."
    },
    "DATA_EXFIL": {
        "name": "Sensitive Data Exfiltration",
        "stage": "Exfiltration",
        "severity": 5,
        "description": "Combination of sensitive reads and outbound communication by the same process."
    },
}

# ============================================================================
# MITRE ATT&CK TECHNIQUE DEFINITIONS (high-level, heuristic)
# ============================================================================

MITRE_TECHNIQUES = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Use of shells or scripting engines (bash, python, powershell, etc.) to execute commands."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Access to sensitive credential stores like /etc/shadow or similar."
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Modifying cron or scheduled task configurations for persistence."
    },
    "T1037": {
        "name": "Boot or Logon Initialization Scripts",
        "tactic": "Persistence",
        "description": "Writing to shell init scripts (e.g., .bashrc) or system init files."
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Sensitive data read followed by outbound network connections, potentially exfiltration."
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Extensive file reads across many locations, indicative of discovery or staging."
    }
}

def canonicalize_filename(name: str) -> str:
    """Canonicalize filenames to detect patterns"""
    if not name:
        return name

    basename = name.split('/')[-1]

    if re.match(r'^program\d+$', basename):
        return "program<NUM>"

    if re.match(r'^tmp\w+$', basename):
        return "tmp<TMP>"

    m = re.match(r'^([A-Za-z_\-]+)\d+$', basename)
    if m:
        return f"{m.group(1)}<NUM>"

    return basename

def beep_key(event):
    """Create grouping key for BEEP compression"""
    filename = event.get("file.path", "")
    canonical = canonicalize_filename(filename)

    return (
        event.get("process.parent.pid"),
        event.get("syscall"),
        canonical
    )

def beep_compress_events(events, time_window_ms=TIME_WINDOW_MS):
    """BEEP event-level compression with multi-burst handling"""
    print(f"[BEEP] Compressing events (window={time_window_ms}ms)...")

    events_sorted = sorted(events, key=lambda e: e.get("timestamp_ms", 0))
    clusters = defaultdict(list)

    for event in events_sorted:
        key = beep_key(event)
        ts = event.get("timestamp_ms", 0)

        if clusters[key]:
            last_burst = clusters[key][-1]

            if ts - last_burst["end"] <= time_window_ms:
                last_burst["end"] = ts
                last_burst["count"] += 1
                last_burst["events"].append(event)
            else:
                clusters[key].append({
                    "start": ts,
                    "end": ts,
                    "count": 1,
                    "events": [event]
                })
        else:
            clusters[key].append({
                "start": ts,
                "end": ts,
                "count": 1,
                "events": [event]
            })

    compressed_events = []

    for key, bursts in clusters.items():
        ppid, syscall, canonical_target = key

        for burst_idx, burst in enumerate(bursts):
            compressed_events.append({
                "ppid": ppid,
                "syscall": syscall,
                "canonical_target": canonical_target,
                "count": burst["count"],
                "start_ts": burst["start"],
                "end_ts": burst["end"],
                "burst_id": burst_idx,
                "events": burst["events"]
            })

    original_count = len(events)
    compressed_count = len(compressed_events)

    if original_count > 0:
        reduction_pct = (1 - compressed_count / original_count) * 100
        print(f"[+] Event compression: {original_count} → {compressed_count} events ({reduction_pct:.1f}% reduction)")

    return compressed_events

def get_base_comm(comm):
    """Extract base command name without path"""
    if comm.startswith('[') and comm.endswith(']'):
        return comm
    base = os.path.basename(comm)
    base = re.split(r'[^a-zA-Z0-9_-]', base)[0]
    return base if base else comm

def is_benign_process(comm):
    """Check if process name matches known benign patterns"""
    for pattern in BENIGN_PROCESS_PATTERNS:
        if re.match(pattern, comm, re.IGNORECASE):
            return True
    return False

def abstract_file_path(filepath):
    if not filepath:
        return filepath

    # Collapse user dirs
    filepath = re.sub(r'/home/[^/]+/', '/home/*/', filepath)

    # Collapse /proc/<pid>
    filepath = re.sub(r'/proc/\d+/', '/proc/*/', filepath)

    # Collapse /tmp/random
    filepath = re.sub(r'/tmp/[A-Za-z0-9._-]+', '/tmp/*', filepath)

    # Collapse /run/user/<uid>
    filepath = re.sub(r'/run/user/\d+/', '/run/user/*/', filepath)

    return filepath

def safe_label(filepath, fallback='unknown_file'):
    """Safely extract label from filepath"""
    if not filepath or not isinstance(filepath, str) or not filepath.strip():
        return fallback

    parts = filepath.rstrip('/').split('/')
    label = parts[-1] if parts else ''
    return label.strip() if label.strip() else fallback

def detect_file_pattern(filenames):
    """Detect common pattern in filenames"""
    if not filenames or len(filenames) < 2:
        return None

    prefix = os.path.commonprefix([str(f) for f in filenames])
    if not prefix:
        return None

    suffixes = []
    for fname in filenames:
        suffix = str(fname)[len(prefix):]
        if suffix.isdigit():
            suffixes.append(int(suffix))

    if len(suffixes) >= 2:
        suffixes.sort()
        if len(suffixes) == (suffixes[-1] - suffixes[0] + 1):
            return f"{prefix}[{suffixes[0]}-{suffixes[-1]}]"
        else:
            return f"{prefix}[×{len(suffixes)}]"

    return None

# ============================================================================
# PROVENANCE GRAPH CLASS
# ============================================================================

FILE_WRITE_SUSPICIOUS = 50        # previously 5
NET_CONNECT_SUSPICIOUS = 10       # previously 3
CHILD_PROC_SUSPICIOUS = 30        # previously 10
UNIQUE_FILE_SUSPICIOUS = 200      # previously 20

class ProvenanceGraph:
    def __init__(self, es_config):
        self.graph = nx.DiGraph()
        self.processes = {}
        self.process_comm = {}
        self.pid_start_time = {}
        self.fd_map = defaultdict(dict)
        self.es = self._connect_es(es_config)
        self.es_index = es_config.get('es_index', 'ebpf-events')

        # Enhanced tracking
        self.file_access_count = Counter()
        self.process_file_bytes = defaultdict(lambda: defaultdict(int))
        self.filtered_events = 0
        self.total_events = 0
        self._path_factor_cache = {}

        # BEEP tracking
        self.beep_clusters = []
        self.event_compression_enabled = True

        # Attack context (generalized)
        self.attack_context = {
            'suspicious_processes': set(),
            'sensitive_files': set(),
            'suspicious_ips': set(),
        }

        # MITRE ATT&CK inference results
        self.mitre_techniques = {}
        self.holmes_hsg = None              # nx.DiGraph of TTP nodes
        self.holmes_hsg_components = []

    def _connect_es(self, es_config):
        es_host = es_config.get("es_host", "localhost")
        es_port = es_config.get("es_port", "9200")
        es_user = es_config.get("es_user", None)
        es_pass = es_config.get("es_password", None)
        is_ssl_enabled = es_config.get("secure", False)

        host = f"http://{es_host}:{es_port}"
        if is_ssl_enabled:
            host = f"https://{es_host}:{es_port}"

        es = Elasticsearch(
            [host],
            basic_auth=(es_user, es_pass),
            verify_certs=False, ssl_show_warn=False,
            request_timeout=30
        )

        if not es.ping():
            raise ConnectionError(f"Failed to connect to ES at {es_host}")

        return es

    def load_events(self, start_ms, end_ms, hostname=None):
        print("Loading events from ES from {} to {}...".format(datetime.fromtimestamp(int(start_ms) / 1000),datetime.fromtimestamp(int(end_ms) / 1000)))
        must_filters = [
            {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}
        ]

        # Hostname filter (if present)
        if hostname:
            must_filters.append({"term": {"host.name.keyword": hostname}})

        query = {
            "size": 5000,
            "query": {
                "bool": {
                    "must": must_filters
                }
            },
            "sort": [{"timestamp_ns": {"order": "asc"}}]
        }

        try:
            response = self.es.search(index=f"{self.es_index}", body=query, scroll='2m')
            sid = response['_scroll_id']
            scroll_size = len(response['hits']['hits'])
            events = [hit['_source'] for hit in response['hits']['hits']]

            while scroll_size > 0:
                response = self.es.scroll(scroll_id=sid, scroll='2m')
                sid = response['_scroll_id']
                scroll_size = len(response['hits']['hits'])
                events.extend([hit['_source'] for hit in response['hits']['hits']])
                if len(events) >= 200000:
                    print("[!] Limit reached (50k events)")
                    break

            self.es.clear_scroll(scroll_id=sid)
            print(f"[+] Loaded {len(events)} total events.")
            return events

        except Exception as e:
            print(f"[!] ES Query Failed: {e}", file=sys.stderr)
            return []

    def detect_attack_indicators(self, events):
        print("Detecting attack indicators...")

        process_stats = defaultdict(lambda: {
            'file_ops': 0,
            'net_connections': 0,
            'child_processes': 0,
            'file_writes': 0,
            'file_deletes': 0,
            'unique_files': set(),
        })

        for event in events:
            # Safely get PID and syscall
            pid = event.get('process.pid')
            if not pid:
                continue
            pid = str(pid)

            sc = event.get('syscall')
            if not sc:
                continue

            if sc in ['openat', 'read', 'write']:
                process_stats[pid]['file_ops'] += 1
                if event.get('file.path'):
                    process_stats[pid]['unique_files'].add(event['file.path'])

            if sc == 'write':
                process_stats[pid]['file_writes'] += 1

            if sc == 'unlinkat':
                process_stats[pid]['file_deletes'] += 1

            if sc == 'connect':
                process_stats[pid]['net_connections'] += 1

            if sc == 'execve':
                # Safely get parent PID
                parent_pid = event.get('process.parent.pid')
                if parent_pid:
                    parent = str(parent_pid)
                    process_stats[parent]['child_processes'] += 1

        for pid, stats in process_stats.items():
            suspicious = (
                stats['file_writes'] > FILE_WRITE_SUSPICIOUS or
                stats['net_connections'] > NET_CONNECT_SUSPICIOUS or
                stats['child_processes'] > CHILD_PROC_SUSPICIOUS or
                len(stats['unique_files']) > UNIQUE_FILE_SUSPICIOUS
            )
            if suspicious:
                self.attack_context['suspicious_processes'].add(pid)

        print(f"[+] Suspicious processes: {len(self.attack_context['suspicious_processes'])}")

    def find_threat_leads(
        self,
        hostname,
        start_ms,
        end_ms,
        top_n=10,
        per_pid_event_limit=200
    ):
        """
        Hybrid threat triage WITH HOSTNAME FILTER SUPPORT.

        Steps:
        1) ES aggregation per host to find suspicious PIDs.
        2) For top candidates, fetch raw events (small window) → refine score.
        3) Return threat leads with sample suspicious events.

        Args:
            start_ns: epoch ms start
            end_ns: epoch ms end
            top_n: top N threat leads to return
            per_pid_event_limit: number of raw events to pull per PID for refinement
            hostname: OPTIONAL → restrict threat hunting to a single host
        """

        print("[*] Running hybrid threat triage (agg + refinement) with hostname filter:", hostname)

        # -----------------------
        # Helper functions
        # -----------------------
        def normalize_name(path_or_name: str) -> str:
            return path_or_name.split("/")[-1] if path_or_name else ""

        def is_sensitive_file(name: str) -> bool:
            if not name:
                return False
            # Path-level detection
            if "/etc/shadow" in name or "/etc/passwd" in name:
                return True
            if ".ssh" in name or ".aws" in name:
                return True
            # Basename fallback
            base = normalize_name(name)
            if base in ("shadow", "passwd", "id_rsa", "id_ed25519", "authorized_keys"):
                return True
            return False

        def is_tmp_or_shm(name: str) -> bool:
            if not name:
                return False
            return name.startswith("/tmp/") or name.startswith("/dev/shm/")

        def is_script_like(name: str) -> bool:
            base = normalize_name(name)
            for ext in (".sh", ".py", ".pl", ".rb", ".php"):
                if base.endswith(ext):
                    return True
            return False

        def is_external_ip(ip: str) -> bool:
            if not ip:
                return False
            if ip.startswith(("127.", "10.", "192.168", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3")):
                return False
            return True

        # -----------------------
        # 1) Build aggregation query WITH hostname filter
        # -----------------------
        must_filters = [
            {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}
        ]

        if hostname:
            must_filters.append({"term": {"host.name.keyword": hostname}})

        agg_query = {
            "size": 0,
            "query": {"bool": {"must": must_filters}},
            "aggs": {
                "pids": {
                    "terms": {"field": "process.pid", "size": top_n * 5},
                    "aggs": {
                        "comms": {"terms": {"field": "process.name.keyword", "size": 1}},
                        "syscalls": {"terms": {"field": "syscall.keyword", "size": 20}},
                        "files": {"terms": {"field": "file.path.keyword", "size": 50}},
                        "dest_ips": {"terms": {"field": "destination.ip.keyword", "size": 20}},
                        "dest_ports": {"terms": {"field": "destination.port", "size": 20}},
                        "last_seen": {"max": {"field": "timestamp"}},
                        "event_count": {"value_count": {"field": "syscall.keyword"}}
                    }
                }
            }
        }

        try:
            resp = self.es.search(index=self.es_index, body=agg_query)
        except Exception as e:
            print(f"[!] Threat triage aggregation failed: {e}")
            return []

        buckets = resp["aggregations"]["pids"]["buckets"]

        # -----------------------
        # 2) Global syscall frequency (for rarity scoring)
        # -----------------------
        global_syscall_freq = Counter()
        for b in buckets:
            for s in b["syscalls"]["buckets"]:
                global_syscall_freq[s["key"]] += s["doc_count"]
        total_events = sum(global_syscall_freq.values()) + 1

        # -----------------------
        # 3) Coarse per-PID scoring
        # -----------------------
        coarse_candidates = []

        for b in buckets:
            pid = b["key"]
            comm = b["comms"]["buckets"][0]["key"] if b["comms"]["buckets"] else "unknown"

            if comm in ["systemd", "dockerd", "filebeat", "node_exporter"]:
                continue

            syscalls = [s["key"] for s in b["syscalls"]["buckets"]]
            files = [f["key"] for f in b["files"]["buckets"]]
            dest_ips = [d["key"] for d in b["dest_ips"]["buckets"]]
            dest_ports = [p["key"] for p in b["dest_ports"]["buckets"]]

            score = 0
            reasons = []

            # Sensitive file access
            if any(is_sensitive_file(fn) for fn in files):
                score += 60
                reasons.append("Sensitive file access")

            # High exec activity
            exec_count = sum(s["doc_count"] for s in b["syscalls"]["buckets"] if s["key"] == "execve")
            if exec_count >= 5:
                score += 25
                reasons.append("Burst of execve calls")

            # Heavy writes
            write_count = sum(s["doc_count"] for s in b["syscalls"]["buckets"] if s["key"] == "write")
            if write_count > 40:
                score += 20
                reasons.append("High write volume")

            # Deletions
            unlink_count = sum(s["doc_count"] for s in b["syscalls"]["buckets"] if s["key"] == "unlinkat")
            if unlink_count > 3:
                score += 35
                reasons.append("Multiple deletions")

            # Network connections
            if "connect" in syscalls:
                score += 20
                reasons.append("Network connections")
                for port in dest_ports:
                    if port not in (0, 22, 80, 443):
                        score += 15
                        reasons.append(f"Connection to unusual port {port}")
                for ip in dest_ips:
                    if is_external_ip(ip):
                        score += 15
                        reasons.append(f"External connection to {ip}")

            # Tmp / shm suspicious file
            if any(is_tmp_or_shm(fn) for fn in files) and "execve" in syscalls:
                score += 35
                reasons.append("Exec from /tmp or /dev/shm")

            # Rare syscalls
            rare_list = []
            for s in syscalls:
                freq = global_syscall_freq[s] / total_events
                if freq < 0.002:
                    rare_list.append(s)
            if rare_list:
                score += 5 * len(rare_list)
                reasons.append("Rare syscall usage")

            if score > 0:
                coarse_candidates.append({
                    "pid": pid,
                    "comm": comm,
                    "base_score": score,
                    "base_reasons": list(reasons),
                    "event_count": b["event_count"]["value"],
                    "timestamp": b["last_seen"]["value"]
                })

        if not coarse_candidates:
            print("[*] No candidate suspicious PIDs found for host:", hostname)
            return []

        # Rank and limit refinement set
        coarse_candidates.sort(key=lambda x: x["base_score"], reverse=True)
        refinement_candidates = coarse_candidates[: max(top_n * 3, top_n) ]

        # -----------------------
        # 4) Per-PID refinement (fetch raw events)
        # -----------------------
        refined = []

        for c in refinement_candidates:
            pid = c["pid"]
            comm = c["comm"]

            # Build filtered event query for this PID + hostname
            must_filters_pid = [
                {"term": {"process.pid": pid}},
                {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}
            ]
            if hostname:
                must_filters_pid.append({"term": {"host.name.keyword": hostname}})

            ev_query = {
                "size": per_pid_event_limit,
                "query": {"bool": {"must": must_filters_pid}},
                "sort": [{"timestamp": {"order": "asc"}}]
            }

            try:
                ev_resp = self.es.search(index=self.es_index, body=ev_query)
                events = [hit["_source"] for hit in ev_resp["hits"]["hits"]]
            except Exception as e:
                print(f"[!] Failed to pull refinement events for PID {pid}: {e}")
                events = []

            extra_score = 0
            extra_reasons = []
            sample_events = []

            seen_sensitive = False
            seen_connect = False
            seen_tmp_exec = False
            seen_unlink = False

            for ev in events:
                sc = ev.get("syscall", "")
                fn = ev.get("file.path", "") or ""
                dt = ev.get("@timestamp", "")
                dip = ev.get("destination.ip", "")
                dport = ev.get("destination.port", 0)

                # Sensitive file use
                if sc in ("openat", "read") and is_sensitive_file(fn):
                    if not seen_sensitive:
                        extra_score += 25
                        extra_reasons.append("Direct sensitive file access (sequence)")
                    seen_sensitive = True
                    sample_events.append({
                        "datetime": dt, "syscall": sc,
                        "filename": fn, "dest_ip": dip,
                        "dest_port": dport,
                        "reason": "Sensitive file access"
                    })

                # Suspicious exec
                if sc == "execve":
                    if is_tmp_or_shm(fn) or is_script_like(fn):
                        if not seen_tmp_exec:
                            extra_score += 30
                            extra_reasons.append("Suspicious script/tmp execution")
                        seen_tmp_exec = True
                        sample_events.append({
                            "datetime": dt, "syscall": sc,
                            "filename": fn, "dest_ip": dip,
                            "dest_port": dport,
                            "reason": "Suspicious exec"
                        })

                # Deletion
                if sc == "unlinkat":
                    if not seen_unlink:
                        extra_score += 20
                        extra_reasons.append("File deletion activity")
                    seen_unlink = True
                    sample_events.append({
                        "datetime": dt, "syscall": sc,
                        "filename": fn, "dest_ip": dip,
                        "dest_port": dport,
                        "reason": "Unlink (delete)"
                    })

                # Outbound connect
                if sc == "connect":
                    if not seen_connect:
                        extra_score += 15
                        extra_reasons.append("Outbound network activity (sequence)")
                    seen_connect = True
                    r = "Outbound connection"
                    if is_external_ip(dip):
                        extra_score += 10
                        extra_reasons.append("Connects to external IP")
                        r = "External connection"
                    sample_events.append({
                        "datetime": dt, "syscall": sc,
                        "filename": fn, "dest_ip": dip,
                        "dest_port": dport,
                        "reason": r
                    })

                # Sensitive-read → external connect (EXFIL pattern)
                if seen_sensitive and sc == "connect" and is_external_ip(dip):
                    extra_score += 25
                    extra_reasons.append("Sensitive read followed by external connect (possible exfiltration)")
                    sample_events.append({
                        "datetime": dt, "syscall": sc,
                        "filename": fn, "dest_ip": dip,
                        "dest_port": dport,
                        "reason": "Possible exfiltration"
                    })

            # Merge reasons
            all_reasons = c["base_reasons"] + extra_reasons
            # Dedup
            seen_set = set()
            unique_reasons = []
            for r in all_reasons:
                if r not in seen_set:
                    seen_set.add(r)
                    unique_reasons.append(r)

            total_score = c["base_score"] + extra_score

            refined.append({
                "pid": pid,
                "comm": comm,
                "score": total_score,
                "reasons": ", ".join(unique_reasons),
                "event_count": c["event_count"],
                "timestamp": c["timestamp"],
                "sample_events": sample_events[:10],
                "hostname": hostname or "<all>"
            })

        refined.sort(key=lambda x: x["score"], reverse=True)
        return refined[:top_n]

    def is_noise_category(self, event):
        """Check if event belongs to a noise category"""
        syscall = event.get('syscall')
        if not syscall:
            return False

        filename = event.get('file.path', '')
        comm = event.get('process.name', '')

        pid = event.get('process.pid')
        if not pid:
            return False
        pid = str(pid)

        for _, rules in NOISE_CATEGORIES.items():
            sensitivity = rules.get('sensitivity', 'medium')
            sensitivity_rules = SENSITIVITY_LEVELS[sensitivity]

            # Check process patterns
            if 'processes' in rules:
                for pattern in rules['processes']:
                    if re.match(pattern, comm):
                        # Don't filter if process is in attack context
                        if pid in self.attack_context['suspicious_processes']:
                            return False

                        # Apply sensitivity rules
                        if syscall == 'read' and sensitivity_rules['filter_reads']:
                            return True
                        if syscall in ['openat', 'read'] and filename:
                            if any(re.match(fp, filename) for fp in rules.get('files', [])):
                                return True

            # Check file patterns
            if 'files' in rules and filename:
                for pattern in rules['files']:
                    if re.match(pattern, filename):
                        # Don't filter if file is in attack context
                        if filename in self.attack_context['sensitive_files']:
                            return False

                        # Apply sensitivity rules
                        if syscall == 'read' and sensitivity_rules['filter_reads']:
                            return True
                        if syscall == 'openat':
                            return True

        return False

    def _should_filter_event(self, event):
        syscall = event.get('syscall')
        if not syscall:
            return True  # Filter events without syscall

        filename = event.get('file.path', '')
        comm = event.get('process.name', '')
        if isinstance(comm, str):
            comm = comm.split('\x00', 1)[0].strip()

        pid = event.get('process.pid')
        if not pid:
            return True  # Filter events without PID
        pid = str(pid)

        # ------------------------------
        # 0. Filter out gdbus completely
        # ------------------------------
        if comm.startswith('gdbus') or 'gdbus' in comm:
            return True

        if 'tracker-miner' in comm or 'tracker-extract' in comm:
            return True

        # ------------------------------
        # 1. NEVER filter critical syscalls
        # ------------------------------
        if syscall in ['execve', 'unlinkat']:
            return False

        # ------------------------------
        # 2. Allow filtering writes from benign processes
        # ------------------------------
        # (HOLMES considers write edges important for suspicious processes,
        #   so we ONLY filter writes for quiet/benign processes)
        if syscall == 'write':
            if is_benign_process(comm):
                return True   # suppress benign write noise
            return False      # keep suspicious writes

        # ------------------------------
        # 3. Auto-filter quiet benign processes
        # ------------------------------
        if is_quiet_benign(comm) and syscall in ['openat', 'read', 'write']:
            return True

        # ------------------------------
        # 4. NEVER filter access to sensitive files
        # ------------------------------
        if filename:
            for pattern in SENSITIVE_FILE_PATTERNS:
                if re.search(pattern, filename):
                    return False

        # ------------------------------
        # 5. Filter noise categories only for NON-suspicious processes
        # ------------------------------
        if pid not in self.attack_context['suspicious_processes']:
            if self.is_noise_category(event):
                return True

        # ------------------------------
        # 6. Default: keep event
        # ------------------------------
        return False

    # ------------------------------------------------------------------------
    # GRAPH CONSTRUCTION
    # ------------------------------------------------------------------------

    def _get_or_create_node(self, node_id, **attrs):
        if not self.graph.has_node(node_id):
            self.graph.add_node(node_id, **attrs)

    def _get_process_node(self, pid, ppid, comm, timestamp_ms):
        if pid not in self.processes:
            proc_node_id = f"proc_{pid}_{timestamp_ms}"
            self.processes[pid] = proc_node_id
            self.pid_start_time[pid] = timestamp_ms
            self.process_comm[pid] = comm
            self._get_or_create_node(
                proc_node_id,
                label=f"{comm}\n(PID: {pid})",
                type="process",
                comm=comm,
                pid=pid,
                benign=is_benign_process(comm)
            )

            if ppid != "0":
                if ppid in self.processes:
                    parent_node_id = self.processes[ppid]
                else:
                    parent_node_id = f"proc_{ppid}_phantom"
                    if not self.graph.has_node(parent_node_id):
                        self._get_or_create_node(
                            parent_node_id,
                            label=f"Parent PID: {ppid}\n(Trace Lost)",
                            type="process",
                            comm="unknown_parent", # <--- ADD THIS LINE
                            style="dashed"
                        )

                self.graph.add_edge(
                    parent_node_id,
                    proc_node_id,
                    label="spawned",
                    time=datetime.fromtimestamp(timestamp_ms / 1000).isoformat(),
                    edge_type="control"
                )

        proc_node_id = self.processes[pid]
        if self.process_comm.get(pid) != comm:
            self.process_comm[pid] = comm
            self.graph.nodes[proc_node_id]['comm'] = comm
            self.graph.nodes[proc_node_id]['label'] = f"{comm}\n(PID: {pid})"
        return proc_node_id

    def find_processes_by_pid(self, target_pid):
        """Find all process nodes matching the given PID"""
        found_procs = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get('type') == 'process' and str(data.get('pid')) == str(target_pid):
                found_procs.append(node_id)
        return found_procs

    def scout_activity_window(self, start_ms, end_ms, pid=None, comm=None, window_minutes=10, hostname=None):
        """
        Scouts for the specific PID or Command to find its active time range.
        Returns a new (start_ms, end_ms) tuple centered on the activity with padding.
        """
        print(f"[*] Scouting for target (PID={pid}, Comm={comm}) in broad range...")

        must_filters = [
             {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}
        ]

        if hostname:
            must_filters.append({"term": {"host.name.keyword": hostname}})

        # Filter strictly by the target
        if pid:
            must_filters.append({"term": {"process.pid": pid}})
        elif comm:
            truncated_comm = comm[:15]
            should_conditions = [
                {"term": {"process.name.keyword": comm}},            # Exact match (short commands)
                {"term": {"process.name.keyword": truncated_comm}},  # Truncated match
                {"term": {"file.path.keyword": comm}},               # Full filename match (from execve)
                {"term": {"file.path.keyword": "./" + comm}}         # Handle relative path case
            ]
            must_filters.append({"bool": {"should": should_conditions, "minimum_should_match": 1}})
        else:
            return start_ms, end_ms  # No target specified, use original range

        query = {
            "size": 100,  # We only need a sample to find the time
            "query": {"bool": {"must": must_filters}},
            "sort": [{"timestamp_ns": {"order": "asc"}}]
        }

        try:
            response = self.es.search(index=self.es_index, body=query)
            hits = response['hits']['hits']

            if not hits:
                return None, None  # Target not found in this range

            # Get the first and last time the target was seen
            first_seen = hits[0]['_source']['timestamp']
            last_seen = hits[-1]['_source']['timestamp']

            print(f"[+] Target found active between {datetime.fromtimestamp(first_seen/1000)} and {datetime.fromtimestamp(last_seen/1000)}")

            # Calculate padding in milliseconds
            padding_ms = window_minutes * 60 * 1000

            # Define new window
            new_start = first_seen - padding_ms
            new_end = last_seen + padding_ms

            return new_start, new_end

        except Exception as e:
            print(f"[!] Scouting failed: {e}")
            return None, None

    def build_graph(self, events, enable_filtering=True, enable_event_compression=False):
        print(f"Building provenance graph (filtering={'enabled' if enable_filtering else 'disabled'})...")

        self.total_events = len(events)
        self.event_compression_enabled = enable_event_compression

        # STEP 1: Detect attack context
        if enable_filtering:
            self.detect_attack_indicators(events)

        # STEP 2: Event compression (cluster metadata only)
        if enable_event_compression:
            self.beep_clusters = beep_compress_events(events, TIME_WINDOW_MS)
            print(f"Processing {len(self.beep_clusters)} event clusters...")

        # STEP 3: Build graph with context-aware filtering
        for event in events:
            if enable_filtering and self._should_filter_event(event):
                self.filtered_events += 1
                continue

            # Safely extract required fields
            pid = event.get('process.pid')
            if not pid:
                continue
            pid = str(pid)

            ppid = event.get('process.parent.pid', 0)
            ppid = str(ppid)

            comm = event.get('process.name', 'unknown')
            if isinstance(comm, str):
                comm = comm.split('\x00', 1)[0].strip()

            syscall = event.get('syscall')
            if not syscall:
                continue

            if 'timestamp' in event:
                timestamp_ms = event['timestamp']
            elif 'timestamp_ns' in event:
                timestamp_ms = event['timestamp_ns'] // 1000000
            else:
                timestamp_ms = event.get('timestamp_ms', 0)

            if syscall == 'execve' and event.get('file.path'):
                new_comm = event['file.path'].split('/')[-1]
                if new_comm:
                    comm = new_comm

            proc_node_id = self._get_process_node(pid, ppid, comm, timestamp_ms)

            if syscall == 'execve':
                file_node = event.get('file.path', '')
                if not file_node or not file_node.strip():
                    continue

                abstract_path = abstract_file_path(file_node)
                self._get_or_create_node(
                    file_node,
                    label=safe_label(file_node, 'exec_file'),
                    type="file",
                    abstract_path=abstract_path
                )
                self.graph.add_edge(
                    proc_node_id,
                    file_node,
                    label="executed",
                    time=event['datetime'],
                    edge_type="control"
                )

            elif syscall == 'openat':
                fd = event.get('fd', -1)
                if fd >= 0:
                    file_node = event.get('file.path', '')
                    if not file_node or not file_node.strip():
                        continue

                    self.fd_map[pid][fd] = file_node
                    self.file_access_count[file_node] += 1

                    abstract_path = abstract_file_path(file_node)
                    self._get_or_create_node(
                        file_node,
                        label=safe_label(file_node, f'file_fd{fd}'),
                        type="file",
                        abstract_path=abstract_path
                    )
                    self.graph.add_edge(
                        proc_node_id,
                        file_node,
                        label="open",
                        time=event['datetime'],
                        edge_type="data"
                    )

            elif syscall == 'read':
                fd = event.get('fd', -1)
                if fd in self.fd_map[pid]:
                    file_node = self.fd_map[pid][fd]
                    ret_bytes = event.get('ret', 0)
                    if ret_bytes > 0:
                        self.process_file_bytes[pid][file_node] += ret_bytes

                    self.graph.add_edge(
                        file_node,
                        proc_node_id,
                        label="read",
                        time=event['datetime'],
                        edge_type="data",
                        bytes=ret_bytes
                    )

            elif syscall == 'write':
                fd = event.get('fd', -1)
                if fd in self.fd_map[pid]:
                    file_node = self.fd_map[pid][fd]
                    ret_bytes = event.get('ret', 0)
                    if ret_bytes > 0:
                        self.process_file_bytes[pid][file_node] += ret_bytes

                    self.graph.add_edge(
                        proc_node_id,
                        file_node,
                        label="write",
                        time=event['datetime'],
                        edge_type="data",
                        bytes=ret_bytes
                    )

            elif syscall == 'unlinkat':
                file_node = event.get('file.path', '')
                if not file_node or not file_node.strip():
                    continue

                abstract_path = abstract_file_path(file_node)
                self._get_or_create_node(
                    file_node,
                    label=safe_label(file_node, 'deleted_file'),
                    type="file",
                    abstract_path=abstract_path
                )
                self.graph.add_edge(
                    proc_node_id,
                    file_node,
                    label="deleted",
                    time=event['datetime'],
                    edge_type="data"
                )

            elif syscall == 'connect':
                dest_ip = event.get('destination.ip', 'unknown_ip')
                dest_port = event.get('destination.port', 0)

                # Filter localhost connections to standard ports (unless suspicious)
                if dest_ip in ['127.0.0.1', 'localhost', '::1']:
                    if f"{dest_ip}:{dest_port}" not in self.attack_context['suspicious_ips']:
                        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999]
                        if dest_port not in suspicious_ports:
                            continue

                net_node_id = f"net_{dest_ip}_{dest_port}"
                net_label = f"Connect:\n{dest_ip}:{dest_port}"

                self._get_or_create_node(
                    net_node_id,
                    label=net_label,
                    type="network",
                    dest_ip=dest_ip,
                    dest_port=dest_port
                )
                self.graph.add_edge(
                    proc_node_id,
                    net_node_id,
                    label="connect",
                    time=event['datetime'],
                    edge_type="network"
                )

        filtered_pct = (self.filtered_events / self.total_events * 100) if self.total_events > 0 else 0
        print(f"[+] Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        print(f"[+] Filtered {self.filtered_events}/{self.total_events} events ({filtered_pct:.1f}% reduction)")

    # ------------------------------------------------------------------------
    # ATT&CK TECHNIQUE INFERENCE
    # ------------------------------------------------------------------------
    def collapse_sibling_processes(self, graph):
        """
        Aggressively merges sibling processes that share the same command name.
        Example: 13 'sudo' processes spawned by 'run-attack.sh' become 'sudo [x13]'
        """
        print("Collapsing identical sibling processes...")
        
        # 1. Group nodes by (parent, command_name)
        siblings_map = defaultdict(list)
        for node, attrs in graph.nodes(data=True):
            if attrs.get('type') == 'process':
                preds = list(graph.predecessors(node))
                if preds:
                    parent = preds[0] # Assuming tree structure for process spawning
                    comm = attrs.get('comm', 'unknown')
                    # Create a signature: Parent + Command Name
                    key = (parent, comm)
                    siblings_map[key].append(node)

        nodes_to_remove = []
        
        # 2. Merge groups larger than 1
        for (parent, comm), nodes in siblings_map.items():
            if len(nodes) < 2:
                continue
                
            # Keep the first node as the "Representative"
            survivor = nodes[0]
            victims = nodes[1:]
            count = len(nodes)
            
            # Update the survivor's label
            new_label = f"{comm}\n[x{count} PIDs]"
            graph.nodes[survivor]['label'] = new_label
            graph.nodes[survivor]['style'] = 'filled,bold,dashed' # Distinct visual style
            graph.nodes[survivor]['fillcolor'] = '#FFD700' # Gold color for clusters
            
            # Rewire edges from victims to survivor
            for v in victims:
                # Move outgoing edges (what the victim did) to the survivor
                for _, target, data in graph.out_edges(v, data=True):
                    if not graph.has_edge(survivor, target):
                        graph.add_edge(survivor, target, **data)
                
                nodes_to_remove.append(v)

        if nodes_to_remove:
            graph.remove_nodes_from(nodes_to_remove)
            print(f"[+] Collapsed {len(nodes_to_remove)} sibling processes into clusters")
            
        return graph

    def infer_mitre_techniques(self, graph):
        """
        Infer high-level MITRE ATT&CK techniques based on the final attack subgraph.
        Heuristic, but good enough to guide the AI + human.
        """
        techniques = {tid: {"info": MITRE_TECHNIQUES[tid], "evidence": []}
                      for tid in MITRE_TECHNIQUES.keys()}

        # Helper to record evidence
        def add_evidence(tid, text):
            if tid in techniques:
                techniques[tid]["evidence"].append(text)

        # Precompute some lookup helpers
        sensitive_files = []
        for node, attrs in graph.nodes(data=True):
            if attrs.get("type") == "file":
                filepath = str(node)
                for pat in SENSITIVE_FILE_PATTERNS:
                    if re.search(pat, filepath):
                        sensitive_files.append(node)
                        break

        # Map processes → whether they touch sensitive files and whether they talk to network
        proc_sensitive = defaultdict(bool)
        proc_network = defaultdict(bool)
        proc_file_read_counts = defaultdict(int)

        for u, v, data in graph.edges(data=True):
            label = data.get("label", "")
            u_type = graph.nodes[u].get("type", "")
            v_type = graph.nodes[v].get("type", "")

            # File reads and writes
            if label == "read" and u_type == "file" and v_type == "process":
                pid = graph.nodes[v].get("pid")
                proc_file_read_counts[pid] += 1
                if u in sensitive_files:
                    proc_sensitive[pid] = True

            if label == "connect" and u_type == "process" and v_type == "network":
                pid = graph.nodes[u].get("pid")
                proc_network[pid] = True

        # 1) Process-based detections
        for node, attrs in graph.nodes(data=True):
            if attrs.get("type") != "process":
                continue

            comm = (attrs.get("comm") or "").lower()
            label = attrs.get("label", str(node))
            pid = attrs.get("pid")

            # T1059: Command & Scripting Interpreter
            if any(x in comm for x in ["bash", "sh", "zsh", "python", "perl", "pwsh", "powershell", "cmd.exe"]):
                add_evidence(
                    "T1059",
                    f"Process {label} appears to be a scripting interpreter ({comm})."
                )

            # T1083: File and Directory Discovery (lots of reads across files)
            if proc_file_read_counts.get(pid, 0) > 20:
                add_evidence(
                    "T1083",
                    f"Process {label} performed more than 20 file read operations, suggesting discovery activity."
                )

        # 2) File-based detections
        for node, attrs in graph.nodes(data=True):
            if attrs.get("type") != "file":
                continue

            filepath = str(node)
            label = attrs.get("label", safe_label(filepath))

            # T1003: OS Credential Dumping
            if re.search(r'/etc/shadow', filepath) or re.search(r'/etc/passwd', filepath):
                # Check for any process that read this file
                readers = []
                for u, v, data in graph.edges(node, data=True):
                    if data.get("label") == "read" and graph.nodes[v].get("type") == "process":
                        readers.append(graph.nodes[v].get("label", v))
                if readers:
                    add_evidence(
                        "T1003",
                        f"Credential file {filepath} was read by: {', '.join(readers)}."
                    )

            # T1053 / T1037: cron/systemd/autostart/rc scripts
            if re.search(r'/etc/cron\.', filepath) or \
               re.search(r'/var/spool/cron', filepath) or \
               re.search(r'/etc/systemd/system', filepath) or \
               re.search(r'\.bashrc$', filepath) or \
               re.search(r'\.profile$', filepath):
                writers = []
                for u, v, data in graph.in_edges(node, data=True):
                    if data.get("label") == "write" and graph.nodes[u].get("type") == "process":
                        writers.append(graph.nodes[u].get("label", u))

                if writers:
                    # cron/systemd
                    if re.search(r'/etc/cron\.|/var/spool/cron|/etc/systemd/system', filepath):
                        add_evidence(
                            "T1053",
                            f"File {filepath} (cron/systemd) was modified by: {', '.join(writers)}."
                        )
                    # shell init scripts
                    if re.search(r'\.bashrc$|\.profile$', filepath):
                        add_evidence(
                            "T1037",
                            f"Shell init file {filepath} was modified by: {', '.join(writers)}."
                        )

        # 3) Exfiltration: sensitive reads + network
        for node, attrs in graph.nodes(data=True):
            if attrs.get("type") != "process":
                continue
            pid = attrs.get("pid")
            label = attrs.get("label", node)

            if proc_sensitive.get(pid) and proc_network.get(pid):
                add_evidence(
                    "T1041",
                    f"Process {label} both accessed sensitive files and made outbound network connections."
                )

        # Filter out techniques with no evidence
        self.mitre_techniques = {
            tid: {
                "id": tid,
                "name": t["info"]["name"],
                "tactic": t["info"]["tactic"],
                "description": t["info"]["description"],
                "evidence": t["evidence"]
            }
            for tid, t in techniques.items()
            if t["evidence"]
        }

        if self.mitre_techniques:
            print("[+] MITRE ATT&CK inference results:")
            for tid, info in self.mitre_techniques.items():
                print(f"    - {tid} {info['tactic']} / {info['name']} ({len(info['evidence'])} evidence items)")
        else:
            print("[+] MITRE ATT&CK inference: no strong technique indicators detected in this graph")

    # ------------------------------------------------------------------------
    # SUBGRAPH & POST-PROCESSING
    # ------------------------------------------------------------------------

    def calculate_path_factor(self, src, dst):
        key = (src, dst)
        if key in self._path_factor_cache:
            return self._path_factor_cache[key]

        try:
            pf = nx.shortest_path_length(self.graph, src, dst)
        except nx.NetworkXNoPath:
            pf = float("inf")

        self._path_factor_cache[key] = pf
        return pf

    def calculate_path_factor_subgraph(self, subgraph, src, dst):
        key = ("sub", id(subgraph), src, dst)   # separate cache entries per-subgraph
        if key in self._path_factor_cache:
            return self._path_factor_cache[key]

        try:
            pf = nx.shortest_path_length(subgraph, src, dst)
        except nx.NetworkXNoPath:
            pf = float("inf")

        self._path_factor_cache[key] = pf
        return pf

    def find_processes_by_name(self, comm_name):
        """Find all process nodes matching the given command name"""
        found_procs = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get('type') == 'process' and data.get('comm') == comm_name:
                found_procs.append(node_id)
        return found_procs

    def get_attack_subgraph(self, target_nodes, max_depth=5, include_parents=True, include_children=True):
        """Extract focused subgraph around target nodes"""
        if not target_nodes:
            return nx.DiGraph()

        print(f"Extracting subgraph for {target_nodes}. Parents={include_parents}, Children={include_children}")

        subgraph_nodes = set(target_nodes)

        for node in target_nodes:
            if not self.graph.has_node(node):
                continue

            if include_parents:
                ancestors = nx.bfs_tree(self.graph, node, reverse=True, depth_limit=max_depth)
                subgraph_nodes.update(ancestors.nodes())

            if include_children:
                descendants = nx.bfs_tree(self.graph, node, reverse=False, depth_limit=max_depth)
                subgraph_nodes.update(descendants.nodes())

        subgraph = self.graph.subgraph(subgraph_nodes).copy()
        print(f"[+] Subgraph extracted: {subgraph.number_of_nodes()} nodes")
        return subgraph

    def remove_low_value_nodes(self, graph, target_nodes):
        """
        Remove nodes that don't contribute to understanding the attack.
        Uses graph centrality and connectivity metrics.
        """
        print("Removing low-value nodes using graph analysis...")

        # Calculate node importance
        try:
            pagerank = nx.pagerank(graph)
        except:
            pagerank = {node: 1.0 for node in graph.nodes()}

        nodes_to_remove = []

        for node, attrs in graph.nodes(data=True):
            # Never remove target nodes
            if node in target_nodes:
                continue

            node_type = attrs.get('type')

            # Calculate importance score
            importance = pagerank.get(node, 0)
            degree = graph.in_degree(node) + graph.out_degree(node)

            # Check if node is on path to target
            on_critical_path = False
            for target in target_nodes:
                if graph.has_node(target):
                    try:
                        if nx.has_path(graph, node, target) or nx.has_path(graph, target, node):
                            on_critical_path = True
                            break
                    except:
                        pass

            # Decision criteria (generalized)
            should_remove = False

            if node_type == 'file':
                # Low importance file with low connectivity
                if importance < 0.001 and degree == 1:
                    # Check if it's NOT a sensitive file
                    if not any(re.search(p, str(node)) for p in SENSITIVE_FILE_PATTERNS):
                        should_remove = True

            elif node_type == 'process':
                # Benign process not on critical path
                if attrs.get('benign', False) and not on_critical_path:
                    if importance < 0.01 and degree < 3:
                        should_remove = True

            elif node_type == 'network':
                # Network connections on standard ports with low importance
                dest_port = attrs.get('dest_port', 0)
                if dest_port in [22, 80, 443] and importance < 0.005:
                    should_remove = True

            if should_remove:
                nodes_to_remove.append(node)

        if nodes_to_remove:
            print(f"[-] Removing {len(nodes_to_remove)} low-value nodes")
            graph.remove_nodes_from(nodes_to_remove)

        return graph

    def prune_high_degree_files(self, graph, degree_threshold=5):
        """Enhanced high-degree file pruning with smart library detection"""
        print(f"Pruning high-degree files (degree > {degree_threshold})...")

        # Enhanced noise file patterns (libraries, system files)
        NOISE_FILE_PATTERNS = [
            r'\.so(\.\d+)*$',                    # Shared libraries
            r'/lib(64)?/.*\.so',                  # Library directories
            r'/usr/lib.*\.so',
            r'ld-linux',                          # Dynamic linker
            r'libc\.so',
            r'libpthread',
            r'libdl\.so',
            r'/usr/share/locale/',                # Locale files
            r'/usr/share/fonts/',                 # Fonts
            r'\.mo$',                             # Translation files
            r'/proc/(cpuinfo|meminfo|stat)',      # Proc pseudo-files
            r'/sys/devices/',                     # Sysfs
            r'/dev/(null|zero|random|urandom)$',  # Standard devices
        ]

        nodes_to_remove = []

        for node, attrs in graph.nodes(data=True):
            if attrs.get('type') == 'file':
                total_degree = graph.in_degree(node) + graph.out_degree(node)
                filepath = str(node)

                # Never remove sensitive/attack files
                is_sensitive = any(re.search(p, filepath) for p in SENSITIVE_FILE_PATTERNS)
                if is_sensitive:
                    continue

                # Adaptive threshold for system paths (2x higher)
                adaptive_threshold = degree_threshold * 2 if any(sys_path in filepath for sys_path in ['/usr/lib', '/lib', '/etc/ld.so']) else degree_threshold

                if total_degree > adaptive_threshold:
                    # Check if it's a known noise pattern (library/system file)
                    is_noise = any(re.search(p, filepath) for p in NOISE_FILE_PATTERNS)

                    # Read-only files with no outgoing edges are likely libraries/configs
                    is_read_only = graph.out_degree(node) == 0

                    # But keep read-only files in suspicious directories
                    in_suspicious_dir = any(susp in filepath for susp in ['/tmp', '/home', '/root'])

                    if is_noise or (is_read_only and not in_suspicious_dir):
                        nodes_to_remove.append(node)

        if nodes_to_remove:
            print(f"[-] Removing {len(nodes_to_remove)} high-degree files (libraries/system files)")
            for node in nodes_to_remove[:5]:
                degree = graph.in_degree(node) + graph.out_degree(node)
                print(f"    - {node} (degree={degree})")
            graph.remove_nodes_from(nodes_to_remove)

        return graph

    def remove_benign_only_subgraphs(self, graph):
        """Remove disconnected subgraphs with only benign processes"""
        print("Removing benign-only subgraphs...")

        if graph.number_of_nodes() == 0:
            return graph

        undirected = graph.to_undirected()
        components = list(nx.connected_components(undirected))

        nodes_to_remove = []
        for component in components:
            has_malicious = False
            for node in component:
                attrs = graph.nodes[node]
                if attrs.get('type') == 'process' and not attrs.get('benign', False):
                    has_malicious = True
                    break
                if attrs.get('type') == 'network':
                    has_malicious = True
                    break

            if not has_malicious and len(component) < 10:
                nodes_to_remove.extend(component)

        if nodes_to_remove:
            print(f"[-] Removing {len(nodes_to_remove)} nodes from benign-only subgraphs")
            graph.remove_nodes_from(nodes_to_remove)

        return graph

    def remove_isolated_nodes(self, graph):
        """Remove nodes with no connections"""
        isolates = list(nx.isolates(graph))
        if isolates:
            print(f"Removing {len(isolates)} isolated nodes")
            graph.remove_nodes_from(isolates)
        return graph

    def beep_edge_grouping(self, graph, time_window_ms=2000, min_group_size=2):
        """Enhanced BEEP-style graph-level edge grouping with adaptive thresholds"""
        print(f"Applying BEEP edge grouping (window={time_window_ms}ms, min_size={min_group_size})...")

        edge_groups = defaultdict(list)
        network_groups = defaultdict(list)  # Track network connections per process

        for u, v, data in list(graph.edges(data=True)):
            source_node = u
            edge_label = data.get('label', '')
            target_node = v
            target_type = graph.nodes[v].get('type', 'unknown')
            time_str = data.get('time', '')

            try:
                if isinstance(time_str, str) and time_str:
                    event_time = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    timestamp_ms = int(event_time.timestamp() * 1000)
                else:
                    timestamp_ms = 0
            except:
                timestamp_ms = 0

            # --- IMPROVEMENT 1: Enhanced abstraction based on type ---
            if target_type == 'process':
                comm = graph.nodes[v].get('comm', '')
                target_abstract = re.sub(r'\d+', '', comm)
            elif target_type == 'file':
                filepath = str(target_node)
                # Skip grouping for attack-related files
                if any(re.search(p, filepath) for p in SENSITIVE_FILE_PATTERNS):
                    continue  # Never group sensitive/attack files

                # IMPROVEMENT 4: Enhanced file path abstraction (directory + extension)
                if '/' in filepath:
                    directory = '/'.join(filepath.split('/')[:-1])
                    filename = filepath.split('/')[-1]
                    ext = filename.rsplit('.', 1)[-1] if '.' in filename else 'file'
                    target_abstract = f"{directory}/*.{ext}"
                else:
                    filename = filepath
                    target_abstract = canonicalize_filename(filename)
            elif target_type == 'network':
                # IMPROVEMENT 5: Network subnet grouping
                dest_ip = graph.nodes[v].get('dest_ip', '')
                dest_port = graph.nodes[v].get('dest_port', 0)
                if dest_ip and '.' in dest_ip:
                    subnet = '.'.join(dest_ip.split('.')[:3])
                    target_abstract = f"{subnet}.x:{dest_port}"
                else:
                    target_abstract = target_type

                # Track network connections for suspicious pattern detection
                network_groups[source_node].append(str(target_node))
            else:
                target_abstract = target_type

            group_key = (source_node, edge_label, target_type, target_abstract)

            edge_groups[group_key].append({
                'source': u,
                'target': v,
                'data': data,
                'timestamp': timestamp_ms
            })

        # IMPROVEMENT 6: Suspicious network pattern detection
        for proc_node, net_targets in network_groups.items():
            unique_dests = set(net_targets)
            if len(unique_dests) >= 3:
                comm = graph.nodes.get(proc_node, {}).get('comm', proc_node)
                print(f"[!] Suspicious: {comm} connected to {len(unique_dests)} different destinations")

        groups_to_collapse = []

        for group_key, edges in edge_groups.items():
            if len(edges) < min_group_size:
                continue

            edges_sorted = sorted(edges, key=lambda x: x['timestamp'])

            # IMPROVEMENT 2: Adaptive time windows (5x longer for network)
            source_node, edge_label, target_type, target_abstract = group_key
            adaptive_window = time_window_ms * 5 if target_type == 'network' else time_window_ms

            if edges_sorted[-1]['timestamp'] > 0 and edges_sorted[0]['timestamp'] > 0:
                time_span = edges_sorted[-1]['timestamp'] - edges_sorted[0]['timestamp']

                # IMPROVEMENT 3: Periodic behavior detection
                if len(edges_sorted) >= 5 and time_span > adaptive_window:
                    intervals = [edges_sorted[i+1]['timestamp'] - edges_sorted[i]['timestamp']
                               for i in range(len(edges_sorted)-1)]
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum(abs(iv - avg_interval) for iv in intervals) / len(intervals)

                    # If intervals are uniform (variance < 30%), it's periodic behavior
                    if variance < avg_interval * 0.3:
                        print(f"[+] Detected periodic pattern: {len(edges_sorted)} events with {avg_interval:.0f}ms intervals")
                        # Allow grouping even if time span exceeds window
                    else:
                        continue  # Skip non-periodic events outside window
                elif time_span > adaptive_window:
                    continue

            groups_to_collapse.append({
                'key': group_key,
                'edges': edges_sorted,
                'count': len(edges_sorted)
            })

        if not groups_to_collapse:
            print(f"[+] No edge groups found (nothing to collapse)")
            return graph

        collapsed_count = 0

        for group_info in groups_to_collapse:
            source_node, edge_label, target_type, target_abstract = group_info['key']
            edges = group_info['edges']
            count = group_info['count']

            target_nodes = [e['target'] for e in edges]

            target_labels = []
            for tgt in target_nodes:
                if target_type == 'file':
                    label = safe_label(tgt)
                elif target_type == 'process':
                    label = graph.nodes[tgt].get('comm', safe_label(tgt))
                else:
                    label = str(tgt)
                target_labels.append(label)

            pattern = detect_file_pattern(target_labels)
            if pattern:
                abstract_label = f"{pattern}"
            elif target_abstract and target_abstract != "":
                abstract_label = f"{target_abstract} [×{count}]"
            else:
                abstract_label = f"{target_labels[0]}... [×{count}]"

            abstract_node_id = f"BEEP_GROUP_{source_node}_{edge_label}_{target_type}_{collapsed_count}"

            graph.add_node(
                abstract_node_id,
                label=abstract_label,
                type=f"beep_{target_type}",
                beep_group=True,
                group_size=count,
                edge_type=edge_label,
                original_targets=target_labels,
                shape='box3d',
                style='filled,bold',
                fillcolor='#FFD700'
            )

            first_time = edges[0]['data'].get('time', 'N/A')
            last_time = edges[-1]['data'].get('time', 'N/A')

            graph.add_edge(
                source_node,
                abstract_node_id,
                label=f"{edge_label} [×{count}]",
                time=first_time,
                time_range=f"{first_time} to {last_time}",
                edge_type='beep_aggregated',
                group_size=count
            )

            for edge in edges:
                target = edge['target']

                if graph.has_edge(edge['source'], target):
                    graph.remove_edge(edge['source'], target)

                if graph.has_node(target):
                    if graph.in_degree(target) == 0 and graph.out_degree(target) == 0:
                        graph.remove_node(target)

            collapsed_count += 1

        print(f"[+] BEEP: Collapsed {collapsed_count} edge groups")
        print(f"[+] Graph after BEEP: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

        return graph

    def compress_structural_nodes(self, graph):
        """ProvGRP-style Structural Compression"""
        print("Applying Structural Node Compression (ProvGRP)...")

        changed = True
        iteration = 0

        while changed and iteration < 5:
            changed = False
            iteration += 1

            signatures = defaultdict(list)

            nodes_list = list(graph.nodes(data=True))
            for node, attrs in nodes_list:
                if attrs.get('beep_group'):
                    continue

                in_sig = []
                for u, _, data in graph.in_edges(node, data=True):
                    in_sig.append((u, data.get('label', '')))
                in_sig.sort()

                out_sig = []
                for _, v, data in graph.out_edges(node, data=True):
                    out_sig.append((data.get('label', ''), v))
                out_sig.sort()

                # --- FIX START ---
                if attrs.get('type') == 'process':
                    # Fallback to node ID if 'comm' is None (e.g., phantom nodes)
                    identity = attrs.get('comm') or str(node)
                else:
                    identity = safe_label(str(node))
                
                # Final safety check to ensure identity is a string
                if identity is None:
                    identity = "unknown"
                # --- FIX END ---

                identity_pattern = re.sub(r'\d+', '', identity)

                sig = (attrs.get('type'), tuple(in_sig), tuple(out_sig), identity_pattern)
                signatures[sig].append(node)

            for sig, nodes in signatures.items():
                if len(nodes) < 2:
                    continue

                keep_node = nodes[0]
                remove_nodes = nodes[1:]

                count = len(nodes)
                old_label = graph.nodes[keep_node].get('label', str(keep_node))

                node_names = [str(n) for n in nodes]
                pattern_name = detect_file_pattern(node_names)

                if pattern_name:
                    new_label = f"{pattern_name}"
                else:
                    clean_label = old_label.split('\n')[0]
                    new_label = f"{clean_label} [×{count}]"

                graph.nodes[keep_node]['label'] = new_label
                graph.nodes[keep_node]['count'] = count
                graph.nodes[keep_node]['shape'] = 'folder'

                graph.remove_nodes_from(remove_nodes)
                changed = True

        print(f"[+] Structural compression finished after {iteration} iterations")
        return graph

    def holmes_backward_slice(self, graph, enable_forward=True):
        """Enhanced HOLMES-style backward slicing with advanced threat detection"""
        print(f"Applying HOLMES backward slicing (Enhanced)...")

        if graph.number_of_nodes() == 0:
            return graph

        alert_nodes = set()
        alert_reasons = defaultdict(list)  # Track why each node is flagged

        # Enhanced suspicious file patterns
        ENHANCED_SENSITIVE_PATTERNS = HOLMES_ALERT_PATTERNS + [
            r'/etc/(passwd|shadow|sudoers)',
            r'\.ssh/(id_rsa|id_ed25519|authorized_keys)',
            r'\.(bash|zsh)_history$',
            r'/proc/\d+/(maps|environ|cmdline)',
            r'/(cron|at)\.d/',
            r'\.(pem|key|cert)$',
        ]

        # Suspicious ports (C2 frameworks, etc.)
        SUSPICIOUS_PORTS = [4444, 5555, 8080, 8443, 9001]

        # Scripting interpreters that may execute staged malware
        SCRIPT_INTERPRETERS = ['bash', 'sh', 'python', 'python3', 'perl', 'ruby', 'php']

        # Untrusted execution locations
        UNTRUSTED_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/']

        # Behavioral pattern analysis
        process_behaviors = defaultdict(lambda: {'files_read': 0, 'files_written': 0, 'net_conns': 0, 'children': []})

        for u, v, data in graph.edges(data=True):
            label = data.get('label', '')
            u_type = graph.nodes[u].get('type', '')
            v_type = graph.nodes[v].get('type', '')

            # Count file reads/writes
            if label == 'read' and u_type == 'file' and v_type == 'process':
                pid = graph.nodes[v].get('pid', v)
                process_behaviors[pid]['files_read'] += 1
            elif label in ['write', 'created'] and u_type == 'process' and v_type == 'file':
                pid = graph.nodes[u].get('pid', u)
                process_behaviors[pid]['files_written'] += 1

            # Count network connections
            elif label == 'connected' and u_type == 'process' and v_type == 'network':
                pid = graph.nodes[u].get('pid', u)
                process_behaviors[pid]['net_conns'] += 1

            # Track process spawning
            elif label == 'spawned' and u_type == 'process' and v_type == 'process':
                ppid = graph.nodes[u].get('pid', u)
                process_behaviors[ppid]['children'].append(v)

        for node, attrs in graph.nodes(data=True):
            node_type = attrs.get('type', '')
            comm = attrs.get('comm', '')

            if node_type == 'process':
                # IMPROVEMENT 1: Rapid process spawning detection
                child_processes = [c for c in process_behaviors[attrs.get('pid', node)]['children']
                                 if graph.nodes.get(c, {}).get('type') == 'process']
                if len(child_processes) >= 5:
                    alert_nodes.add(node)
                    alert_reasons[node].append('rapid_spawning')
                    print(f"[!] Alert: {comm} spawned {len(child_processes)} child processes (rapid spawning)")

                # IMPROVEMENT 2: Untrusted code execution
                if comm in SCRIPT_INTERPRETERS:
                    # Check if executing from untrusted location
                    for successor in graph.successors(node):
                        if graph.nodes[successor].get('type') == 'file':
                            filepath = str(successor)
                            if any(untrusted in filepath for untrusted in UNTRUSTED_PATHS):
                                alert_nodes.add(node)
                                alert_reasons[node].append('untrusted_execution')
                                print(f"[!] Alert: {comm} executing from untrusted location: {filepath}")
                                break

                # IMPROVEMENT 3: Behavioral exfiltration patterns (but exclude benign processes)
                pid = attrs.get('pid', node)
                behavior = process_behaviors[pid]
                if behavior['files_read'] > 20 and behavior['net_conns'] > 0:
                    # Exclude benign desktop processes like gjs
                    if not is_benign_process(comm):
                        alert_nodes.add(node)
                        alert_reasons[node].append('potential_exfiltration')
                        print(f"[!] Alert: {comm} shows exfiltration pattern ({behavior['files_read']} reads + {behavior['net_conns']} network)")

                # IMPROVEMENT 4: Mass file modification (ransomware detection)
                if behavior['files_written'] > 50:
                    alert_nodes.add(node)
                    alert_reasons[node].append('mass_file_modification')
                    print(f"[!] Alert: {comm} shows mass modification pattern ({behavior['files_written']} writes)")

                # File deletion (anti-forensics)
                for successor in graph.successors(node):
                    edge_data = graph.get_edge_data(node, successor)
                    if isinstance(edge_data, dict):
                        labels = [d.get('label') for d in edge_data.values()] if 0 in edge_data else [edge_data.get('label')]

                        if 'deleted' in labels or 'unlink' in str(labels):
                            alert_nodes.add(node)
                            alert_reasons[node].append('file_deletion')
                            print(f"[!] Alert: {comm} deleted a file (anti-forensics)")

            if node_type == 'file':
                filepath = str(node)
                # IMPROVEMENT 5: Enhanced sensitive file patterns
                for pattern in ENHANCED_SENSITIVE_PATTERNS:
                    if re.search(pattern, filepath):
                        for pred in graph.predecessors(node):
                            if graph.nodes[pred].get('type') == 'process':
                                alert_nodes.add(pred)
                                alert_reasons[pred].append(f'accessed_sensitive:{filepath}')
                                print(f"[!] Alert: {graph.nodes[pred].get('comm', pred)} accessed {filepath}")

            if node_type == 'network':
                # IMPROVEMENT 6: Suspicious port detection
                dest_port = attrs.get('dest_port', 0)
                if dest_port in SUSPICIOUS_PORTS:
                    for pred in graph.predecessors(node):
                        if graph.nodes[pred].get('type') == 'process':
                            alert_nodes.add(pred)
                            comm = graph.nodes[pred].get('comm', pred)
                            alert_reasons[pred].append(f'suspicious_port:{dest_port}')
                            print(f"[!] Alert: {comm} connected to suspicious port {dest_port}")

                # Network connections from non-benign processes
                for pred in graph.predecessors(node):
                    if graph.nodes[pred].get('type') == 'process':
                        comm = graph.nodes[pred].get('comm', '')
                        if not is_benign_process(comm):
                            alert_nodes.add(pred)
                            alert_reasons[pred].append('network_connection')
                            print(f"[!] Alert: {comm} made network connection")

        if not alert_nodes:
            print(f"[+] No sensitive operations detected, keeping full graph")
            return graph

        print(f"[+] Found {len(alert_nodes)} alert nodes")

        causal_ancestors = set()
        for alert in alert_nodes:
            try:
                ancestors = nx.ancestors(graph, alert)
                causal_ancestors.update(ancestors)
            except nx.NetworkXError:
                pass

        print(f"[+] Backward slice: {len(causal_ancestors)} ancestor nodes")

        consequences = set()
        if enable_forward:
            for alert in alert_nodes:
                try:
                    descendants = nx.descendants(graph, alert)
                    consequences.update(descendants)
                except nx.NetworkXError:
                    pass
            print(f"[+] Forward slice: {len(consequences)} descendant nodes")

        siblings = set()
        for ancestor in causal_ancestors:
            if graph.nodes[ancestor].get('type') == 'process':
                children = graph.successors(ancestor)
                siblings.update(children)

        print(f"[+] Sibling expansion: Added {len(siblings)} context nodes")

        keep_nodes = alert_nodes | causal_ancestors | consequences | siblings

        for node, attrs in graph.nodes(data=True):
            node_type = attrs.get('type', '')
            if node_type == 'file':
                filepath = str(node)
                for pattern in ENHANCED_SENSITIVE_PATTERNS:
                    if re.search(pattern, filepath):
                        keep_nodes.add(node)
            elif node_type == 'network':
                keep_nodes.add(node)

        all_nodes = set(graph.nodes())
        remove_nodes = all_nodes - keep_nodes

        if remove_nodes:
            print(f"[-] HOLMES: Removing {len(remove_nodes)} non-causal nodes")
            graph.remove_nodes_from(remove_nodes)

        return graph

    def filter_temporal_window(self, graph, attack_start_time, window_hours=1):
        """Remove processes outside temporal window"""
        print(f"Filtering processes outside {window_hours}h window from attack start...")
        try:
            # Handle epoch milliseconds properly
            if isinstance(attack_start_time, (int, float)):
                attack_dt = datetime.fromtimestamp(int(attack_start_time) / 1000.0)
            elif isinstance(attack_start_time, str):
                try:
                    attack_dt = datetime.fromisoformat(attack_start_time.replace('Z', '+00:00'))
                except ValueError:
                    attack_dt = datetime.fromtimestamp(int(attack_start_time) / 1000.0)
            else:
                attack_dt = attack_start_time

            window_start = attack_dt - timedelta(hours=window_hours)
            window_start_ms = int(window_start.timestamp() * 1000)

            nodes_to_remove = []

            for node, attrs in graph.nodes(data=True):
                if attrs.get('type') == 'process':
                    pid = attrs.get('pid')

                    if pid and str(pid) in self.pid_start_time:
                        start_time_ms = self.pid_start_time[str(pid)]

                        if start_time_ms < window_start_ms:
                            if attrs.get('benign', False):
                                nodes_to_remove.append(node)

            if nodes_to_remove:
                print(f"[-] Removing {len(nodes_to_remove)} processes that started before attack window")
                graph.remove_nodes_from(nodes_to_remove)

            return graph

        except Exception as e:
            print(f"[!] Temporal filtering failed: {e}")
            return graph

    # ------------------------------------------------------------------------
    # EXPORTS
    # ------------------------------------------------------------------------

    def export_text_summary(self, graph, filename):
        """Export human-readable summary including inferred ATT&CK techniques"""
        if not graph:
            return

        print(f"Exporting text summary to {filename}...")
        try:
            edges = sorted(graph.edges(data=True), key=lambda x: x[2].get('time', ''))
            with open(filename, 'w') as f:
                f.write("=== ATTACK PROVENANCE ANALYSIS ===\n\n")
                f.write(f"Total Nodes: {graph.number_of_nodes()}\n")
                f.write(f"Total Edges: {graph.number_of_edges()}\n\n")

                proc_count = sum(1 for _, d in graph.nodes(data=True) if d.get('type') == 'process')
                file_count = sum(1 for _, d in graph.nodes(data=True) if d.get('type') == 'file')
                net_count = sum(1 for _, d in graph.nodes(data=True) if d.get('type') == 'network')

                f.write(f"Processes: {proc_count}\n")
                f.write(f"Files: {file_count}\n")
                f.write(f"Network: {net_count}\n\n")

                if self.beep_clusters:
                    f.write(f"BEEP Event Clusters: {len(self.beep_clusters)}\n")
                    burst_count = sum(1 for c in self.beep_clusters if c['count'] > 1)
                    f.write(f"Multi-event Bursts: {burst_count}\n\n")

                # MITRE ATT&CK section
                f.write("=== MITRE ATT&CK TECHNIQUE INFERENCE ===\n\n")
                if self.mitre_techniques:
                    for tid, info in self.mitre_techniques.items():
                        f.write(f"- {tid} | {info['tactic']} | {info['name']}\n")
                        f.write(f"  Description: {info['description']}\n")
                        for ev in info['evidence']:
                            f.write(f"    * {ev}\n")
                        f.write("\n")
                else:
                    f.write("No strong MITRE ATT&CK patterns were identified in this graph.\n\n")

                f.write("=== CHRONOLOGICAL EVENTS ===\n\n")
                for u, v, data in edges:
                    src = graph.nodes[u].get('label', u).replace('\n', ' ')
                    dst = graph.nodes[v].get('label', v).replace('\n', ' ')
                    edge_label = data.get('label', '')
                    timestamp = data.get('time', 'N/A')

                    f.write(f"[{timestamp}] {src} --[{edge_label}]--> {dst}\n")

            print(f"[+] Text summary saved")
        except Exception as e:
            print(f"[!] Text export failed: {e}")

    def export_to_dot(self, graph, filename, focus_nodes=None):
        """Export cleaned graph to a Graphviz DOT file with SAFE attributes."""

        print(f"Exporting to DOT format...")

        # Allowed for Graphviz
        GRAPHVIZ_ALLOWED_ATTRS = {
            "label", "shape", "style", "fillcolor", "color", "penwidth", "tooltip"
        }

        def q(s):
            """Quote + escape string for DOT."""
            if s is None:
                return "\"\""
            s = str(s).replace('"', '\\"')
            return f"\"{s}\""

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("digraph G {\n")
                f.write("  rankdir=LR;\n")
                f.write("  fontsize=12;\n")
                f.write("  labelloc=\"top\";\n")
                for node_id, attrs in graph.nodes(data=True):
                    styled = {}
                    ntype = attrs.get("type")
                    if ntype == "process":
                        styled["shape"] = "box"
                        styled["style"] = "filled,rounded"
                        styled["fillcolor"] = "#AAAAAA" if attrs.get("benign", False) else "#40A8D1"

                    elif ntype == "file":
                        styled["shape"] = "note"
                        styled["style"] = "filled"
                        path = str(node_id)
                        if any(re.search(p, path) for p in SENSITIVE_FILE_PATTERNS):
                            styled["fillcolor"] = "#D14040"      # sensitive
                        elif "/tmp/" in path:
                            styled["fillcolor"] = "#D18C40"      # tmp files
                        else:
                            styled["fillcolor"] = "#CCCCCC"      # normal file
                    # ---- NETWORK NODES ----
                    elif ntype == "network":
                        styled["shape"] = "diamond"
                        styled["style"] = "filled"
                        styled["fillcolor"] = "#FF69B4"
                    # ---- BEEP GROUP / AGGREGATED EVENTS ----
                    elif attrs.get("beep_group", False):
                        styled["shape"] = "box3d"
                        styled["style"] = "filled,bold"
                        styled["fillcolor"] = "#FFD700"
                    # -----------------------
                    # Highlight focus nodes
                    # -----------------------
                    if focus_nodes and node_id in focus_nodes:
                        styled["color"] = "red"
                        styled["penwidth"] = "4"
                    else:
                        styled["color"] = "black"
                        styled["penwidth"] = "1"

                    label = attrs.get("label", str(node_id))
                    tooltip = label.replace('"', "'")

                    styled["label"] = label
                    styled["tooltip"] = tooltip

                    dot_attrs = []
                    for k, v in styled.items():
                        if k in GRAPHVIZ_ALLOWED_ATTRS:
                            dot_attrs.append(f'{k}={q(v)}')

                    f.write(f'  {q(node_id)} [{", ".join(dot_attrs)}];\n')

                for u, v, attrs in graph.edges(data=True):
                    edge_attrs = {}

                    # label if present
                    if "label" in attrs:
                        edge_attrs["label"] = attrs["label"]

                    # tooltip (if timestamp or cause exists)
                    if "time" in attrs:
                        edge_attrs["tooltip"] = f"time: {attrs['time']}"

                    # make edges visible
                    edge_attrs["color"] = "gray"

                    # write clean attributes
                    dot_attrs = [f'{k}={q(v)}' for k, v in edge_attrs.items()]

                    f.write(f'  {q(u)} -> {q(v)} [{", ".join(dot_attrs)}];\n')

                # -----------------------
                # FOOTER
                # -----------------------
                f.write("}\n")

            print(f"[+] DOT file saved: {filename}")

        except Exception as e:
            print(f"[!] DOT export failed: {e}")
            raise

def main():
    print("Enhanced Provenance Graph Analyzer with Generalized Context-Aware Filtering + MITRE ATT&CK inference")
    parser = argparse.ArgumentParser(
        description="Enhanced Provenance Graph Analyzer with Generalized Context-Aware Filtering + MITRE ATT&CK inference"
    )

    parser.add_argument("--comm", type=str, help="Target process name")
    parser.add_argument("--pid", type=str, help="Target process PID")
    parser.add_argument("--start", type=str, required=True, help="Start time (ISO format or epoch ms)")
    parser.add_argument("--end", type=str, required=True, help="End time (ISO format or epoch ms)")
    parser.add_argument("--depth", type=int, default=5, help="Max graph depth")
    parser.add_argument("--out", type=str, default="provenance_attack_0.dot", help="Output DOT file")
    parser.add_argument("--text-out", type=str, default="attack_summary.txt", help="Text summary file")

    parser.add_argument("--no-parents", action="store_true", help="Disable ancestor tracing")
    parser.add_argument("--no-children", action="store_true", help="Disable descendant tracing")
    parser.add_argument("--prune", action="store_true", help="Enable high-degree pruning")
    parser.add_argument("--no-filter", action="store_true", help="Disable event filtering")
    parser.add_argument("--degree-threshold", type=int, default=5, help="Degree threshold for pruning")
    parser.add_argument("--beep", action="store_true", help="Enable BEEP edge grouping")
    parser.add_argument("--beep-window", type=int, default=2000, help="BEEP time window in ms")
    parser.add_argument("--beep-threshold", type=int, default=3, help="BEEP minimum group size")
    parser.add_argument("--no-event-compression", action="store_true", help="Disable BEEP event-level compression")
    parser.add_argument("--holmes", action="store_true", help="Enable HOLMES backward slicing")
    parser.add_argument("--both", action="store_true", help="Uses both HOLMES backward slicing and BEEP edge grouping")
    parser.add_argument("--holmes-forward", action="store_true", default=True, help="HOLMES: trace forward from alerts")
    parser.add_argument("--cli-only", action="store_true", help="CLI mode: display summary in terminal")
    parser.add_argument("--host", help="Filter by hostname of agent")
    parser.add_argument("--provenance-window", type=int, default=10, help="Minutes of context before/after the event")

    args = parser.parse_args()
    try:
        with open('/var/monitoring/config.json', 'r') as f:
            config = json.load(f)

    except FileNotFoundError:
        print("[!] Config file not found", file=sys.stderr)
        sys.exit(1)

    output_dir = config.get('output_dir', '.')
    os.makedirs(output_dir, exist_ok=True)
    for f in [args.out, args.out.replace('.dot', '.png'), args.text_out]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    try:
        es_config = config.get("es_config", {})
        analyzer = ProvenanceGraph(es_config)

        final_start = args.start
        final_end = args.end

        if args.pid or args.comm:
            found_start, found_end = analyzer.scout_activity_window(
                args.start, 
                args.end, 
                pid=args.pid, 
                comm=args.comm, 
                window_minutes=args.provenance_window,
                hostname=args.host
            )

            if found_start and found_end:
                print(f"[+] Adjusting analysis window to capture provenance context.")
                print(f"    Original: {args.start} -> {args.end}")
                print(f"    Focused:  {found_start} -> {found_end} (Target ± {args.provenance_window} min)")
                final_start = str(found_start)
                final_end = str(found_end)
            else:
                print(f"[!] Warning: Target not found in the original time range. Graph may be empty.")
                sys.exit(1)

        events = analyzer.load_events(final_start, final_end, hostname=args.host)
        if not events:
            print("[!] No events found", file=sys.stderr)
            sys.exit(1)

        # Build with context-aware filtering
        print("Building Provenance Graph...")
        analyzer.build_graph(
            events,
            enable_filtering=not args.no_filter,
            enable_event_compression=not args.no_event_compression
        )

        target_procs = []
        if args.pid:
            print(f"Searching for PID: {args.pid}")
            target_procs = analyzer.find_processes_by_pid(args.pid)
            if not target_procs:
                print(f"[!] No process found with PID '{args.pid}'")
                sys.exit(1)

        elif args.comm:
            print(f"Searching for Comm: {args.comm}")
            target_procs = analyzer.find_processes_by_name(args.comm)
            if not target_procs:
                print(f"[!] No process found named '{args.comm}'")
                sys.exit(1)

        else:
            print("[!] You must specify either --comm or --pid", file=sys.stderr)
            sys.exit(1)

        print(f"[+] Found {len(target_procs)} matching processes. Using the first one.")

        print("Generating subgraph")
        attack_subgraph = analyzer.get_attack_subgraph(
            [target_procs[0]],
            max_depth=args.depth,
            include_parents=not args.no_parents,
            include_children=not args.no_children
        )

        # Generalized filtering pipeline
        attack_subgraph = analyzer.remove_low_value_nodes(attack_subgraph, [target_procs[0]])
        attack_subgraph = analyzer.filter_temporal_window(attack_subgraph, args.start, window_hours=1)

        if args.prune:
            attack_subgraph = analyzer.prune_high_degree_files(
                attack_subgraph,
                degree_threshold=args.degree_threshold
            )

        if args.holmes:
            print("Filtering using HOLMES")
            attack_subgraph = analyzer.holmes_backward_slice(
                attack_subgraph,
                enable_forward=args.holmes_forward
            )
            attack_subgraph = analyzer.compress_structural_nodes(attack_subgraph)

        if args.beep:
            print("Filtering using BEEP")
            attack_subgraph = analyzer.beep_edge_grouping(
                attack_subgraph,
                time_window_ms=args.beep_window,
                min_group_size=args.beep_threshold
            )
            attack_subgraph = analyzer.collapse_sibling_processes(attack_subgraph)

        if args.both:
            print("Filtering using Both Algorithms")
            attack_subgraph = analyzer.holmes_backward_slice(
                attack_subgraph,
                enable_forward=args.holmes_forward
            )
            attack_subgraph = analyzer.compress_structural_nodes(attack_subgraph)
            attack_subgraph = analyzer.beep_edge_grouping(
                attack_subgraph,
                time_window_ms=args.beep_window,
                min_group_size=args.beep_threshold
            )

        attack_subgraph = analyzer.remove_benign_only_subgraphs(attack_subgraph)
        attack_subgraph = analyzer.remove_isolated_nodes(attack_subgraph)

        if attack_subgraph.number_of_nodes() > 0:
            # Run MITRE ATT&CK inference on final graph
            analyzer.infer_mitre_techniques(attack_subgraph)
            analyzer.export_to_dot(attack_subgraph, args.out, focus_nodes=[target_procs[0]])
            analyzer.export_text_summary(attack_subgraph, args.text_out)
            print(f"\n[✓] Analysis complete!")
            print(f"[✓] Final graph: {attack_subgraph.number_of_nodes()} nodes, {attack_subgraph.number_of_edges()} edges")

            if args.cli_only:
                print("\n" + "=" * 80)
                print("ATTACK SUMMARY")
                print("=" * 80)
                with open(args.text_out, 'r') as f:
                    summary_text = f.read()
                    print(summary_text)
                print("=" * 80)
                print(f"\n[i] Graph file: {args.out}")
                print(f"[i] To visualize: dot -Tpng {args.out} -o graph.png && xdg-open graph.png")
        else:
            print("[!] No attack graph generated (all nodes filtered)")
            sys.exit(1)

    except Exception as e:
        print(f"[!] Fatal error observed: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()