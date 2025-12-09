# mitre.py
"""
Simple rule-based MITRE ATT&CK inference engine.

Input:
    raw_graph   = { pid : {"events": [...], "exec_transitions": [...], "children": [...] } }
    bipartite   = normalized bipartite graph (process_nodes, file_nodes, file_edges)

Output:
    A structured list:
    [
        {
            "tid": "T1059",
            "tactic": "Execution",
            "name": "Command and Scripting Interpreter",
            "description": "...",
            "evidence": ["....", "..."]
        },
        ...
    ]
"""

import re
from ipaddress import ip_address, IPv4Address


def is_external_ip(ip):
    """Return True if IP is not in private RFC1918 ranges."""
    try:
        ip_obj = ip_address(ip)
        if isinstance(ip_obj, IPv4Address):
            # RFC1918 private ranges
            private_ranges = [
                ("10.0.0.0", "10.255.255.255"),
                ("172.16.0.0", "172.31.255.255"),
                ("192.168.0.0", "192.168.255.255"),
            ]
            for start, end in private_ranges:
                if ip_address(start) <= ip_obj <= ip_address(end):
                    return False
            return True
        return True
    except Exception:
        return False


def infer_mitre(raw_graph, bipartite):
    techniques = []

    # =============================
    #  T1059 — Command Execution
    # =============================
    suspicious_interpreters = {"bash", "sh", "python", "perl", "ruby", "pwsh"}
    exec_evidence = []
    for pid, pdata in raw_graph.items():
        for ev in pdata.get("events", []):
            comm = ev.get("comm", "")
            if comm in suspicious_interpreters:
                exec_evidence.append(f"PID {pid} executed {comm}")
        for ex in pdata.get("exec_transitions", []):
            binname = ex.get("binary", "")
            if binname:
                prog = binname.split("/")[-1]
                if prog in suspicious_interpreters:
                    exec_evidence.append(f"PID {pid} execve → {prog}")

    if exec_evidence:
        techniques.append({
            "tid": "T1059",
            "tactic": "Execution",
            "name": "Command and Scripting Interpreter",
            "description": "A scripting or shell interpreter was executed.",
            "evidence": exec_evidence
        })

    # =============================
    #  T1548 — Abuse Elevation Control Mechanisms
    # =============================
    priv_evidence = []
    for pid, pdata in raw_graph.items():
        for ev in pdata.get("events", []):
            filename = ev.get("filename", "")
            if filename == "/usr/bin/sudo":
                priv_evidence.append(f"PID {pid} invoked sudo")
            if "/etc/sudoers" in filename:
                priv_evidence.append(f"PID {pid} accessed /etc/sudoers")

    if priv_evidence:
        techniques.append({
            "tid": "T1548",
            "tactic": "Privilege Escalation",
            "name": "Abuse Elevation Control Mechanisms",
            "description": "Evidence of sudo invocation or sudoers access.",
            "evidence": priv_evidence
        })

    # =============================
    #  T1003 — Credential Access
    # =============================
    cred_evidence = []
    sensitive_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh",
        "/root/.ssh",
    ]

    for pid, pdata in raw_graph.items():
        for ev in pdata.get("events", []):
            filename = ev.get("filename", "")
            if any(p in filename for p in sensitive_patterns):
                cred_evidence.append(f"PID {pid} accessed {filename}")

    if cred_evidence:
        techniques.append({
            "tid": "T1003",
            "tactic": "Credential Access",
            "name": "OS Credential Dumping",
            "description": "Process accessed sensitive credential files.",
            "evidence": cred_evidence
        })

    # =============================
    #  T1053 — Scheduled Task / Cron Persistence
    # =============================
    pers_evidence = []
    persistence_files = [
        "/etc/cron",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/systemd/system",
        ".bashrc",
        ".profile",
    ]

    for edge in bipartite.get("file_edges", []):
        fp = edge["file"]
        if any(x in fp for x in persistence_files):
            pers_evidence.append(f"{edge['process']} modified {fp}")

    if pers_evidence:
        techniques.append({
            "tid": "T1053",
            "tactic": "Persistence",
            "name": "Cron or Startup Modification",
            "description": "Process modified cron or startup configuration.",
            "evidence": pers_evidence
        })

    # =============================
    #  T1083 — File System Discovery
    # =============================
    disc_evidence = []
    for pid, pdata in raw_graph.items():
        for ev in pdata.get("events", []):
            filename = ev.get("filename", "")
            if filename.startswith("/proc/"):
                disc_evidence.append(f"PID {pid} accessed {filename}")

    if disc_evidence:
        techniques.append({
            "tid": "T1083",
            "tactic": "Discovery",
            "name": "File System Discovery",
            "description": "Process accessed /proc extensively.",
            "evidence": disc_evidence
        })

    # =============================
    #  T1070 — Log Clearing
    # =============================
    log_evidence = []
    for edge in bipartite.get("file_edges", []):
        fp = edge["file"]
        ops = edge["operations"]
        if "/var/log" in fp and ("unlinkat" in ops or "write" in ops):
            log_evidence.append(f"{edge['process']} modified or deleted {fp}")

    if log_evidence:
        techniques.append({
            "tid": "T1070",
            "tactic": "Defense Evasion",
            "name": "Indicator Removal",
            "description": "Process modified or deleted log files.",
            "evidence": log_evidence
        })

    # =============================
    #  T1041 — Exfiltration Over C2 Channel
    # =============================
    exfil_evidence = []
    for pid, pdata in raw_graph.items():
        for ev in pdata.get("events", []):
            if ev.get("syscall") == "connect":
                ip = ev.get("dest_ip")
                port = ev.get("dest_port")
                if ip and is_external_ip(ip):
                    exfil_evidence.append(f"PID {pid} connected to {ip}:{port}")

    if exfil_evidence:
        techniques.append({
            "tid": "T1041",
            "tactic": "Exfiltration",
            "name": "Exfiltration Over Command and Control Channel",
            "description": "Process made outbound connections to external IPs.",
            "evidence": exfil_evidence
        })

    return techniques
