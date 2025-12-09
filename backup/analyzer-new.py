#!/usr/bin/env python3
"""
Simplified analyzer:

- Uses ProcessTracer to build a PID tree for a target PID or comm.
- Filters events using noise_reduce.filter_noisy_events (unless --no-filter).
- Normalizes to a bipartite graph and optionally prunes high-degree files.
- Exports DOT/PNG using exporter.py.
- Prints stats in a format consumed by provenance.py (parse_analyzer_stats).
"""

import argparse
import json
import os
import sys

from elasticsearch import Elasticsearch
import urllib3

# Local imports: assume analyzer.py sits in repo root alongside these files
from process_tracing import ProcessTracer
from noise_reduce import (
    filter_noisy_events,
    normalize_graph_for_bipartite,
    prune_high_degree_files,
    remove_trivial_processes,
)
from exporter import to_dot, to_png

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------
# Config + ES helpers
# ---------------------------------------------------------------------
def load_config():
    """
    Try to load config.json.

    1. /var/monitoring/config.json   (original path)
    2. ./config.json                 (repo root)
    """
    candidates = [
        "/var/monitoring/config.json",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"),
    ]

    for path in candidates:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)

    print("[✗] Could not find config.json in /var/monitoring or local directory.")
    sys.exit(1)


def connect_elasticsearch(es_config):
    """
    Minimal ES connector using es_config from config.json.

    Expected keys:
        es_host, es_port, es_user, es_password, use_ssl
    """
    host = es_config.get("es_host", "localhost")
    port = es_config.get("es_port", 9200)
    user = es_config.get("es_user")
    password = es_config.get("es_password")
    use_ssl = es_config.get("secure", False)

    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}"

    print(f"[+] Connecting to Elasticsearch at {url} ...")

    if user and password:
        es = Elasticsearch(
            url,
            basic_auth=(user, password),
            verify_certs=False,
        )
    else:
        es = Elasticsearch(
            url,
            verify_certs=False,
        )

    if not es.ping():
        print("[✗] Failed to connect to Elasticsearch")
        sys.exit(1)

    print("[✓] Connected to Elasticsearch")
    return es


# ---------------------------------------------------------------------
# CLI + main logic
# ---------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Simplified provenance analyzer using ProcessTracer + noise_reduce"
    )

    parser.add_argument("--start", required=True, help="Start time (epoch ms)")
    parser.add_argument("--end", required=True, help="End time (epoch ms)")

    parser.add_argument("--out", required=True, help="DOT output file path")
    parser.add_argument("--text-out", required=True, help="Text summary output path")

    parser.add_argument("--depth", type=int, default=5, help="Max process tree depth (0=root only)")
    parser.add_argument("--prune", action="store_true", help="Prune high-degree files (noise)")
    parser.add_argument("--degree-threshold", type=int, default=10, help="Degree threshold for high-degree files")

    parser.add_argument("--no-filter", action="store_true", help="Disable event-level filtering (show all events)")

    parser.add_argument("--pid", help="Target PID")
    parser.add_argument("--comm", help="Target process name (comm)")
    parser.add_argument("--host", help="Hostname / agent filter", default=None)

    return parser.parse_args()


def build_raw_graph(es, index, args):
    tracer = ProcessTracer(es, index)

    # Decide seed
    target_pid = args.pid
    target_comm = args.comm
    hostname = args.host

    if target_pid:
        try:
            pid_val = int(target_pid)
        except Exception:
            pid_val = target_pid
        print(f"[+] Tracing from PID={pid_val} (host={hostname or 'ANY'})")
        graph = tracer.trace_process(
            hostname=hostname,
            pid=pid_val,
            process=None,
            start_ms=int(args.start),
            end_ms=int(args.end),
            max_depth=args.depth,
        )
    elif target_comm:
        print(f"[+] Tracing from comm='{target_comm}' (host={hostname or 'ANY'})")
        graph = tracer.trace_process(
            hostname=hostname,
            process=target_comm,
            pid=None,
            start_ms=int(args.start),
            end_ms=int(args.end),
            max_depth=args.depth,
        )
    else:
        print("[✗] You must provide either --pid or --comm")
        sys.exit(1)

    if not graph:
        print("[!] No processes / events found for given parameters.")
        return {}

    return graph


def summarize_and_export(graph_raw, args):
    """
    Apply noise reduction / normalization and export DOT/PNG.
    Also print stats in a format that provenance.py expects.
    """
    if not graph_raw:
        print("[!] Empty graph, nothing to export.")
        return

    total_events = sum(len(v["events"]) for v in graph_raw.values())
    print(f"[+] Loaded {total_events} total events from {len(graph_raw)} processes.")

    # --- Event-level filtering ---
    if args.no_filter:
        print("[*] Event filtering is DISABLED (--no-filter).")
        filtered_graph = graph_raw
        filtered_events = total_events
        filtered_out = 0
    else:
        print("[*] Applying event-level noise filter (noise_reduce.filter_noisy_events)...")
        filtered_graph = filter_noisy_events(graph_raw)
        filtered_events = sum(len(v["events"]) for v in filtered_graph.values())
        filtered_out = total_events - filtered_events

    if total_events > 0:
        pct = (filtered_out / total_events) * 100.0
    else:
        pct = 0.0

    # Line format matched by parse_analyzer_stats()
    #   "Filtered X/Y events (Z%)"
    print(f"[+] Filtered {filtered_out}/{total_events} events ({pct:.1f}%).")

    # --- Normalize to bipartite graph ---
    print("[*] Normalizing to bipartite graph (processes + files)...")
    bipartite = normalize_graph_for_bipartite(filtered_graph)

    # Optional high-degree pruning
    if args.prune:
        print(f"[*] Pruning high-degree files (degree_threshold={args.degree_threshold})...")
        bipartite = prune_high_degree_files(bipartite, degree_threshold=args.degree_threshold)
    else:
        # Still safe to keep function available; we just don't call it
        print("[*] High-degree file pruning is DISABLED.")

    # Remove trivial processes
    print("[*] Removing trivial processes (no meaningful activity)...")
    bipartite = remove_trivial_processes(bipartite)
    from mitre import infer_mitre

    print("[*] Inferring MITRE ATT&CK techniques...")
    mitre_list = infer_mitre(graph_raw, bipartite)

    print("\n=== MITRE ATT&CK TECHNIQUE INFERENCE ===")
    for tech in mitre_list:
        print(f"- {tech['tid']} | {tech['tactic']} | {tech['name']}")
        print(f"Description: {tech['description']}")
        for ev in tech["evidence"]:
            print(f"    * {ev}")

    print("=== CHRONOLOGICAL EVENTS ===\n") 
    # Stats for final graph
    process_nodes = bipartite.get("process_nodes", {})
    file_nodes = bipartite.get("file_nodes", {})
    process_edges = bipartite.get("process_edges", [])
    exec_edges = bipartite.get("exec_edges", [])
    file_edges = bipartite.get("file_edges", [])

    total_nodes = len(process_nodes) + len(file_nodes)
    total_edges = len(process_edges) + len(exec_edges) + len(file_edges)

    # Line format matched by parse_analyzer_stats()
    #   "Final graph: N nodes, M edges"
    print(f"[+] Final graph: {total_nodes} nodes, {total_edges} edges")

    # --- Export DOT + PNG ---
    dot_path = args.out
    print(f"[*] Writing DOT to {dot_path} ...")
    to_dot(bipartite, dot_path)

    png_path = dot_path.replace(".dot", ".png")
    print(f"[*] Attempting to generate PNG at {png_path} ...")
    to_png(bipartite, png_path, dot_path)

    # --- Write simple text summary for provenance.py to show ---
    write_text_summary(args, total_events, filtered_events,
                       total_nodes, total_edges, bipartite)


def write_text_summary(args, total_events, filtered_events,
                       total_nodes, total_edges, bipartite):
    path = args.text_out
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w") as f:
        f.write("=== SIMPLE PROVENANCE SUMMARY ===\n\n")
        f.write(f"Target host: {args.host or 'ANY'}\n")
        if args.pid:
            f.write(f"Target PID: {args.pid}\n")
        if args.comm:
            f.write(f"Target comm: {args.comm}\n")
        f.write(f"Time range (epoch ms): {args.start} → {args.end}\n\n")

        f.write(f"Total events loaded: {total_events}\n")
        f.write(f"Events after filtering: {filtered_events}\n")
        if total_events > 0:
            pct_kept = (filtered_events / total_events) * 100.0
            f.write(f"Events kept: {pct_kept:.1f}%\n")
        f.write("\n")

        f.write(f"Graph nodes: {total_nodes}\n")
        f.write(f"Graph edges: {total_edges}\n")
        f.write(f"Process nodes: {len(bipartite.get('process_nodes', {}))}\n")
        f.write(f"File nodes: {len(bipartite.get('file_nodes', {}))}\n")
        f.write(f"Process edges (fork/clone): {len(bipartite.get('process_edges', []))}\n")
        f.write(f"Exec edges (same-PID transformations): {len(bipartite.get('exec_edges', []))}\n")
        f.write(f"File edges (file accesses): {len(bipartite.get('file_edges', []))}\n")
        f.write("\n")

    print(f"[✓] Text summary written: {path}")


def main():
    args = parse_args()
    config = load_config()
    es_config = config.get("es_config", {})
    es = connect_elasticsearch(es_config)

    index = (
        es_config.get("ebpf_index")
        or es_config.get("es_index")
        or "ebpf-events"
    )

    print(f"[+] Using index: {index}")

    raw_graph = build_raw_graph(es, index, args)
    summarize_and_export(raw_graph, args)


if __name__ == "__main__":
    main()
