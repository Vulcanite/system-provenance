#!/usr/bin/env python3
"""
Generate provenance graph from trace_output.json with noise reduction.
Creates a bipartite graph with processes and files as separate nodes.
"""

import json
import urllib3
from exporter import to_dot, to_png
from elasticsearch import Elasticsearch
from process_tracing import ProcessTracer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEX = "ebpf-events"

es = Elasticsearch(
    "https://139.59.247.254:9200",
    basic_auth=("elastic", "HUor6PC1eO3=q2-A9Fr2"),
    verify_certs=False,
)

def make_json_safe(obj):
    """Recursively convert all non-JSON-serializable objects into JSON-safe formats."""
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, tuple):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, set):
        return [make_json_safe(v) for v in obj]
    else:
        return obj

def main():
    COMMAND = "nginx"
    tracer = ProcessTracer(es, INDEX)
    graph = tracer.trace_process("student-VirtualBox", COMMAND)
    print(f"Total processes traced: {len(graph)}\n")

    safe_graph = make_json_safe(graph)
    with open("trace_output.json", "w") as f:
        json.dump(safe_graph, f, indent=2)

    print("=" * 60)
    print("  Provenance Graph Generator with Noise Reduction")
    print("  Bipartite Graph: Processes + Files")
    print("=" * 60)
    print()

    total_events = sum(len(v['events']) for v in safe_graph.values())
    print(f"[✓] Loaded {len(safe_graph)} PIDs with {total_events:,} total events")
    print()

    # Apply noise reduction
    print("[*] Applying noise reduction...")
    #reduced_graph = reduce_noise(safe_graph)
    reduced_graph = safe_graph
    print()

    # Export to DOT
    print("[*] Generating DOT file...")
    dot_file = to_dot(reduced_graph, f"attack_{COMMAND}.dot")
    print()

    # Try to generate PNG
    print("[*] Generating PNG visualization...")
    png_file = to_png(reduced_graph, f"attack_{COMMAND}.png", f"attack_{COMMAND}.dot")
    print()

    # Save reduced graph as JSON for streamlit
    print("[*] Saving reduced graph for streamlit...")
    with open("reduced_graph.json", "w") as f:
        json.dump(reduced_graph, f, indent=2)

    print("[✓] Saved reduced_graph.json")
    print()

    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"Original: {len(safe_graph)} processes, {total_events:,} events")
    print(f"Reduced:  {len(reduced_graph['process_nodes'])} process nodes (includes exec states)")
    print(f"Files:    {len(reduced_graph['file_nodes'])} file nodes")
    print(f"Edges:    {len(reduced_graph['process_edges'])} process relationships (fork/clone)")
    print(f"          {len(reduced_graph.get('exec_edges', []))} exec transformations (same PID)")
    print(f"          {len(reduced_graph['file_edges'])} file access operations")
    print()

    # Print graph summary
    print("Process Summary:")
    for pid, node in list(reduced_graph["process_nodes"].items())[:10]:
        # Count files accessed by this process
        file_count = len([e for e in reduced_graph["file_edges"] if e["process"] == pid])

        print(f"  PID {pid}: {node['comm']}")
        if file_count > 0:
            print(f"    Files accessed: {file_count}")
        if node.get('network'):
            print(f"    Network: {', '.join(node['network'])}")

    if len(reduced_graph["process_nodes"]) > 10:
        print(f"  ... and {len(reduced_graph['process_nodes']) - 10} more processes")

    print()
    print("File Summary (top 10):")
    # Count how many processes access each file
    file_access_counts = {}
    for filepath in reduced_graph["file_nodes"].keys():
        count = len([e for e in reduced_graph["file_edges"] if e["file"] == filepath])
        file_access_counts[filepath] = count

    # Sort by access count
    sorted_files = sorted(file_access_counts.items(), key=lambda x: x[1], reverse=True)

    for filepath, count in sorted_files[:10]:
        filename = filepath.split("/")[-1] if "/" in filepath else filepath
        print(f"  {filename}: accessed by {count} process(es)")
        print(f"    Path: {filepath}")

if __name__ == "__main__":
    main()
