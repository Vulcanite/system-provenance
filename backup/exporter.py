#/usr/bin/env python3

def to_dot(graph, filename="provenance.dot"):
    """
    Export bipartite graph to DOT format.
    Processes are shown as boxes, files as document shapes (leaves).
    Exec transformations are shown as separate nodes connected by exec edges.

    Args:
        graph: Dictionary with 'process_nodes', 'file_nodes', 'process_edges', 'exec_edges', 'file_edges'
        filename: Output filename
    """
    process_nodes = graph["process_nodes"]
    file_nodes = graph["file_nodes"]
    process_edges = graph["process_edges"]
    exec_edges = graph.get("exec_edges", [])
    file_edges = graph["file_edges"]

    with open(filename, "w") as f:
        f.write("digraph G {\n")
        f.write("  rankdir=LR;\n")  # Left to right layout
        f.write("  node [fontsize=10, fontname=\"Arial\"];\n")
        f.write("  edge [fontsize=8, fontname=\"Arial\"];\n\n")

        # Write process nodes
        f.write("  // Process nodes\n")
        for node_id, node in process_nodes.items():
            comm = node["comm"].replace("\"", "'")
            actual_pid = node["pid"]  # Use the actual PID from node data
            has_network = bool(node.get("network"))

            # Determine node color based on activity
            if has_network:
                color = "#ffcccc"  # Light red for network activity
                shape = "box"
            else:
                color = "#ccccff"  # Light blue for processes
                shape = "box"

            # Build label - use actual PID, not node_id
            label_parts = [f"{comm}"]
            label_parts.append(f"PID: {actual_pid}")

            # Add network info
            if has_network:
                net_ops = ", ".join(set(node["network"]))
                label_parts.append(f"🌐 {net_ops}")

                # Add connection details (IP:port)
                connections = node.get("network_connections", [])
                if connections:
                    for conn in connections[:3]:  # Show up to 3 connections
                        label_parts.append(f"→ {conn}")

            label = "\\n".join(label_parts)

            # Use node_id for internal graph structure, but show actual PID in label
            f.write(f'  "proc_{node_id}" [label="{label}", style=filled, fillcolor="{color}", shape={shape}];\n')

        f.write("\n")

        # Write file nodes (as leaves)
        f.write("  // File nodes\n")
        for filepath, node in file_nodes.items():
            # Escape special characters for DOT
            safe_path = filepath.replace("\"", "'").replace("\\", "\\\\")
            # Get just the filename for display
            filename_only = filepath.split("/")[-1] if "/" in filepath else filepath

            # File nodes are green documents
            label = f"📄 {filename_only}\\n{filepath}"

            f.write(f'  "file_{hash(filepath)}" [label="{label}", style=filled, fillcolor="#ccffcc", shape=note, fontsize=9];\n')

        f.write("\n")

        # Write exec transformation edges
        f.write("  // Exec transformations (same PID, different program)\n")
        for edge in exec_edges:
            from_node = edge["from"]
            to_node = edge["to"]
            f.write(f'  "proc_{from_node}" -> "proc_{to_node}" [label="exec", color="#FF6600", penwidth=2, style=bold];\n')

        f.write("\n")

        # Write process-to-process edges (parent-child)
        f.write("  // Process relationships (fork/clone)\n")
        for edge in process_edges:
            parent = edge["parent"]
            child = edge["child"]
            f.write(f'  "proc_{parent}" -> "proc_{child}" [color="#333333", penwidth=2];\n')

        f.write("\n")

        # Write process-to-file edges
        f.write("  // File access relationships\n")
        for edge in file_edges:
            process = edge["process"]
            filepath = edge["file"]
            operations = edge["operations"]

            # Edge label shows operation type
            label = operations if len(operations) < 30 else operations[:27] + "..."

            f.write(f'  "proc_{process}" -> "file_{hash(filepath)}" [label="{label}", color="#999999", style=dashed, fontsize=7];\n')

        f.write("}\n")

    print(f"[✓] DOT file written: {filename}")
    return filename


def to_png(graph, output_file="provenance_graph.png", dot_file=None):
    """
    Generate PNG from bipartite graph using graphviz.

    Args:
        graph: Dictionary with 'process_nodes', 'file_nodes', etc.
        output_file: Output PNG filename
        dot_file: Intermediate DOT file (optional, will be temp if not specified)
    """
    import subprocess

    if dot_file is None:
        dot_file = output_file.replace('.png', '.dot')

    # Generate DOT file
    to_dot(graph, dot_file)

    # Convert to PNG using dot command
    try:
        subprocess.run(['dot', '-Tpng', dot_file, '-o', output_file], check=True)
        print(f"[✓] PNG generated: {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"[✗] Error generating PNG: {e}")
        print("Make sure graphviz is installed: sudo apt-get install graphviz")
        return None
    except FileNotFoundError:
        print("[✗] 'dot' command not found. Install graphviz: sudo apt-get install graphviz")
        return None
