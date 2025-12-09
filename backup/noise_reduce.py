#!/usr/bin/env python3

from collections import defaultdict
import json

# Syscalls that are typically noise and can be filtered
NOISY_SYSCALLS = {'read', 'write', 'close', 'fstat', 'stat', 'lseek', 'mmap', 'munmap', 'brk', 'access'}

# Files that are typically noise (system libraries, configs)
NOISY_FILES_PATTERNS = [
    '/lib/', '/usr/lib/', '/etc/ld.so', '.so',
    '/proc/', '/sys/', '/dev/null', '/dev/urandom', '/dev/tty', '/dev/ptmx',
    '/usr/share/locale', '/usr/share/zoneinfo',
    # Common system configs (noise)
    '/etc/nsswitch.conf', '/etc/group',  # Removed /etc/passwd and /etc/shadow (security-sensitive!)
    '/etc/hosts', '/etc/host.conf', '/etc/resolv.conf',
    '/etc/localtime', '/etc/locale', '/etc/environment',
    # PAM configs (usually noise unless specifically investigating auth)
    '/etc/pam.d/', '/etc/security/',
    # Sudo configs (can be commented out if investigating privilege escalation)
    '/etc/sudo.conf', '/etc/.pwd.lock',
    # Runtime state
    '/var/run/', '/run/',
    # Home directory admin files
    '.sudo_as_admin_successful', '.curlrc', '.bashrc', '.profile'
]

def is_noisy_file(filename):
    """Check if a file is typically noise."""
    if not filename:
        return True
    for pattern in NOISY_FILES_PATTERNS:
        if pattern in filename:
            return True
    return False

def filter_noisy_events(graph):
    """
    Filter out noisy events from each PID's event list.
    Keep only meaningful events: exec, meaningful file ops, network ops.
    """
    filtered_graph = {}

    for pid, data in graph.items():
        filtered_events = []

        for event in data['events']:
            syscall = event.get('syscall', '')
            filename = event.get('filename', '')

            # Always keep process events (exec, clone)
            if syscall in ['execve', 'clone', 'fork', 'vfork']:
                filtered_events.append(event)
                continue

            # Keep network events
            if syscall in ['socket', 'connect', 'bind', 'listen', 'accept', 'sendto', 'recvfrom']:
                filtered_events.append(event)
                continue

            # Keep file modification events (not just reads)
            if syscall in ['unlinkat', 'renameat', 'mkdir', 'rmdir', 'chmod', 'chown']:
                if not is_noisy_file(filename):
                    filtered_events.append(event)
                continue

            # Keep openat for non-library files
            if syscall == 'openat' and not is_noisy_file(filename):
                filtered_events.append(event)
                continue

        # Only keep PIDs that have meaningful events or children
        if filtered_events or data.get('children') or data.get('exec_transitions'):
            filtered_graph[pid] = {
                'events': filtered_events,
                'exec_transitions': data.get('exec_transitions', []),
                'children': data.get('children', [])
            }

    return filtered_graph

def normalize_graph_for_bipartite(graph):
    """
    Transform the graph into a bipartite format with separate process and file nodes.
    Creates separate nodes for each exec transformation to show process evolution.

    Returns:
        {
            "process_nodes": {node_id: {...}},  # node_id can be "pid" or "pid_exec_N"
            "file_nodes": {filepath: {...}},
            "process_edges": [(parent, child), ...],
            "exec_edges": [(from_node, to_node), ...],  # exec transformations
            "file_edges": [(node_id, filepath, operation), ...]
        }
    """
    normalized = {
        "process_nodes": {},
        "file_nodes": {},
        "process_edges": [],
        "exec_edges": [],
        "file_edges": []
    }

    # Map from PID to its final node_id (after all execs)
    pid_to_final_node = {}

    # Build process nodes with exec transformations
    for pid, data in graph.items():
        # Get initial command
        initial_comm = None
        if data.get('events') and data['events']:
            initial_comm = data['events'][0].get('comm', '')

        # Collect network operations with connection details for the entire PID
        network_ops = []
        network_connections = []  # Store IP:port details

        for e in data['events']:
            syscall = e.get('syscall', '')
            if syscall in ['socket', 'connect', 'bind', 'listen', 'accept', 'sendto', 'recvfrom']:
                network_ops.append(syscall)

                # Capture connection details for connect/bind
                if syscall in ['connect', 'bind']:
                    dest_ip = e.get('dest_ip', '')
                    dest_port = e.get('dest_port', '')
                    if dest_ip and dest_port:
                        conn_str = f"{dest_ip}:{dest_port}"
                        if conn_str not in network_connections:
                            network_connections.append(conn_str)

        network_ops = list(set(network_ops))

        # Check if we have exec transitions
        exec_transitions = data.get('exec_transitions', [])

        if exec_transitions:
            # Create separate nodes for each exec state
            current_node_id = pid
            previous_node_id = None

            # First node: initial state (before first exec)
            # exec_transition structure:
            #   - new_comm: what the process was called BEFORE exec
            #   - binary: what was executed (what it becomes AFTER)
            first_exec = exec_transitions[0]
            pre_exec_comm = first_exec.get('new_comm', '')  # What it was before

            # Use new_comm as the initial state
            first_state_comm = pre_exec_comm or f'PID-{pid}'

            # Always create initial state node for exec chains
            normalized["process_nodes"][current_node_id] = {
                "pid": pid,  # Actual PID (not node_id)
                "comm": first_state_comm,
                "network": [],
                "network_connections": [],  # No connections in initial state
                "exec_transitions": [],
                "event_count": 0,
                "is_exec_state": True,
                "exec_state": 0
            }
            previous_node_id = current_node_id

            # Create nodes for each exec transition
            for idx, exec_trans in enumerate(exec_transitions, 1):
                new_comm = exec_trans.get('new_comm', '')  # What it was before (not used for final state)
                binary_path = exec_trans.get('binary', '')  # What it executed (becomes this)

                # Extract meaningful name from the binary that was executed
                if binary_path:
                    binary_name = binary_path.split('/')[-1]
                    display_comm = binary_name if binary_name else f'PID-{pid}'
                else:
                    display_comm = f'PID-{pid}'

                # Create new node for this exec state
                current_node_id = f"{pid}_exec_{idx}"

                # Last exec state gets network ops and event count
                is_final = (idx == len(exec_transitions))

                normalized["process_nodes"][current_node_id] = {
                    "pid": pid,  # Always the actual PID (not node_id)
                    "comm": display_comm or f'PID-{pid}',
                    "network": network_ops if is_final else [],
                    "network_connections": network_connections if is_final else [],
                    "exec_transitions": [],
                    "event_count": len(data['events']) if is_final else 0,
                    "is_exec_state": True,
                    "exec_state": idx
                }

                # Add exec edge from previous to current
                normalized["exec_edges"].append({
                    "from": previous_node_id,
                    "to": current_node_id,
                    "type": "exec"
                })

                previous_node_id = current_node_id

            # Remember the final node for this PID
            pid_to_final_node[pid] = current_node_id

        else:
            # No exec transitions, single node
            normalized["process_nodes"][pid] = {
                "pid": pid,
                "comm": initial_comm or f'PID-{pid}',
                "network": network_ops,
                "network_connections": network_connections,
                "exec_transitions": [],
                "event_count": len(data['events']),
                "is_exec_state": False
            }
            pid_to_final_node[pid] = pid

        # Collect file operations for this process
        # File edges connect from the FINAL node (after all execs)
        final_node = pid_to_final_node[pid]

        file_ops = defaultdict(list)
        for event in data['events']:
            filename = event.get('filename', '')
            syscall = event.get('syscall', '')

            if filename and not is_noisy_file(filename):
                if syscall in ['openat', 'unlinkat', 'renameat', 'mkdir', 'rmdir', 'chmod', 'chown', 'read', 'write']:
                    file_ops[filename].append(syscall)

        # Create file nodes and edges
        for filepath, operations in file_ops.items():
            # Create file node if it doesn't exist
            if filepath not in normalized["file_nodes"]:
                normalized["file_nodes"][filepath] = {
                    "path": filepath,
                    "accessed_by": []
                }

            # Add this process to the file's access list
            normalized["file_nodes"][filepath]["accessed_by"].append(pid)

            # Create edge from FINAL node to file
            op_summary = ", ".join(sorted(set(operations)))
            normalized["file_edges"].append({
                "process": final_node,  # Use final node after all execs
                "file": filepath,
                "operations": op_summary
            })

    # Build process-to-process edges from children relationships
    # Connect parent's FINAL node to child's FIRST node
    for pid, data in graph.items():
        children = data.get('children', [])
        if isinstance(children, set):
            children = list(children)

        for child in children:
            child_str = str(child)
            # Only add edge if both parent and child exist in filtered graph
            if pid in pid_to_final_node and child_str in graph:
                # Parent's final node → child's first node
                parent_final = pid_to_final_node[pid]
                # Child's first node is just the PID (before any execs)
                child_first = child_str

                normalized["process_edges"].append({
                    "parent": parent_final,
                    "child": child_first
                })

    # Also infer edges from PPID in events (backup method)
    for pid, data in graph.items():
        ppid_set = set()
        for event in data['events']:
            if 'ppid' in event:
                ppid_set.add(str(event['ppid']))

        for ppid in ppid_set:
            if ppid in pid_to_final_node and pid in graph:
                ppid_final = pid_to_final_node[ppid]
                child_first = pid

                edge = {"parent": ppid_final, "child": child_first}
                # Only add if not already present
                if edge not in normalized["process_edges"]:
                    normalized["process_edges"].append(edge)

    # Deduplicate process edges
    unique_edges = []
    seen = set()
    for edge in normalized["process_edges"]:
        key = (edge["parent"], edge["child"])
        if key not in seen:
            seen.add(key)
            unique_edges.append(edge)
    normalized["process_edges"] = unique_edges

    return normalized

def collapse_identical_siblings(graph):
    """
    Collapse multiple children with identical behavior.
    Returns modified graph with collapsed nodes marked.
    """
    process_nodes = graph["process_nodes"]
    process_edges = graph["process_edges"]
    file_edges = graph["file_edges"]

    # Group children by parent and their signature
    parent_children = defaultdict(lambda: defaultdict(list))

    for edge in process_edges:
        parent = edge["parent"]
        child = edge["child"]

        if child in process_nodes:
            # Create signature based on node properties and file access
            child_files = sorted([fe["file"] for fe in file_edges if fe["process"] == child])
            sig = json.dumps({
                'comm': process_nodes[child]['comm'],
                'network': sorted(process_nodes[child].get('network', [])),
                'files': child_files[:3]  # First 3 files
            }, sort_keys=True)

            parent_children[parent][sig].append(child)

    # Create new edges, collapsing identical children
    new_edges = []
    collapsed_count = {}

    for parent, sig_groups in parent_children.items():
        for sig, children in sig_groups.items():
            if len(children) == 1:
                new_edges.append({"parent": parent, "child": children[0]})
            else:
                # Keep first child as representative
                rep = children[0]
                new_edges.append({"parent": parent, "child": rep})

                # Mark how many were collapsed
                collapsed_count[rep] = len(children)

    # Update node labels for collapsed nodes
    for pid, count in collapsed_count.items():
        if pid in process_nodes:
            original_comm = process_nodes[pid]['comm']
            process_nodes[pid]['comm'] = f"{original_comm} (×{count})"
            process_nodes[pid]['collapsed_count'] = count

    graph["process_edges"] = new_edges
    return graph

def remove_trivial_processes(graph):
    """
    Remove processes that have no meaningful activity:
    - No network operations
    - No file operations
    - No children
    Note: Preserves exec transformation chains
    """
    process_nodes = graph["process_nodes"]
    process_edges = graph["process_edges"]
    exec_edges = graph.get("exec_edges", [])
    file_edges = graph["file_edges"]

    # Find nodes with children
    nodes_with_children = set(e["parent"] for e in process_edges)

    # Find nodes that access files
    nodes_with_files = set(e["process"] for e in file_edges)

    # Find nodes that are part of exec chains
    nodes_in_exec_chain = set()
    for edge in exec_edges:
        nodes_in_exec_chain.add(edge["from"])
        nodes_in_exec_chain.add(edge["to"])

    # Keep only meaningful nodes
    meaningful_nodes = {}
    for node_id, node in process_nodes.items():
        has_activity = (
            node.get('network') or
            node_id in nodes_with_files or
            node_id in nodes_with_children or
            node_id in nodes_in_exec_chain or  # Keep all nodes in exec chains
            node.get('event_count', 0) > 0
        )

        if has_activity:
            meaningful_nodes[node_id] = node

    # Keep only edges between meaningful nodes
    meaningful_process_edges = [
        e for e in process_edges
        if e["parent"] in meaningful_nodes and e["child"] in meaningful_nodes
    ]

    meaningful_exec_edges = [
        e for e in exec_edges
        if e["from"] in meaningful_nodes and e["to"] in meaningful_nodes
    ]

    meaningful_file_edges = [
        e for e in file_edges
        if e["process"] in meaningful_nodes
    ]

    # Remove file nodes that are no longer referenced
    referenced_files = set(e["file"] for e in meaningful_file_edges)
    meaningful_file_nodes = {
        path: node for path, node in graph["file_nodes"].items()
        if path in referenced_files
    }

    graph["process_nodes"] = meaningful_nodes
    graph["file_nodes"] = meaningful_file_nodes
    graph["process_edges"] = meaningful_process_edges
    graph["exec_edges"] = meaningful_exec_edges
    graph["file_edges"] = meaningful_file_edges

    return graph

def prune_high_degree_files(graph, degree_threshold=10):
    """
    Remove file nodes accessed by too many processes (likely system noise).
    Keeps security-sensitive files regardless of access count.

    Args:
        degree_threshold: Files accessed by more than this many processes are removed
    """
    file_nodes = graph["file_nodes"]
    file_edges = graph["file_edges"]

    # Security-sensitive files to always keep
    SECURITY_SENSITIVE_FILES = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']

    # Count how many processes access each file
    file_access_counts = defaultdict(int)
    for edge in file_edges:
        file_access_counts[edge["file"]] += 1

    # Keep only low-degree files OR security-sensitive files
    low_degree_files = {}
    for filepath, node in file_nodes.items():
        is_security_sensitive = any(sensitive in filepath for sensitive in SECURITY_SENSITIVE_FILES)
        is_low_degree = file_access_counts[filepath] <= degree_threshold

        if is_low_degree or is_security_sensitive:
            low_degree_files[filepath] = node

    # Keep only edges to low-degree files
    low_degree_edges = [
        e for e in file_edges
        if e["file"] in low_degree_files
    ]

    removed_count = len(file_nodes) - len(low_degree_files)
    if removed_count > 0:
        print(f"      Pruned {removed_count} high-degree files (>{degree_threshold} accesses)")
        # Show if we kept security-sensitive files
        kept_security = [f for f in low_degree_files.keys()
                        if any(s in f for s in SECURITY_SENSITIVE_FILES)]
        if kept_security:
            print(f"      Kept security-sensitive: {', '.join([f.split('/')[-1] for f in kept_security])}")

    graph["file_nodes"] = low_degree_files
    graph["file_edges"] = low_degree_edges

    return graph

def reduce_noise(raw_graph, degree_threshold=10):
    """
    Apply all noise reduction steps and create bipartite graph.

    Args:
        raw_graph: Dictionary with PIDs as keys, each containing events, exec_transitions, children
        degree_threshold: Remove files accessed by more than this many processes (default: 10)

    Returns:
        Bipartite graph with separate process and file nodes
    """
    print(f"[1/6] Original graph: {len(raw_graph)} PIDs")

    # Step 1: Filter noisy events
    graph = filter_noisy_events(raw_graph)
    print(f"[2/6] After filtering noisy events: {len(graph)} PIDs")

    # Step 2: Normalize to bipartite graph format
    graph = normalize_graph_for_bipartite(graph)
    print(f"[3/6] Normalized: {len(graph['process_nodes'])} process nodes, {len(graph['file_nodes'])} file nodes")
    print(f"      Process edges: {len(graph['process_edges'])}, File edges: {len(graph['file_edges'])}")

    # Step 3: Prune high-degree files (accessed by many processes = noise)
    graph = prune_high_degree_files(graph, degree_threshold)
    print(f"[4/6] After pruning high-degree files: {len(graph['file_nodes'])} files, {len(graph['file_edges'])} file edges")

    # Step 4: Remove trivial processes
    graph = remove_trivial_processes(graph)
    print(f"[5/6] After removing trivial: {len(graph['process_nodes'])} processes, {len(graph['file_nodes'])} files")

    # Step 5: Collapse identical siblings (optional - can comment out if you want all nodes)
    # graph = collapse_identical_siblings(graph)
    # print(f"[6/6] After collapsing siblings: {len(graph['process_nodes'])} processes")

    print(f"[6/6] Noise reduction complete!")

    return graph
