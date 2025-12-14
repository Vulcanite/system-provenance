#!/usr/bin/env python3
"""
Offline Forensic Analysis - Parse auditd raw logs and build provenance graphs
Uses the same ProvenanceGraph analyzer as the live eBPF system.
"""

import streamlit as st
import sys
import os
import time
import subprocess
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import load_config
from auditd_normalizer import parse_auditd_logs
from analyzer import ProvenanceGraph

st.set_page_config(page_title="Offline Forensics", page_icon="🔬", layout="wide")

st.title("🔬 Offline Forensic Analysis")
st.markdown("### Upload auditd logs and build attack provenance graphs")
st.markdown("Uses the same noise reduction algorithms (HOLMES & BEEP) as the live eBPF system.")

# Load config
config = load_config()
es_config = config.get("es_config", {})
output_dir = os.path.abspath(config.get("output_dir", "."))
os.makedirs(output_dir, exist_ok=True)

# Session state initialization
if 'ecs_events' not in st.session_state:
    st.session_state['ecs_events'] = []
if 'dot_file_path' not in st.session_state:
    st.session_state['dot_file_path'] = None
if 'text_summary' not in st.session_state:
    st.session_state['text_summary'] = None
if 'analyzer_stats' not in st.session_state:
    st.session_state['analyzer_stats'] = {}
if 'mitre_techniques' not in st.session_state:
    st.session_state['mitre_techniques'] = []

def create_interactive_graph(dot_file_path):
    """Create interactive PyVis graph from DOT file (same as provenance.py)"""
    if not os.path.exists(dot_file_path):
        st.error(f"DOT file not found: {dot_file_path}")
        return None

    try:
        graph = nx.drawing.nx_pydot.read_dot(dot_file_path)
        graph = nx.DiGraph(graph)

        net = Network(
            height="750px",
            width="100%",
            bgcolor="#222222",
            font_color="white",
            directed=True
        )

        net.set_options("""
        {
          "nodes": {"font": {"size": 14}},
          "edges": {"color": {"inherit": true},
                    "smooth": {"type": "continuous"},
                    "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}}},
          "physics": {"enabled": true,
                      "stabilization": {"iterations": 200},
                      "barnesHut": {"gravitationalConstant": -8000,
                                    "centralGravity": 0.3,
                                    "springLength": 150,
                                    "springConstant": 0.04}},
          "interaction": {"hover": true,
                          "tooltipDelay": 100,
                          "navigationButtons": true,
                          "keyboard": true}
        }
        """)

        # Add nodes
        for node_id, attrs in graph.nodes(data=True):
            label = str(attrs.get("label", node_id)).strip('"').replace("\\n", "\n")
            tooltip = label
            fillcolor = str(attrs.get("fillcolor", "#CCCCCC")).strip('"')
            shape = attrs.get("shape", "box")

            net.add_node(
                node_id,
                label=label,
                title=tooltip,
                color=fillcolor,
                shape=shape,
                size=18
            )

        # Add edges
        for u, v, attrs in graph.edges(data=True):
            label = attrs.get("label", "").strip('"')
            tooltip = label
            color = attrs.get("color", "gray").strip('"')
            net.add_edge(u, v, label=label, title=tooltip, color=color)

        return net

    except Exception as e:
        st.error(f"Error creating interactive graph: {e}")
        return None

def parse_mitre_from_summary(summary_text):
    """Parse MITRE ATT&CK techniques from text summary (same as provenance.py)"""
    if not summary_text:
        return []

    techniques = []
    current = None
    in_section = False

    for raw_line in summary_text.splitlines():
        line = raw_line.rstrip()

        if line.startswith("=== MITRE ATT&CK TECHNIQUE INFERENCE"):
            in_section = True
            continue

        if not in_section:
            continue

        if line.startswith("=== CHRONOLOGICAL EVENTS"):
            break

        if not line.strip():
            continue

        # Technique line: "- T1059 | Execution | Command and Scripting Interpreter"
        if line.startswith("- "):
            body = line[2:]
            parts = [p.strip() for p in body.split("|")]
            tid = parts[0] if len(parts) > 0 else ""
            tactic = parts[1] if len(parts) > 1 else ""
            name = parts[2] if len(parts) > 2 else ""

            if current:
                techniques.append(current)

            current = {
                "tid": tid,
                "tactic": tactic,
                "name": name,
                "description": "",
                "evidence": [],
            }
            continue

        if line.strip().startswith("Description:") and current:
            current["description"] = line.split("Description:", 1)[1].strip()
            continue

        stripped = line.lstrip()
        if current and (stripped.startswith("* ") or stripped.startswith("- ") or stripped.startswith("• ")):
            ev = stripped[1:].strip() if stripped[1:].strip() else stripped.strip()
            if ev:
                current["evidence"].append(ev)

    if current:
        techniques.append(current)

    return techniques

# ===== FILE UPLOAD =====
st.markdown("## 📁 Upload Auditd Raw Logs")

log_file = st.file_uploader(
    "Upload auditd log file (e.g., /var/log/audit/audit.log)",
    type=['log', 'txt', 'audit'],
    help="Raw auditd log file in standard Linux audit format"
)

if log_file:
    st.success(f"✅ Uploaded: {log_file.name} ({log_file.size:,} bytes)")

    with st.expander("⚙️ Parsing Options", expanded=True):
        col1, col2, col3 = st.columns(3)

        with col1:
            max_lines = st.number_input(
                "Max lines to process",
                min_value=1000,
                max_value=1000000,
                value=50000,
                step=5000,
                help="Limit for large log files"
            )

        with col2:
            event_filter = st.text_input(
                "Event type filter (optional)",
                placeholder="e.g., SYSCALL,EXECVE,PATH",
                help="Comma-separated audit event types"
            )

        with col3:
            hostname = st.text_input(
                "Hostname",
                value="forensic-analysis",
                help="Hostname to use for events"
            )

    if st.button("🔄 Parse Auditd Logs", type="primary"):
        with st.spinner("Parsing auditd logs and normalizing to ECS..."):
            try:
                # Read log file
                content = log_file.getvalue().decode('utf-8', errors='ignore')

                # Parse event type filter
                event_filters = [f.strip().upper() for f in event_filter.split(',')] if event_filter else None

                # Progress tracking
                progress_bar = st.progress(0)
                status_text = st.empty()

                status_text.text("Parsing auditd logs...")
                progress_bar.progress(0.3)

                # Parse and normalize to ECS
                ecs_events = parse_auditd_logs(
                    content,
                    hostname=hostname,
                    max_lines=max_lines,
                    event_type_filter=event_filters
                )

                progress_bar.progress(1.0)
                status_text.text(f"✅ Parsed {len(ecs_events)} ECS-normalized events!")

                st.session_state['ecs_events'] = ecs_events

                if ecs_events:
                    st.success(f"✅ Normalized {len(ecs_events)} audit events to ECS format")

                    # Quick stats
                    col1, col2, col3, col4 = st.columns(4)

                    with col1:
                        st.metric("Total Events", f"{len(ecs_events):,}")

                    with col2:
                        syscalls = set(e.get('syscall') for e in ecs_events if e.get('syscall'))
                        st.metric("Unique Syscalls", len(syscalls))

                    with col3:
                        pids = set(e.get('process.pid') for e in ecs_events if e.get('process.pid'))
                        st.metric("Unique PIDs", len(pids))

                    with col4:
                        timestamps = [e['timestamp'] for e in ecs_events if 'timestamp' in e]
                        if timestamps:
                            duration = (max(timestamps) - min(timestamps)) / 1000.0
                            st.metric("Time Span", f"{duration:.1f}s")

                    # Show sample
                    with st.expander("📋 Sample ECS Events"):
                        st.json(ecs_events[:3])

                else:
                    st.error("No valid audit events found in log file")

            except Exception as e:
                st.error(f"Error parsing logs: {e}")
                import traceback
                st.text(traceback.format_exc())

# ===== PROVENANCE GRAPH BUILDING =====
if st.session_state['ecs_events']:
    st.markdown("---")
    st.markdown("## 🕸️ Build Provenance Graph")
    st.caption("Uses the same ProvenanceGraph analyzer as the live eBPF system")

    col1, col2 = st.columns([1, 1])

    with col1:
        target_comm = st.text_input(
            "Target Process Name (optional)",
            value="",
            help="Focus graph on specific process (e.g., bash, suspicious-script.sh)"
        )

    with col2:
        target_pid = st.text_input(
            "Target PID (optional)",
            help="Focus graph on specific PID"
        )

    with st.expander("⚙️ Graph Analysis Options", expanded=True):
        col3, col4 = st.columns(2)

        with col3:
            max_depth = st.slider(
                "Graph Depth",
                min_value=1,
                max_value=10,
                value=5,
                help="Maximum traversal depth in the process tree"
            )

        with col4:
            disable_filtering = st.checkbox(
                "Disable Event Filtering",
                value=False,
                help="Show all events (not recommended for large datasets)"
            )

        col5, col6 = st.columns(2)

        with col5:
            prune_noise = st.checkbox(
                "Prune High-Degree Files",
                value=True,
                help="Remove files accessed by many processes"
            )

        with col6:
            degree_threshold = st.number_input(
                "Degree Threshold",
                min_value=3,
                max_value=20,
                value=5,
                help="Degree threshold for pruning"
            )

        analysis_mode = st.selectbox(
            "Select Analysis Strategy",
            options=[
                "Standard",
                "HOLMES Backward Slicing",
                "BEEP Edge Grouping",
                "Both HOLMES & BEEP"
            ],
            index=3,  # Default to both
            help="Select noise reduction algorithm"
        )

        use_holmes = "HOLMES" in analysis_mode
        use_beep = "BEEP" in analysis_mode
        use_both = "Both" in analysis_mode

    if st.button("🔬 Build Provenance Graph", type="primary"):
        with st.spinner("Building provenance graph from auditd events..."):
            try:
                # Initialize analyzer (same as live system)
                analyzer = ProvenanceGraph(es_config)
                events = st.session_state['ecs_events']

                progress_bar = st.progress(0)
                status_text = st.empty()

                # Build graph using analyzer.py logic
                status_text.text("Building provenance graph...")
                analyzer.build_graph(
                    events,
                    enable_filtering=not disable_filtering,
                    enable_event_compression=False  # BEEP is applied at graph level
                )
                progress_bar.progress(0.4)

                # Get subgraph if target specified
                if target_comm or target_pid:
                    status_text.text("Extracting target subgraph...")

                    if target_pid:
                        target_procs = analyzer.find_processes_by_pid(target_pid)
                    else:
                        target_procs = analyzer.find_processes_by_name(target_comm)

                    if not target_procs:
                        st.error(f"Process not found: {target_pid or target_comm}")
                    else:
                        attack_subgraph = analyzer.get_attack_subgraph(
                            [target_procs[0]],
                            max_depth=max_depth,
                            include_parents=True,
                            include_children=True
                        )
                        analyzer.graph = attack_subgraph

                progress_bar.progress(0.6)

                # Apply noise reduction algorithms
                if prune_noise:
                    status_text.text("Pruning high-degree files...")
                    analyzer.graph = analyzer.prune_high_degree_files(
                        analyzer.graph,
                        degree_threshold=degree_threshold
                    )

                if use_holmes:
                    status_text.text("Applying HOLMES backward slicing...")
                    analyzer.graph = analyzer.holmes_backward_slice(
                        analyzer.graph,
                        enable_forward=True
                    )
                    analyzer.graph = analyzer.compress_structural_nodes(analyzer.graph)
                    progress_bar.progress(0.75)

                if use_beep:
                    status_text.text("Applying BEEP edge grouping...")
                    analyzer.graph = analyzer.beep_edge_grouping(
                        analyzer.graph,
                        time_window_ms=2000,
                        min_group_size=3
                    )
                    analyzer.graph = analyzer.collapse_sibling_processes(analyzer.graph)
                    progress_bar.progress(0.85)

                if use_both:
                    status_text.text("Applying combined HOLMES + BEEP...")
                    analyzer.graph = analyzer.remove_benign_only_subgraphs(analyzer.graph)

                analyzer.graph = analyzer.remove_isolated_nodes(analyzer.graph)

                progress_bar.progress(0.95)

                # Infer MITRE ATT&CK techniques
                status_text.text("Inferring MITRE ATT&CK techniques...")
                analyzer.infer_mitre_techniques(analyzer.graph)

                # Export to files
                timestamp = int(time.time())
                DOT_FILE = os.path.join(output_dir, f"offline_provenance_{timestamp}.dot")
                TXT_OUTPUT = os.path.join(output_dir, f"offline_summary_{timestamp}.txt")

                if analyzer.graph.number_of_nodes() > 0:
                    focus_nodes = target_procs if (target_comm or target_pid) and target_procs else None
                    analyzer.export_to_dot(analyzer.graph, DOT_FILE, focus_nodes=focus_nodes)
                    analyzer.export_text_summary(analyzer.graph, TXT_OUTPUT)

                    # Read summary for MITRE parsing
                    with open(TXT_OUTPUT, 'r') as f:
                        summary_text = f.read()

                    st.session_state['dot_file_path'] = DOT_FILE
                    st.session_state['text_summary'] = summary_text
                    st.session_state['mitre_techniques'] = parse_mitre_from_summary(summary_text)
                    st.session_state['analyzer_stats'] = {
                        'events_loaded': len(events),
                        'events_filtered': analyzer.filtered_events,
                        'filter_percentage': (analyzer.filtered_events / len(events) * 100) if len(events) > 0 else 0,
                        'nodes': analyzer.graph.number_of_nodes(),
                        'edges': analyzer.graph.number_of_edges()
                    }

                    progress_bar.progress(1.0)
                    status_text.text("✅ Provenance graph built successfully!")

                else:
                    st.error("Graph is empty after filtering. Try disabling filters or changing target.")

            except Exception as e:
                st.error(f"Graph building failed: {e}")
                import traceback
                st.text(traceback.format_exc())

    # Display statistics
    if st.session_state.get('analyzer_stats'):
        stats = st.session_state['analyzer_stats']

        st.markdown("---")
        st.markdown("### Analysis Statistics")
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Events Loaded", f"{stats['events_loaded']:,}")

        with col2:
            if stats['events_filtered'] > 0:
                st.metric("Events Filtered", f"{stats['events_filtered']:,}",
                         delta=f"-{stats['filter_percentage']:.1f}%")
            else:
                st.metric("Events Filtered", "0")

        with col3:
            st.metric("Graph Nodes", f"{stats['nodes']}")

        with col4:
            st.metric("Graph Edges", f"{stats['edges']}")

        # MITRE ATT&CK techniques
        if st.session_state.get('mitre_techniques'):
            st.markdown("### 🧬 MITRE ATT&CK Techniques Detected")
            mitre_list = st.session_state['mitre_techniques']
            for tech in mitre_list:
                with st.expander(f"{tech['tid']} • {tech['tactic']} • {tech['name']}", expanded=False):
                    if tech.get('description'):
                        st.markdown(f"**Description:** {tech['description']}")
                    if tech.get('evidence'):
                        st.markdown("**Evidence:**")
                        for ev in tech['evidence']:
                            st.markdown(f"- {ev}")
        else:
            st.markdown("### 🧬 MITRE ATT&CK Techniques Detected")
            st.caption("No strong MITRE ATT&CK patterns identified")

    # Display interactive graph
    if st.session_state.get('dot_file_path'):
        st.markdown("---")
        st.markdown("### Interactive Provenance Graph")

        dot_file = st.session_state['dot_file_path']
        interactive_graph = create_interactive_graph(dot_file)

        if interactive_graph:
            try:
                temp_html_name = "offline_graph_temp.html"
                interactive_graph.write_html(temp_html_name)

                final_html_path = os.path.join(output_dir, "offline_provenance_graph.html")
                os.replace(temp_html_name, final_html_path)

                with open(final_html_path, "r", encoding="utf-8") as f:
                    components.html(f.read(), height=800, scrolling=True)

            except Exception as e:
                st.error(f"Failed to render interactive graph: {e}")

            # PNG export
            png_file = dot_file.replace(".dot", ".png")
            try:
                if not os.path.exists(png_file):
                    subprocess.run(
                        ["dot", "-Tpng", dot_file, "-o", png_file],
                        check=True,
                        timeout=60,
                        capture_output=True
                    )

                if os.path.exists(png_file):
                    with open(png_file, "rb") as f:
                        st.download_button(
                            label="📥 Download PNG Image",
                            data=f.read(),
                            file_name=os.path.basename(png_file),
                            mime="image/png"
                        )

            except Exception as e:
                st.warning(f"PNG generation unavailable: {e}")

        # Text summary
        if st.session_state.get('text_summary'):
            with st.expander("📄 View Attack Analysis", expanded=False):
                st.text_area(
                    "Attack Chain Summary",
                    value=st.session_state['text_summary'],
                    height=300,
                    label_visibility="hidden"
                )

                st.download_button(
                    label="📥 Download Summary",
                    data=st.session_state['text_summary'],
                    file_name="offline_attack_summary.txt",
                    mime="text/plain"
                )

else:
    if not st.session_state['ecs_events']:
        st.info("👆 Upload an auditd log file to begin offline forensic analysis")

st.markdown("---")
st.caption("*Offline Forensic Analysis - Uses the same provenance analysis algorithms as live eBPF monitoring*")
