#!/usr/bin/env python3
"""Provenance Analysis Page"""

import streamlit as st
from datetime import datetime, timedelta
import sys
import os
import subprocess
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import time
import re
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import ollama_agent
from analyzer import ProvenanceGraph

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch, to_epoch_ms

st.title("🔍 Provenance Analysis")
st.markdown("### Build Attack Provenance Graphs with AI-Powered Analysis")

# Load configuration
config = load_config()
es_config = config.get("es_config", {})
ebpf_index = es_config.get("ebpf_index", "ebpf-events")
output_dir = os.path.abspath(config.get("output_dir", "."))

# Ensure output directory exists
os.makedirs(output_dir, exist_ok=True)

# Connect to Elasticsearch
es = connect_elasticsearch(es_config)

ANALYZER_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analyzer.py")

def fetch_hostnames(es, index):
    """Return list of unique hostnames from eBPF events."""
    try:
        body = {
            "size": 0,
            "aggs": {
                "unique_hosts": {
                    "terms": {
                        "field": "hostname.keyword",
                        "size": 1000
                    }
                }
            }
        }
        result = es.search(index=index, body=body)
        buckets = result["aggregations"]["unique_hosts"]["buckets"]
        return [b["key"] for b in buckets]
    except Exception as e:
        st.error(f"Failed to fetch hostnames: {e}")
        return []

def create_interactive_graph(dot_file_path):
    """Create interactive PyVis graph from DOT file using safe non-pydot parsing."""
    if not os.path.exists(dot_file_path):
        st.error(f"DOT file not found: {dot_file_path}")
        return None

    try:
        # ---- SAFE PARSING: networkx directly ----
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

        # ---- Add nodes ----
        for node_id, attrs in graph.nodes(data=True):
            label = str(attrs.get("label", node_id)).strip('"').replace("\\n", "\n")
            tooltip = label

            node_type = (attrs.get("type") or "").strip('"')

            # Node color/shape rules
            if node_type == "process":
                color = "#4FC3F7"   # light blue
                shape = "ellipse"
            elif node_type == "file":
                color = "#FFB74D"   # orange
                shape = "box"
            elif node_type == "network":
                color = "#E57373"   # red
                shape = "diamond"
            else:
                color = "#BDBDBD"   # grey
                shape = "ellipse"

            net.add_node(
                node_id,
                label=label,
                title=tooltip,
                color=color,
                shape=shape,
                size=18
            )

        # ---- Add edges ----
        for u, v, attrs in graph.edges(data=True):
            label = attrs.get("label", "").strip('"')
            tooltip = label

            # We added "source" to edges in analyzer.py: ebpf / auditd / pcap
            edge_src = str(attrs.get("source", "ebpf")).strip('"')

            if edge_src == "auditd":
                color = "green"
                dashes = True
            elif edge_src == "pcap":
                color = "red"
                dashes = [5, 5]  # dotted style
            else:  # ebpf default
                color = "blue"
                dashes = False

            net.add_edge(
                u, v,
                label=label,
                title=tooltip,
                color=color,
                smooth={"type": "continuous"},
                dashes=dashes
            )

        for node in net.nodes:
            node_id = node['id']
            node['title'] = f"<b>{node_id}</b><br>Type: {graph.nodes[node_id].get('type','unknown')}"

        return net

    except Exception as e:
        st.error(f"Error creating interactive graph: {e}")
        return None

def parse_analyzer_stats(stdout_text):
    """Parse statistics from analyzer output"""
    stats = {
        'events_loaded': 0,
        'events_filtered': 0,
        'filter_percentage': 0,
        'nodes': 0,
        'edges': 0
    }

    for line in stdout_text.split('\n'):
        if 'Loaded' in line and 'events' in line:
            match = re.search(r'Loaded (\d+)', line)
            if match:
                stats['events_loaded'] = int(match.group(1))

        if 'Filtered' in line and '/' in line:
            match = re.search(r'Filtered (\d+)/(\d+) events \((\d+\.?\d*)%', line)
            if match:
                stats['events_filtered'] = int(match.group(1))
                stats['filter_percentage'] = float(match.group(3))

        if 'Graph built:' in line:
            match = re.search(r'(\d+) nodes, (\d+) edges', line)
            if match:
                stats['nodes'] = int(match.group(1))
                stats['edges'] = int(match.group(2))

        if 'Final graph:' in line:
            match = re.search(r'(\d+) nodes, (\d+) edges', line)
            if match:
                stats['nodes'] = int(match.group(1))
                stats['edges'] = int(match.group(2))

    return stats


def parse_mitre_from_summary(summary_text):
    """Parse MITRE ATT&CK techniques from the text summary produced by analyzer.py.

    Returns a list of dicts with keys: tid, tactic, name, description, evidence[]
    """
    if not summary_text:
        return []

    techniques = []
    current = None
    in_section = False

    for raw_line in summary_text.splitlines():
        line = raw_line.rstrip()

        # Enter section
        if line.startswith("=== MITRE ATT&CK TECHNIQUE INFERENCE"):
            in_section = True
            continue

        if not in_section:
            continue

        # Section ends when chronological events start
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

        # Description line
        if line.strip().startswith("Description:") and current:
            current["description"] = line.split("Description:", 1)[1].strip()
            continue

        # Evidence lines: "    * something"
        stripped = line.lstrip()
        if current and (stripped.startswith("* ") or stripped.startswith("- ") or stripped.startswith("• ")):
            ev = stripped[1:].strip() if stripped[1:].strip() else stripped.strip()
            if ev:
                current["evidence"].append(ev)

    if current:
        techniques.append(current)

    return techniques


# Sidebar - Time Range
st.sidebar.header("📅 Time Range")
preset = st.sidebar.selectbox("Quick Select", ["Last 1 Hour", "Last 6 Hours", "Last 12 Hours", "Last 24 Hours", "Today", "Custom"])

host_list = fetch_hostnames(es, ebpf_index)
if not host_list:
    selected_host = None
else:
    selected_host = st.sidebar.selectbox(
        "Select Host / Agent",
        options=host_list,
        index=0,
        help="Choose which agent's events to analyze"
    )

if preset == "Last 1 Hour":
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=1)
elif preset == "Last 6 Hours":
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=6)
elif preset == "Last 12 Hours":
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=12)
elif preset == "Last 24 Hours":
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=24)
elif preset == "Today":
    end_dt = datetime.now()
    start_dt = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
else:
    start_dt = datetime.now() - timedelta(hours=1)
    end_dt = datetime.now()

start_date = st.sidebar.date_input("Start Date", start_dt.date())
start_time = st.sidebar.time_input("Start Time", start_dt.time())
end_date = st.sidebar.date_input("End Date", end_dt.date())
end_time = st.sidebar.time_input("End Time", end_dt.time())

start_datetime = datetime.combine(start_date, start_time)
end_datetime = datetime.combine(end_date, end_time)
start_ms = to_epoch_ms(start_datetime)
end_ms = to_epoch_ms(end_datetime)

if start_datetime >= end_datetime:
    st.sidebar.error("Start time must be before end time!")
    st.stop()

st.markdown("---")

# Create tabs
tab1, tab2, tab3= st.tabs(["🎯 Threat Hunting", "📊 Graph Generation", "🤖 AI Analysis"])
# --- TAB 1: THREAT HUNTING ---
with tab1:
    st.subheader("🔍 Automated Threat Triage")
    st.caption("Scan the selected time range for anomalies to find a starting point.")
    top_n = st.slider("Max Threats", min_value=10, max_value=250, value=10, help="Maximum number of threat leads to return", step=10)
    if st.button("🚀 Scan for Threats", type="primary"):
        with st.spinner("Hunting for anomalies in Elasticsearch..."):
            # Initialize analyzer just for this query
            # Ensure es_config is loaded from your utils/config
            analyzer = ProvenanceGraph(es_config)
            # Run the threat hunting query (using the method we defined earlier)
            leads = analyzer.find_threat_leads(selected_host, start_ms, end_ms, top_n)
            st.session_state['threat_leads'] = leads

    if 'threat_leads' in st.session_state and st.session_state['threat_leads']:
        leads = st.session_state['threat_leads']
        st.markdown(f"### Found {len(leads)} Suspicious Leads")

        for lead in leads:
            score_color = "🔴" if lead['score'] >= 50 else "🟠"
            
            with st.expander(f"{score_color} Score {lead['score']}: {lead['comm']} (PID: {lead['pid']})"):
                c1, c2, c3 = st.columns([2, 1, 1])
                
                with c1:
                    st.markdown(f"**Reasons:** {lead['reasons']}")
                    st.markdown(f"**Events:** {lead['event_count']}")
                    st.caption(f"Last Seen: {datetime.fromtimestamp(lead['timestamp']/1000)}")

                with c2:
                    st.markdown("**Copy PID:**")
                    st.code(str(lead['pid']), language="text")

                with c3:
                    st.markdown("**Copy Command:**")
                    st.code(lead['comm'], language="bash")

    elif 'threat_leads' in st.session_state:
        st.info("✅ No high-confidence threats found in this window.")
    
with tab2:
    st.subheader("Build Attack Provenance Graph")
    st.caption("Generate focused provenance graphs with intelligent noise reduction")

    # Main controls
    col1, col2 = st.columns([1, 1])
    with col1:
        target_comm = st.text_input("Target Process Name", value="", help="Name of the suspicious process (e.g., bash, run-attack.sh)")
    with col2:
        target_pid = st.text_input("Target PID", help="PID of the suspicious process (e.g., 12345)")

    # Advanced filtering options
    with st.expander("⚙️ Advanced Filtering Options", expanded=True):
        col5, col6 = st.columns([1, 1])
        with col5:
            max_depth = st.slider("Graph Depth", min_value=1, max_value=10, value=5, help="Maximum traversal depth in the process tree")
        with col6:
            provenance_window = st.slider("Process Scope Window (minutes)", min_value=1, max_value=60, value=5, help="Maximum traversal depth in the process tree")

        col3, col4 = st.columns(2)
        with col3:
            disable_filtering = st.checkbox("Disable Event Filtering", value=False, help="Show all events (not recommended for large datasets)")

        with col4:
            prune_noise = st.checkbox("Prune High-Degree Files", value=True, help="Remove files accessed by many processes (system noise)")

        analysis_mode = st.selectbox(
            "Select Analysis Strategy",
            options=[
                "Standard",
                "HOLMES Backward Slicing",
                "BEEP Edge Grouping",
                "Both HOLMES & BEEP"
            ],
            index=0,
            help="Select a research-based algorithm to reduce graph noise."
        )

        use_holmes = "HOLMES" in analysis_mode
        use_beep = "BEEP" in analysis_mode
        use_both = "Both" in analysis_mode

    # st.sidebar.markdown("### 🔗 SPECTRA Fusion")
    enable_fusion = False #st.sidebar.checkbox("Enable Multi-Source Fusion (eBPF + PCAP + Auditd)", value=False)
    include_pcap = False #st.sidebar.checkbox("Include PCAP Network Enrichment", value=True)
    include_auditd = False #st.sidebar.checkbox("Include Auditd Semantic Edges", value=True)

    if st.button("🔍 Analyze & Build Graph", type="primary", width="stretch"):
        if not target_comm and not target_pid:
            st.error("Please enter either a Target Process Name OR a Target PID.")
            st.stop()
        if target_comm and target_pid:
            st.info("ℹ️ PID and Process Name entered. Prioritizing PID.")
            target_comm = ""

        if not os.path.exists(ANALYZER_SCRIPT_PATH):
            st.error(f"Analyzer script not found: {ANALYZER_SCRIPT_PATH}")
        else:
            target_display = target_pid if target_pid else target_comm
            with st.spinner(f"Analyzing '{target_display}'..."):
                try:
                    # Use configured output directory
                    timestamp = int(time.time())
                    TXT_OUTPUT = os.path.join(output_dir, f"attack_summary_{timestamp}.txt")
                    DOT_FILE = os.path.join(output_dir, f"provenance_attack_{timestamp}.dot")

                    cmd = [
                        "python3", ANALYZER_SCRIPT_PATH,
                        "--start", str(start_ms),
                        "--end", str(end_ms),
                        "--out", DOT_FILE,
                        "--text-out", TXT_OUTPUT,
                        "--depth", str(max_depth),
                        "--provenance-window", str(provenance_window)
                    ]

                    if prune_noise:
                        cmd.extend(["--prune", "--degree-threshold", str(5)])
                    if disable_filtering:
                        cmd.append("--no-filter")

                    # Research algorithms
                    if use_holmes:
                        cmd.append("--holmes")
                    if use_beep:
                        cmd.append("--beep")
                    if use_both:
                        cmd.append("--both")

                    if target_pid:
                        cmd.extend(["--pid", target_pid])
                    elif target_comm:
                        cmd.extend(["--comm", target_comm])

                    if selected_host:
                        cmd.extend(["--host", selected_host])

                    if enable_fusion:
                        cmd.append("--fusion")
                        if not include_pcap:
                            cmd.append("--no-pcap")
                        if not include_auditd:
                            cmd.append("--no-auditd")

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                    st.session_state['analyzer_stdout'] = result.stdout
                    st.session_state['analyzer_stderr'] = result.stderr
                    st.session_state['analyzer_stats'] = parse_analyzer_stats(result.stdout)

                    if os.path.exists(DOT_FILE) and os.path.getsize(DOT_FILE) > 0:
                        st.session_state['dot_file_path'] = DOT_FILE
                    else:
                        st.session_state['dot_file_path'] = None
                        st.warning(f"⚠️ No graph generated. Process '{target_comm if target_comm else target_pid}' might not be in the logs.")

                    if os.path.exists(TXT_OUTPUT):
                        with open(TXT_OUTPUT, 'r') as f:
                            summary_text = f.read()
                        st.session_state['text_summary'] = summary_text
                        # Parse MITRE ATT&CK techniques for UI display
                        st.session_state['mitre_techniques'] = parse_mitre_from_summary(summary_text)

                except subprocess.TimeoutExpired:
                    st.error("⏱️ Analysis timed out (>5 minutes). Try reducing the time range or graph depth.")
                    st.session_state['dot_file_path'] = None
                except Exception as e:
                    st.error(f"Error running analysis: {e}")
                    st.session_state['dot_file_path'] = None

    # Display statistics if available
    if 'analyzer_stats' in st.session_state:
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

        # MITRE ATT&CK inference summary
        if st.session_state.get('mitre_techniques'):
            st.markdown("### 🧬 MITRE ATT&CK Techniques Detected")
            mitre_list = st.session_state['mitre_techniques']

            # Create heatmap visualization
            st.markdown("#### Tactic Coverage Heatmap")

            # Define MITRE ATT&CK tactics in standard order
            all_tactics = [
                "Initial Access",
                "Execution",
                "Persistence",
                "Privilege Escalation",
                "Defense Evasion",
                "Credential Access",
                "Discovery",
                "Lateral Movement",
                "Collection",
                "Command and Control",
                "Exfiltration",
                "Impact"
            ]

            # Count techniques per tactic
            tactic_counts = {}
            technique_details = {}
            for tech in mitre_list:
                tactic = tech.get('tactic', 'Unknown')
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                if tactic not in technique_details:
                    technique_details[tactic] = []
                technique_details[tactic].append(f"{tech.get('tid', '')} - {tech.get('name', '')}")

            # Build heatmap data
            heatmap_data = []
            for tactic in all_tactics:
                count = tactic_counts.get(tactic, 0)
                heatmap_data.append({
                    'Tactic': tactic,
                    'Technique Count': count,
                    'Status': '🔴 Detected' if count > 0 else '⚪ Not Detected'
                })

            heatmap_df = pd.DataFrame(heatmap_data)

            # Create horizontal bar chart with color coding
            fig_heatmap = px.bar(
                heatmap_df,
                x='Technique Count',
                y='Tactic',
                orientation='h',
                color='Technique Count',
                color_continuous_scale='Reds',
                labels={'Technique Count': 'Techniques Detected', 'Tactic': 'MITRE ATT&CK Tactic'},
                hover_data={'Status': True}
            )
            fig_heatmap.update_layout(
                height=450,
                margin=dict(l=20, r=20, t=20, b=20),
                yaxis={'categoryorder': 'array', 'categoryarray': all_tactics[::-1]},
                showlegend=False
            )
            st.plotly_chart(fig_heatmap, width="stretch")

            # Detailed technique breakdown
            st.markdown("#### Technique Details")
            for tech in mitre_list:
                with st.expander(f"{tech['tid']} • {tech['tactic']} • {tech['name']}", expanded=False):
                    if tech.get('description'):
                        st.markdown(f"**Description:** {tech['description']}")
                    if tech.get('evidence'):
                        st.markdown("**Evidence:**")
                        for ev in tech['evidence']:
                            st.markdown(f"- {ev}")

            # Summary metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Techniques", len(mitre_list))
            with col2:
                st.metric("Tactics Covered", len(tactic_counts))
            with col3:
                highest_tactic = max(tactic_counts.items(), key=lambda x: x[1]) if tactic_counts else ("None", 0)
                st.metric("Most Active Tactic", highest_tactic[0], delta=f"{highest_tactic[1]} techniques")

        else:
            st.markdown("### 🧬 MITRE ATT&CK Techniques Detected")
            st.caption("No strong MITRE ATT&CK patterns were identified in this graph.")

    # Context-Aware Timeline (extract from analyzer stdout)
    if 'analyzer_stdout' in st.session_state:
        stdout = st.session_state['analyzer_stdout']

        # Try to extract activity window from stdout
        activity_window_match = re.search(
            r'\[.\] Target found active between ([^\n]+) and ([^\n]+)',
            stdout
        )

        if activity_window_match:
            start_time_str = activity_window_match.group(1).strip()
            end_time_str = activity_window_match.group(2).strip()

            st.markdown("---")
            st.markdown("### ⏱️ Activity Window Context")

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Window Start", start_time_str[-8:] if len(start_time_str) > 8 else start_time_str)
            with col2:
                st.metric("Window End", end_time_str[-8:] if len(end_time_str) > 8 else end_time_str)
            with col3:
                # Calculate window duration
                try:
                    start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S.%f")
                    end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S.%f")
                    duration = (end_dt - start_dt).total_seconds()
                    st.metric("Duration", f"{duration:.0f}s")
                except:
                    try:
                        start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
                        end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S")
                        duration = (end_dt - start_dt).total_seconds()
                        st.metric("Duration", f"{duration:.0f}s")
                    except:
                        st.metric("Duration", "N/A")

            st.caption("""
            📍 **Activity Window**: The time range where the target process was active,
            with padding for context. Events outside this window show the broader system state.
            """)

            # Parse chronological events from text summary
            if 'text_summary' in st.session_state:
                summary = st.session_state['text_summary']

                # Extract chronological events section
                chron_match = re.search(
                    r'=== CHRONOLOGICAL EVENTS \(GRAPH ORDER\) ===(.*?)(?:===|$)',
                    summary,
                    re.DOTALL
                )

                if chron_match:
                    chron_section = chron_match.group(1)

                    # Parse individual events (format: [HH:MM:SS] event description)
                    event_pattern = r'\[(\d{2}:\d{2}:\d{2})\]\s*(.+?)(?=\n\[|\n\n|\Z)'
                    events = re.findall(event_pattern, chron_section, re.DOTALL)

                    if events and len(events) > 1:
                        st.markdown("#### Event Timeline")

                        # Create timeline dataframe
                        timeline_data = []
                        for i, (time_str, desc) in enumerate(events):
                            # Clean up description
                            desc_clean = desc.strip().replace('\n', ' ')[:80]
                            if len(desc) > 80:
                                desc_clean += "..."

                            timeline_data.append({
                                'Time': time_str,
                                'Sequence': i + 1,
                                'Event': desc_clean
                            })

                        timeline_df = pd.DataFrame(timeline_data)

                        # Create timeline visualization
                        fig_timeline = go.Figure()

                        # Add scatter trace for events
                        fig_timeline.add_trace(go.Scatter(
                            x=timeline_df['Sequence'],
                            y=[1] * len(timeline_df),
                            mode='markers+text',
                            marker=dict(
                                size=15,
                                color=timeline_df['Sequence'],
                                colorscale='Viridis',
                                showscale=False,
                                line=dict(width=2, color='white')
                            ),
                            text=timeline_df['Time'],
                            textposition='top center',
                            hovertemplate='<b>%{text}</b><br>Event %{x}<extra></extra>',
                            showlegend=False
                        ))

                        # Add connecting line
                        fig_timeline.add_trace(go.Scatter(
                            x=timeline_df['Sequence'],
                            y=[1] * len(timeline_df),
                            mode='lines',
                            line=dict(color='rgba(100,100,100,0.3)', width=2),
                            showlegend=False,
                            hoverinfo='skip'
                        ))

                        # Update layout
                        fig_timeline.update_layout(
                            height=200,
                            margin=dict(l=20, r=20, t=40, b=20),
                            xaxis=dict(
                                title='Event Sequence',
                                showgrid=False,
                                zeroline=False
                            ),
                            yaxis=dict(
                                showticklabels=False,
                                showgrid=False,
                                zeroline=False,
                                range=[0.5, 1.5]
                            ),
                            plot_bgcolor='rgba(0,0,0,0)',
                            paper_bgcolor='rgba(0,0,0,0)'
                        )

                        st.plotly_chart(fig_timeline, width="stretch")

                        # Show event details in expandable table
                        with st.expander("📋 View Event Details", expanded=False):
                            # Create detailed table with full descriptions
                            detailed_data = []
                            for time_str, desc in events:
                                detailed_data.append({
                                    'Time': time_str,
                                    'Description': desc.strip()
                                })
                            detailed_df = pd.DataFrame(detailed_data)
                            st.dataframe(detailed_df, width="stretch", hide_index=True, height=400)

    # Display graph if available
    if st.session_state.get('dot_file_path'):
        st.markdown("---")

        # ========================================
        # SPECTRA AUTOMATED NARRATIVE SECTION
        # ========================================
        if 'text_summary' in st.session_state:
            summary_text = st.session_state['text_summary']

            # Parse SPECTRA narrative sections
            if "SPECTRA: AUTOMATED ATTACK NARRATIVE" in summary_text:
                st.markdown("## 📖 SPECTRA Attack Narrative")
                st.caption("Automated natural language analysis of the attack")

                # Extract and display executive summary
                exec_summary_match = re.search(
                    r'## Executive Summary\n\n(.+?)(?=\n##|\n====|$)',
                    summary_text,
                    re.DOTALL
                )

                if exec_summary_match:
                    exec_summary = exec_summary_match.group(1).strip()

                    # Display in an info box
                    if "🔴 CRITICAL" in exec_summary:
                        st.error(f"**Executive Summary**\n\n{exec_summary}")
                    elif "🟠 HIGH" in exec_summary:
                        st.warning(f"**Executive Summary**\n\n{exec_summary}")
                    elif "🟡 MEDIUM" in exec_summary:
                        st.info(f"**Executive Summary**\n\n{exec_summary}")
                    else:
                        st.success(f"**Executive Summary**\n\n{exec_summary}")

                # Extract evaluation metrics
                metrics_match = re.search(
                    r'SPECTRA EVALUATION METRICS REPORT(.+?)(?====|$)',
                    summary_text,
                    re.DOTALL
                )

                if metrics_match:
                    with st.expander("📊 SPECTRA Performance Metrics", expanded=False):
                        metrics_text = metrics_match.group(1)

                        # Parse key metrics
                        reduction_match = re.search(r'Reduction Percentage: ([\d.]+)%', metrics_text)
                        compression_match = re.search(r'Overall Compression:\s+([\d.]+)%', metrics_text)
                        nodes_match = re.search(r'Reduced Nodes:\s+(\d+)', metrics_text)
                        edges_match = re.search(r'Reduced Edges:\s+(\d+)', metrics_text)

                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            if reduction_match:
                                st.metric("Log Reduction", f"{reduction_match.group(1)}%")
                        with col2:
                            if compression_match:
                                st.metric("Graph Compression", f"{compression_match.group(1)}%")
                        with col3:
                            if nodes_match:
                                st.metric("Graph Nodes", nodes_match.group(1))
                        with col4:
                            if edges_match:
                                st.metric("Graph Edges", edges_match.group(1))

                        st.code(metrics_text, language="text")

                # Extract full narrative
                narrative_match = re.search(
                    r'FULL NARRATIVE\n=+\n\n(.+?)(?=\n====|$)',
                    summary_text,
                    re.DOTALL
                )

                if narrative_match:
                    with st.expander("📝 Full Attack Narrative", expanded=True):
                        narrative = narrative_match.group(1).strip()
                        st.markdown(narrative)

                st.markdown("---")

        st.markdown("### Interactive Provenance Graph")

        # Button to switch to AI tab
        if st.button("🤖 Discuss with AI Assistant", type="secondary", help="Chat with AI about this analysis"):
            st.session_state['switch_to_ai_tab'] = True
            st.session_state['ai_context_loaded'] = False
            st.switch_page("pages/provenance.py")

        dot_file = st.session_state['dot_file_path']
        interactive_graph = create_interactive_graph(dot_file)
        if interactive_graph:
            try:
                # Always normalize the output directory
                output_dir = os.path.abspath(output_dir)
                os.makedirs(output_dir, exist_ok=True)

                # PyVis cannot write to a full path; must use simple filenames.
                try:
                    temp_html_name = "provenance_graph_temp.html"

                    # Step 1: Write HTML to current working directory
                    interactive_graph.write_html(temp_html_name)

                    # Step 2: Move it to the correct output directory
                    final_html_path = os.path.join(output_dir, "provenance_graph.html")
                    final_html_path = os.path.abspath(final_html_path)
                    os.makedirs(output_dir, exist_ok=True)

                    os.replace(temp_html_name, final_html_path)

                    # Step 3: Load into Streamlit
                    with open(final_html_path, "r", encoding="utf-8") as f:
                        components.html(f.read(), height=800, scrolling=True)

                except Exception as e:
                    st.error(f"Failed to render interactive graph: {e}")

            except Exception as e:
                st.error(f"Failed to render interactive graph: {e}")

            # PNG EXPORT
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
        if 'text_summary' in st.session_state:
            with st.expander("📄 View Attack Relationships", expanded=False):
                st.text_area("Attack Chain Summary", value=st.session_state['text_summary'], height=300, label_visibility="hidden")

                # Download button
                st.download_button(
                    label="📥 Download Summary",
                    data=st.session_state['text_summary'],
                    file_name="attack_summary.txt",
                    mime="text/plain"
                )

with tab3:
    st.subheader("🤖 AI-Powered Attack Analysis")

    if 'chat_history' not in st.session_state:
        st.session_state['chat_history'] = []

    # Ollama connection
    col1, col2 = st.columns([3, 1])
    with col1:
        ollama_host = st.text_input("Ollama Host", value="http://localhost:11434", help="URL of your Ollama instance")

    is_connected, available_models_full, available_models_simple = ollama_agent.check_ollama_connection(ollama_host)

    with col2:
        if is_connected:
            st.success("✅ Connected")
        else:
            st.error("❌ Not Connected")

    # Model selection
    if available_models_full:
        selected_model = st.selectbox("Select Model", options=available_models_full)
        st.caption(f"💡 Available models: {', '.join(available_models_simple)}")
    else:
        selected_model = st.text_input("Model Name", value="llama3:latest", help="Enter model name with tag (e.g., llama3:latest)")
        if not is_connected:
            st.warning("⚠️ Ollama not connected. Start Ollama with: `ollama serve`")

    # Auto-load context when switching from Tab 1
    if 'analyzer_stats' in st.session_state or 'text_summary' in st.session_state:
        if st.session_state.get('switch_to_ai_tab') and not st.session_state.get('ai_context_loaded'):
            st.session_state['ai_context_loaded'] = True
            st.session_state['switch_to_ai_tab'] = False

            # Build context from analysis
            context_parts = ["# Attack Analysis Context\n"]

            if 'analyzer_stats' in st.session_state:
                stats = st.session_state['analyzer_stats']
                context_parts.append(f"""
## Analysis Statistics
- Events Loaded: {stats['events_loaded']:,}
- Events Filtered: {stats['events_filtered']:,} ({stats['filter_percentage']:.1f}% reduction)
- Graph Nodes: {stats['nodes']}
- Graph Edges: {stats['edges']}
                """)

            if 'text_summary' in st.session_state:
                summary = st.session_state['text_summary']
                original_length = len(summary)
                if len(summary) > 8000:
                    summary = summary[:8000] + f"\n...(truncated from {original_length} chars)"
                context_parts.append(f"\n## Attack Chain Summary\n{summary}")

            context = "\n".join(context_parts)

            # Add context as first system message
            initial_prompt = f"""
You are an expert Cyber Forensic Analyst using the MITRE ATT&CK framework.
Analyze the provided execution graph summary from an eBPF monitor.

Context:
{context}

Your Analysis Objectives:
1. **Trace the Execution Chain:** Identify the root process (Patient Zero) and the sequence of spawned processes.
2. **Identify Malicious Behaviors:** Look for ANY of the following:
   - **Collection:** Accessing sensitive files (secrets, keys, databases).
   - **C2/Exfiltration:** Network connections to non-standard ports or external IPs.
   - **Impact/Destruction:** File deletion, overwriting (ransomware behavior), or permission changes.
   - **Persistence:** Writing to startup locations (cron, init.d, .bashrc).
3. **Analyze Noise Reduction:** If you see "BEEP" (grouped events) or "HOLMES" (causal filtering), explain what repetitive or noisy behavior was compressed.

Final Output Format:
- **Attack Type:** (e.g., Exfiltration, Ransomware, Dropper, etc.)
- **Critical IOCs:** (List IPs, filenames, and PIDs)
- **Narrative:** A brief chronological story of what happened.

Based on the logs, provide your analysis."""

            # Get initial AI response
            with st.spinner("Loading attack context into AI..."):
                ai_response = ollama_agent.query_ollama(initial_prompt, model=selected_model, host=ollama_host)
                st.session_state['chat_history'] = [
                    {"role": "system", "content": context},
                    {"role": "assistant", "content": ai_response}
                ]

        # Show context loaded indicator
        with st.expander("📊 Attack Context Loaded", expanded=False):
            if 'analyzer_stats' in st.session_state:
                stats = st.session_state['analyzer_stats']
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Events", f"{stats['events_loaded']:,}")
                with col2:
                    st.metric("Filtered", f"{stats['filter_percentage']:.1f}%")
                with col3:
                    st.metric("Nodes", stats['nodes'])
                with col4:
                    st.metric("Edges", stats['edges'])

            # MITRE ATT&CK techniques (parsed from summary)
            if st.session_state.get('mitre_techniques'):
                mitre_list = st.session_state['mitre_techniques']
                st.markdown("#### 🧬 MITRE ATT&CK Techniques")
                for tech in mitre_list:
                    st.markdown(f"- **{tech['tid']}** ({tech['tactic']}) – {tech['name']}")

            if 'text_summary' in st.session_state:
                summary = st.session_state['text_summary']
                summary_length = len(summary)
                lines = summary.count('\n')
                st.caption(f"📄 Attack summary: {summary_length:,} chars, {lines} lines")

                with st.expander("View Full Attack Summary Context"):
                    st.text_area("Full Context Loaded into AI", value=summary, height=400, label_visibility="hidden")

            col_reload1, col_reload2 = st.columns(2)
            with col_reload1:
                if st.button("🔄 Reload Context"):
                    st.session_state['ai_context_loaded'] = False
                    st.session_state['switch_to_ai_tab'] = True
                    st.rerun()
            with col_reload2:
                if st.button("📋 Copy Context to Clipboard"):
                    if 'text_summary' in st.session_state:
                        st.code(st.session_state['text_summary'], language='text')

    else:
        st.info("💡 Generate a provenance graph in the 'Graph Generation' tab first, then click '🤖 Discuss with AI Assistant' to load the context here.")

    # Chat interface
    st.markdown("---")
    st.markdown("### 💬 Chat")

    # Debug toggle
    show_debug = st.checkbox("🔍 Show debug info (conversation sent to AI)", value=False)

    # Display chat history
    for message in st.session_state.get('chat_history', []):
        if message['role'] == 'system':
            continue  # Don't display system context in chat

        if message['role'] == 'user':
            with st.chat_message("user"):
                st.markdown(message['content'])
        elif message['role'] == 'assistant':
            with st.chat_message("assistant"):
                st.markdown(message['content'])

    # Chat input
    user_input = st.chat_input("Ask about the attack analysis...")
    if user_input:
        if not is_connected:
            st.error("Cannot send message: Ollama is not connected")
        else:
            # Add user message to history
            st.session_state['chat_history'].append({"role": "user", "content": user_input})

            # Build conversation context for Ollama
            conversation = ""
            for msg in st.session_state['chat_history']:
                if msg['role'] == 'system':
                    conversation += f"System Context:\n{msg['content']}\n\n"
                elif msg['role'] == 'user':
                    conversation += f"User: {msg['content']}\n\n"
                elif msg['role'] == 'assistant':
                    conversation += f"Assistant: {msg['content']}\n\n"

            conversation += f"User: {user_input}\n\nAssistant:"

            # Show debug info if enabled
            if show_debug:
                with st.expander("🔍 Debug: Full Conversation Sent to AI", expanded=False):
                    st.text_area("Conversation", value=conversation, height=300, label_visibility="hidden")
                    st.caption(f"Total length: {len(conversation):,} chars")

            # Get AI response
            with st.spinner("Thinking..."):
                ai_response = ollama_agent.query_ollama(conversation, model=selected_model, host=ollama_host)

            # Add AI response to history
            st.session_state['chat_history'].append({"role": "assistant", "content": ai_response})

            # Rerun to display new messages
            st.rerun()

    # Clear chat button
    if st.session_state.get('chat_history'):
        col1, col2 = st.columns([6, 1])
        with col2:
            if st.button("🗑️ Clear Chat"):
                st.session_state['chat_history'] = []
                st.session_state['ai_context_loaded'] = False
                st.rerun()
