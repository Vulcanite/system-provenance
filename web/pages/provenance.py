#!/usr/bin/env python3
"""Provenance Analysis Page"""

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import json
import sys
import os
import subprocess
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import tempfile
import pydot
import time
import re
import ollama_agent

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch, to_epoch_ms

st.title("🔍 Provenance Analysis")
st.markdown("### Build Attack Provenance Graphs with AI-Powered Analysis")

# Load configuration
config = load_config()
es_config = config.get("es_config", {})
ebpf_index = es_config.get("ebpf_index", "ebpf-events")
output_dir = config.get("output_dir", ".")

# Ensure output directory exists
os.makedirs(output_dir, exist_ok=True)

# Connect to Elasticsearch
es = connect_elasticsearch(es_config)

ANALYZER_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analyzer.py")

def create_interactive_graph(dot_file_path):
    """Create interactive PyVis graph from DOT file"""
    if not os.path.exists(dot_file_path):
        return None

    try:
        pydot_graphs = pydot.graph_from_dot_file(dot_file_path)
        if not pydot_graphs:
            return None

        graph = nx.DiGraph(nx.nx_pydot.from_pydot(pydot_graphs[0]))
        net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)
        net.set_options("""
        {
          "nodes": {"font": {"size": 14}},
          "edges": {"color": {"inherit": true}, "smooth": {"type": "continuous"}, "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}}},
          "physics": {"enabled": true, "stabilization": {"iterations": 200}, "barnesHut": {"gravitationalConstant": -8000, "centralGravity": 0.3, "springLength": 150, "springConstant": 0.04}},
          "interaction": {"hover": true, "tooltipDelay": 100, "navigationButtons": true, "keyboard": true}
        }
        """)

        for node_id in graph.nodes():
            node_attrs = graph.nodes[node_id]

            label = node_attrs.get('label', node_id).strip('"').replace('\\n', '\n')

            fillcolor = node_attrs.get('fillcolor', 'lightblue').strip('"')
            shape = node_attrs.get('shape', 'box').strip('"')

            shape_map = {'box': 'box', 'note': 'box', 'diamond': 'diamond', 'ellipse': 'ellipse'}
            pyvis_shape = shape_map.get(shape, 'box')

            # Color mapping
            color_map = {
                'lightblue': '#40A8D1',    # Process (suspicious)
                '#40A8D1': '#40A8D1',
                '#AAAAAA': '#888888',      # Process (benign)
                'red': '#D14040',          # Sensitive file
                '#D14040': '#D14040',
                'orange': '#D18C40',       # Downloads/tmp
                '#D18C40': '#D18C40',
                'yellow': '#D1D140',
                '#D1D140': '#D1D140',
                'lightgray': '#CCCCCC',    # Normal file
                '#CCCCCC': '#CCCCCC',
                'pink': '#FF69B4',         # Network
                '#FF69B4': '#FF69B4',
                '#A8D1A0': '#A8D1A0'       # Network (green)
            }
            color = color_map.get(fillcolor, fillcolor)

            penwidth = node_attrs.get('penwidth', '1.0').strip('"')
            is_focus = float(penwidth) > 2.0

            tooltip = node_attrs.get('tooltip', label).strip('"').replace('\\n', '\n')

            net.add_node(
                node_id, label=label, title=tooltip, color=color, shape=pyvis_shape,
                size=30 if is_focus else 20, borderWidth=4 if is_focus else 2, borderWidthSelected=6
            )

        for u, v in graph.edges():
            edge_attrs = graph.edges[u, v]
            edge_label = edge_attrs.get('label', '').strip('"')
            edge_color = edge_attrs.get('color', 'gray').strip('"')
            tooltip = edge_attrs.get('tooltip', edge_label).strip('"')
            net.add_edge(u, v, label=edge_label, title=tooltip, color=edge_color)

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

# Sidebar - Time Range
st.sidebar.header("📅 Time Range")
preset = st.sidebar.selectbox("Quick Select", ["Last 1 Hour", "Last 24 Hours", "Today", "Custom"])

if preset == "Last 1 Hour":
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=1)
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
tab1, tab2 = st.tabs(["📊 Graph Generation", "🤖 AI Analysis"])

with tab1:
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
        col1, col2 = st.columns(2)
        with col1:
            disable_filtering = st.checkbox("Disable Event Filtering", value=False, help="Show all events (not recommended for large datasets)")

        with col2:
            prune_noise = st.checkbox("Prune High-Degree Files", value=False, help="Remove files accessed by many processes (system noise)")

        analysis_mode = st.selectbox(
            "Select Analysis Strategy",
            options=[
                "Standard",
                "BEEP Edge Grouping"
            ],
            index=0,
            help="Select a research-based algorithm to reduce graph noise."
        )

        use_beep = "BEEP" in analysis_mode

    if st.button("🔍 Analyze & Build Graph", type="primary", use_container_width=True):
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
                        "--depth", str(5)
                    ]

                    if prune_noise:
                        cmd.extend(["--prune", "--degree-threshold", str(5)])
                    if disable_filtering:
                        cmd.append("--no-filter")
                    if use_beep:
                        cmd.append("--beep")
                    if target_pid:
                        cmd.extend(["--pid", target_pid])
                    elif target_comm:
                        cmd.extend(["--comm", target_comm])

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
                            st.session_state['text_summary'] = f.read()

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

    # Display graph if available
    if st.session_state.get('dot_file_path'):
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
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                interactive_graph.save_graph(f.name)
                with open(f.name, 'r', encoding='utf-8') as html_file:
                    source_code = html_file.read()
                components.html(source_code, height=800, scrolling=True)
                os.unlink(f.name)

            # PNG export option
            png_file = dot_file.replace(".dot", ".png")
            try:
                if not os.path.exists(png_file):
                    subprocess.run(["dot", "-Tpng", dot_file, "-o", png_file],
                                    check=True, timeout=30, capture_output=True)

                if os.path.exists(png_file):
                    with open(png_file, 'rb') as f:
                        st.download_button(
                            label="📥 Download PNG Image",
                            data=f.read(),
                            file_name=os.path.basename(png_file),
                            mime="image/png"
                        )
            except Exception as e:
                st.warning(f"PNG generation unavailable: {e}")
        else:
            st.error("Failed to create interactive graph.")

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

with tab2:
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
