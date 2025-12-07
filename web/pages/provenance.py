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

        # ---- Add edges ----
        for u, v, attrs in graph.edges(data=True):
            label = attrs.get("label", "").strip('"')
            tooltip = label
            color = attrs.get("color", "gray").strip('"')

            net.add_edge(u, v, label=label, title=tooltip, color=color)

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

    # Fetch hostnames dynamically
    host_list = fetch_hostnames(es, ebpf_index)

    if not host_list:
        st.warning("No hostname information found in Elasticsearch.")
        selected_host = None
    else:
        selected_host = st.selectbox(
            "Select Host / Agent",
            options=host_list,
            index=0,
            help="Choose which agent's events to analyze"
        )

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

                    print(cmd)
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

                    print(cmd)
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    print(result)
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
            st.caption("No strong MITRE ATT&CK patterns were identified in this graph.")

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
