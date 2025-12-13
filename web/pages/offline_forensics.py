#!/usr/bin/env python3
"""
Offline Forensic Analysis - Parse auditd raw logs and build provenance graphs
"""

import streamlit as st
import json
import sys
import os
from datetime import datetime
import plotly.graph_objects as go
import networkx as nx

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import ProvenanceGraph
from narrative_gen import generate_narrative_from_analysis
from utils import load_config

st.set_page_config(page_title="Offline Forensics", page_icon="🔬", layout="wide")

st.title("🔬 Offline Forensic Analysis")
st.markdown("### Parse auditd logs and build provenance graphs")

# Session state
if 'events' not in st.session_state:
    st.session_state['events'] = []
if 'graph_builder' not in st.session_state:
    st.session_state['graph_builder'] = None
if 'narrative' not in st.session_state:
    st.session_state['narrative'] = None

# Load config
config = load_config()
es_config = config.get("es_config", {})

# ===== FILE UPLOAD =====
st.markdown("## 📁 Upload Auditd Raw Logs")

log_file = st.file_uploader(
    "Upload auditd log file",
    type=['log', 'txt', 'audit'],
    help="Raw auditd log file (e.g., /var/log/audit/audit.log)"
)

if log_file:
    st.success(f"✅ Uploaded: {log_file.name} ({log_file.size:,} bytes)")

    # Processing options
    with st.expander("⚙️ Processing Options", expanded=True):
        col1, col2 = st.columns(2)

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
                placeholder="e.g., EXECVE,SYSCALL,CONNECT",
                help="Comma-separated event types to include"
            )

    if st.button("🔄 Parse & Build Graph", type="primary"):
        with st.spinner("Parsing auditd logs..."):
            try:
                # Read log file
                content = log_file.getvalue().decode('utf-8', errors='ignore')
                lines = content.split('\n')

                # Parse auditd raw format
                events = []
                current_event_id = None
                current_event = {}

                event_filters = [f.strip().upper() for f in event_filter.split(',')] if event_filter else []

                progress_bar = st.progress(0)
                status_text = st.empty()

                for idx, line in enumerate(lines[:max_lines]):
                    if idx % 1000 == 0:
                        progress = min(idx / min(len(lines), max_lines), 1.0)
                        progress_bar.progress(progress)
                        status_text.text(f"Processing line {idx:,} of {min(len(lines), max_lines):,}")

                    if not line.strip() or line.startswith('#'):
                        continue

                    # Parse auditd line: type=TYPE msg=audit(timestamp:sequence): key=value ...
                    if 'type=' in line and 'msg=audit' in line:
                        try:
                            # Extract type
                            type_start = line.find('type=') + 5
                            type_end = line.find(' ', type_start)
                            event_type = line[type_start:type_end]

                            # Apply filter
                            if event_filters and event_type not in event_filters:
                                continue

                            # Extract timestamp and sequence
                            if 'msg=audit(' in line:
                                msg_start = line.find('msg=audit(') + 10
                                msg_end = line.find(')', msg_start)
                                ts_seq = line[msg_start:msg_end]
                                timestamp, sequence = ts_seq.split(':')

                                event_id = f"{timestamp}:{sequence}"

                                # New event
                                if event_id != current_event_id:
                                    if current_event:
                                        events.append(current_event)
                                    current_event_id = event_id
                                    current_event = {
                                        'type': event_type,
                                        'timestamp': float(timestamp),
                                        'sequence': sequence,
                                        '@timestamp': datetime.fromtimestamp(float(timestamp)).isoformat()
                                    }

                                # Extract key-value pairs
                                kv_part = line[msg_end+2:] if msg_end+2 < len(line) else ""

                                # Parse fields
                                import re
                                # Match key=value or key="value"
                                pattern = r'(\w+)=(?:"([^"]*)"|(\S+))'
                                matches = re.findall(pattern, kv_part)

                                for key, quoted_val, unquoted_val in matches:
                                    value = quoted_val if quoted_val else unquoted_val
                                    current_event[key] = value

                        except Exception as e:
                            continue

                # Add last event
                if current_event:
                    events.append(current_event)

                progress_bar.progress(1.0)
                status_text.text(f"✅ Parsing complete!")

                st.session_state['events'] = events

                if events:
                    st.success(f"✅ Parsed {len(events)} audit events")

                    # Quick stats
                    col1, col2, col3, col4 = st.columns(4)

                    with col1:
                        st.metric("Total Events", f"{len(events):,}")

                    with col2:
                        event_types = set(e.get('type') for e in events if e.get('type'))
                        st.metric("Event Types", len(event_types))

                    with col3:
                        pids = set(e.get('pid') for e in events if e.get('pid'))
                        st.metric("Unique PIDs", len(pids))

                    with col4:
                        timestamps = [e['timestamp'] for e in events if 'timestamp' in e]
                        if timestamps:
                            duration = max(timestamps) - min(timestamps)
                            st.metric("Time Span", f"{duration:.1f}s")

                    # Show sample
                    with st.expander("📋 Sample Events"):
                        st.json(events[:5])

                else:
                    st.error("No valid audit events found in log file")

            except Exception as e:
                st.error(f"Error parsing logs: {e}")
                import traceback
                st.text(traceback.format_exc())

# ===== PROVENANCE GRAPH BUILDING =====
if st.session_state['events']:
    st.markdown("---")
    st.markdown("## 🕸️ Build Provenance Graph")

    col1, col2 = st.columns(2)

    with col1:
        generate_narrative = st.checkbox("Generate Attack Narrative", value=True)

    with col2:
        visualize_graph = st.checkbox("Visualize Graph", value=True)

    if st.button("🔬 Build Provenance Graph", type="primary"):
        with st.spinner("Building provenance graph from events..."):
            try:
                # Create graph builder
                graph_builder = ProvenanceGraph(es_config)
                events = st.session_state['events']

                # Process events into graph
                progress_bar = st.progress(0)
                status_text = st.empty()

                process_nodes = {}
                file_nodes = set()
                network_nodes = set()

                for idx, event in enumerate(events):
                    if idx % 100 == 0:
                        progress = idx / len(events)
                        progress_bar.progress(progress)
                        status_text.text(f"Processing event {idx:,} of {len(events):,}")

                    event_type = event.get('type', '')
                    pid = event.get('pid')
                    ppid = event.get('ppid')
                    comm = event.get('comm', '')
                    exe = event.get('exe', '')

                    # Track processes
                    if pid:
                        proc_id = f"pid_{pid}"
                        if proc_id not in process_nodes:
                            process_nodes[proc_id] = {
                                'pid': pid,
                                'comm': comm,
                                'exe': exe,
                                'type': 'process'
                            }
                            graph_builder.graph.add_node(proc_id, **process_nodes[proc_id])

                        # Parent-child relationship
                        if ppid and ppid != pid:
                            parent_id = f"pid_{ppid}"
                            if parent_id not in process_nodes:
                                process_nodes[parent_id] = {
                                    'pid': ppid,
                                    'type': 'process'
                                }
                                graph_builder.graph.add_node(parent_id, **process_nodes[parent_id])

                            if not graph_builder.graph.has_edge(parent_id, proc_id):
                                graph_builder.graph.add_edge(parent_id, proc_id, relation='spawned')

                    # File operations
                    if event_type in ['EXECVE', 'PATH', 'OPENAT', 'OPEN']:
                        file_path = event.get('name', event.get('a0', ''))
                        if file_path and file_path not in ['/dev/null', '/dev/urandom'] and pid:
                            # Clean up hex encoding if present
                            if all(c in '0123456789ABCDEFabcdef' for c in file_path.replace('/', '')):
                                try:
                                    file_path = bytes.fromhex(file_path.replace('/', '')).decode('utf-8', errors='ignore')
                                except:
                                    pass

                            if file_path and len(file_path) < 200:
                                file_nodes.add(file_path)
                                graph_builder.graph.add_node(file_path, type='file', path=file_path)

                                proc_id = f"pid_{pid}"
                                if event_type == 'EXECVE':
                                    graph_builder.graph.add_edge(proc_id, file_path, relation='executed')
                                else:
                                    graph_builder.graph.add_edge(proc_id, file_path, relation='accessed')

                    # Network operations
                    if event_type in ['SOCKADDR', 'CONNECT']:
                        saddr = event.get('saddr', '')
                        if saddr and pid:
                            # Parse socket address (simplified)
                            if 'sin_addr' in saddr:
                                # Extract IP from saddr
                                import re
                                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', saddr)
                                if ip_match:
                                    dest_ip = ip_match.group()
                                    net_node = f"net_{dest_ip}"
                                    network_nodes.add(net_node)

                                    graph_builder.graph.add_node(net_node, type='network', ip=dest_ip)

                                    proc_id = f"pid_{pid}"
                                    graph_builder.graph.add_edge(proc_id, net_node, relation='connected')

                progress_bar.progress(1.0)
                status_text.text("✅ Graph construction complete!")

                st.session_state['graph_builder'] = graph_builder

                # Display stats
                st.success("✅ Provenance graph built successfully!")

                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("Total Nodes", graph_builder.graph.number_of_nodes())
                with col2:
                    st.metric("Total Edges", graph_builder.graph.number_of_edges())
                with col3:
                    st.metric("Process Nodes", len(process_nodes))
                with col4:
                    st.metric("File Nodes", len(file_nodes))

                # Generate narrative
                if generate_narrative:
                    with st.spinner("Generating narrative..."):
                        try:
                            narrative_result = generate_narrative_from_analysis(
                                graph=graph_builder.graph,
                                events=events[:1000],
                                stats={
                                    'total_events': len(events),
                                    'processes': len(process_nodes),
                                    'files': len(file_nodes),
                                    'network': len(network_nodes)
                                }
                            )
                            # Handle both string and tuple returns
                            if isinstance(narrative_result, tuple):
                                narrative = narrative_result[0]  # First element is usually the narrative
                            else:
                                narrative = str(narrative_result)

                            st.session_state['narrative'] = narrative
                        except Exception as e:
                            st.warning(f"Narrative generation failed: {e}")

            except Exception as e:
                st.error(f"Graph building failed: {e}")
                import traceback
                st.text(traceback.format_exc())

# ===== NARRATIVE DISPLAY =====
if st.session_state.get('narrative'):
    st.markdown("---")
    st.markdown("## 📖 Attack Narrative")

    st.markdown(st.session_state['narrative'])

    st.download_button(
        label="📥 Download Narrative",
        data=st.session_state['narrative'],
        file_name=f"narrative_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )

# ===== GRAPH VISUALIZATION =====
if st.session_state.get('graph_builder') and visualize_graph:
    st.markdown("---")
    st.markdown("## 🗺️ Provenance Graph Visualization")

    G = st.session_state['graph_builder'].graph

    if G.number_of_nodes() > 0:
        # Limit graph size
        max_nodes = st.slider("Max nodes to display", 10, 200, 50, 10)

        if G.number_of_nodes() > max_nodes:
            # Get most connected nodes
            degrees = dict(G.degree())
            top_nodes = sorted(degrees.keys(), key=lambda x: degrees[x], reverse=True)[:max_nodes]
            G_viz = G.subgraph(top_nodes).copy()
            st.info(f"Showing top {max_nodes} most connected nodes (out of {G.number_of_nodes()} total)")
        else:
            G_viz = G.copy()

        # Layout
        pos = nx.spring_layout(G_viz, k=0.5, iterations=50)

        # Create plotly figure
        edge_x = []
        edge_y = []
        for edge in G_viz.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines'
        )

        # Nodes
        node_x = []
        node_y = []
        node_text = []
        node_color = []

        for node in G_viz.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)

            # Label
            if str(node).startswith('pid_'):
                node_data = G_viz.nodes[node]
                label = node_data.get('comm', node)[:20]
            else:
                label = str(node)[:30]
            node_text.append(label)

            # Color by type
            node_data = G_viz.nodes[node]
            node_type = node_data.get('type', 'unknown')
            if node_type == 'process':
                node_color.append(0)
            elif node_type == 'file':
                node_color.append(1)
            elif node_type == 'network':
                node_color.append(2)
            else:
                node_color.append(3)

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=node_text,
            textposition="top center",
            marker=dict(
                size=10,
                color=node_color,
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(
                    title="Node Type",
                    tickvals=[0, 1, 2, 3],
                    ticktext=['Process', 'File', 'Network', 'Other']
                )
            ),
            hoverinfo='text'
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title=f'Provenance Graph ({G_viz.number_of_nodes()} nodes, {G_viz.number_of_edges()} edges)',
                showlegend=False,
                hovermode='closest',
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=600
            )
        )

        st.plotly_chart(fig, use_container_width=True)

        # Export graph
        st.markdown("### 📥 Export Graph")

        col1, col2 = st.columns(2)

        with col1:
            # Export as GraphML
            import io
            buffer = io.StringIO()
            nx.write_graphml(G, buffer)
            st.download_button(
                "Download GraphML",
                data=buffer.getvalue(),
                file_name=f"graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.graphml",
                mime="application/xml"
            )

        with col2:
            # Export events as JSON
            events_json = json.dumps(st.session_state['events'], indent=2)
            st.download_button(
                "Download Events JSON",
                data=events_json,
                file_name=f"events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

else:
    if not st.session_state['events']:
        st.info("👆 Upload an auditd log file to begin")

st.markdown("---")
st.caption("*Offline Forensic Analysis - Parse auditd logs and build provenance graphs*")
