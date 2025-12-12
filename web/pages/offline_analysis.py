#!/usr/bin/env python3
"""Offline PCAP Analysis - Network Traffic Visualization"""

import streamlit as st
import pandas as pd
import json
import sys
import os
from datetime import datetime

import tempfile
import subprocess
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

st.title("📊 Offline Forensic Analysis")
st.markdown("### Network Traffic (PCAP) & System Audit (auditd) Analysis")

# Session state
if 'pcap_flows' not in st.session_state:
    st.session_state['pcap_flows'] = None
if 'auditd_events' not in st.session_state:
    st.session_state['auditd_events'] = None

# Main upload section
st.markdown("## 🌐 PCAP File Upload")

pcap_file = st.file_uploader(
    "Upload PCAP file",
    type=['pcap', 'pcapng'],
    help="Network packet capture file (.pcap or .pcapng format)"
)

if pcap_file:
    st.success(f"✅ Uploaded: {pcap_file.name} ({pcap_file.size:,} bytes)")

    # Processing options
    with st.expander("⚙️ PCAP Processing Options", expanded=False):
        col1, col2 = st.columns(2)

        with col1:
            bpf_filter = st.text_input(
                "BPF Filter (optional)",
                placeholder="e.g., tcp port 443 or host 8.8.8.8",
                help="Berkeley Packet Filter expression to filter traffic"
            )

        with col2:
            max_packets = st.number_input(
                "Max packets to process",
                min_value=100,
                max_value=1000000,
                value=50000,
                step=5000,
                help="Limit for large files (prevents memory issues)"
            )

    if st.button("🔄 Process PCAP File", type="primary", width="stretch"):
        with st.spinner("Parsing PCAP file with tshark..."):
            # Save uploaded file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_pcap:
                tmp_pcap.write(pcap_file.getvalue())
                tmp_pcap_path = tmp_pcap.name

            try:
                # Use tshark to parse PCAP
                cmd = [
                    'tshark', '-r', tmp_pcap_path,
                    '-T', 'json',
                    '-c', str(max_packets)
                ]

                if bpf_filter:
                    cmd.extend(['-Y', bpf_filter])

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                if result.returncode == 0:
                    packets = json.loads(result.stdout)

                    # Extract and aggregate flow information
                    flows = []
                    flow_dict = {}

                    for pkt in packets:
                        layers = pkt.get('_source', {}).get('layers', {})

                        # Extract timestamp
                        frame = layers.get('frame', {})
                        timestamp = float(frame.get('frame.time_epoch', '0'))

                        # Extract IP layer
                        ip_layer = layers.get('ip', {})
                        src_ip = ip_layer.get('ip.src', 'N/A')
                        dst_ip = ip_layer.get('ip.dst', 'N/A')

                        # Extract transport layer
                        protocol = None
                        src_port = None
                        dst_port = None
                        flags = []

                        if 'tcp' in layers:
                            protocol = 'TCP'
                            tcp = layers['tcp']
                            src_port = tcp.get('tcp.srcport', 'N/A')
                            dst_port = tcp.get('tcp.dstport', 'N/A')

                            # Extract TCP flags
                            if tcp.get('tcp.flags.syn') == '1':
                                flags.append('SYN')
                            if tcp.get('tcp.flags.ack') == '1':
                                flags.append('ACK')
                            if tcp.get('tcp.flags.fin') == '1':
                                flags.append('FIN')
                            if tcp.get('tcp.flags.reset') == '1':
                                flags.append('RST')
                            if tcp.get('tcp.flags.push') == '1':
                                flags.append('PSH')

                        elif 'udp' in layers:
                            protocol = 'UDP'
                            udp = layers['udp']
                            src_port = udp.get('udp.srcport', 'N/A')
                            dst_port = udp.get('udp.dstport', 'N/A')

                        if protocol and src_ip != 'N/A' and dst_ip != 'N/A':
                            flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"

                            if flow_key not in flow_dict:
                                flow_dict[flow_key] = {
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'src_port': src_port,
                                    'dst_port': dst_port,
                                    'protocol': protocol,
                                    'first_seen': timestamp,
                                    'last_seen': timestamp,
                                    'packet_count': 0,
                                    'byte_count': 0,
                                    'flags': set()
                                }

                            flow_dict[flow_key]['packet_count'] += 1
                            flow_dict[flow_key]['byte_count'] += int(frame.get('frame.len', 0))
                            flow_dict[flow_key]['last_seen'] = max(flow_dict[flow_key]['last_seen'], timestamp)
                            flow_dict[flow_key]['flags'].update(flags)

                    # Convert to DataFrame
                    flows = list(flow_dict.values())
                    df_flows = pd.DataFrame(flows)

                    if len(df_flows) > 0:
                        df_flows['first_seen_dt'] = pd.to_datetime(df_flows['first_seen'], unit='s')
                        df_flows['last_seen_dt'] = pd.to_datetime(df_flows['last_seen'], unit='s')
                        df_flows['duration'] = df_flows['last_seen'] - df_flows['first_seen']
                        df_flows['flags_str'] = df_flows['flags'].apply(lambda x: ','.join(sorted(x)) if x else '')
                        df_flows['mb'] = df_flows['byte_count'] / (1024 * 1024)

                        # Add derived fields
                        df_flows['packets_per_sec'] = df_flows.apply(
                            lambda row: row['packet_count'] / row['duration'] if row['duration'] > 0 else row['packet_count'],
                            axis=1
                        )
                        df_flows['avg_packet_size'] = df_flows['byte_count'] / df_flows['packet_count']

                        st.session_state['pcap_flows'] = df_flows

                        st.success(f"✅ Parsed {len(packets)} packets into {len(flows)} unique flows")

                        # Summary metrics
                        st.markdown("### 📊 PCAP Summary")
                        col1, col2, col3, col4, col5 = st.columns(5)

                        with col1:
                            st.metric("Total Flows", f"{len(flows):,}")
                        with col2:
                            st.metric("Total Packets", f"{df_flows['packet_count'].sum():,}")
                        with col3:
                            st.metric("Total Data", f"{df_flows['mb'].sum():.2f} MB")
                        with col4:
                            time_range = df_flows['last_seen_dt'].max() - df_flows['first_seen_dt'].min()
                            st.metric("Time Span", f"{time_range.total_seconds():.1f}s")
                        with col5:
                            unique_ips = len(set(df_flows['src_ip'].unique()) | set(df_flows['dst_ip'].unique()))
                            st.metric("Unique IPs", unique_ips)
                    else:
                        st.error("No flows could be extracted from PCAP")

                else:
                    st.error(f"Failed to parse PCAP: {result.stderr}")

            except subprocess.TimeoutExpired:
                st.error("⏱️ PCAP processing timed out. Try using a BPF filter or reducing max packets.")
            except FileNotFoundError:
                st.error("❌ tshark not found. Please install: sudo apt-get install tshark")
            except Exception as e:
                st.error(f"Error processing PCAP: {e}")
                import traceback
                st.text(traceback.format_exc())
            finally:
                if os.path.exists(tmp_pcap_path):
                    os.unlink(tmp_pcap_path)

# ===== AUDITD LOG SECTION =====
st.markdown("---")
st.markdown("## 🔍 Auditd Log Upload")

auditd_file = st.file_uploader(
    "Upload auditd log file",
    type=['log', 'txt'],
    help="Linux audit daemon log file (usually from /var/log/audit/audit.log)"
)

if auditd_file:
    st.success(f"✅ Uploaded: {auditd_file.name} ({auditd_file.size:,} bytes)")

    # Processing options
    with st.expander("⚙️ Auditd Processing Options", expanded=False):
        col1, col2 = st.columns(2)

        with col1:
            event_type_filter = st.text_input(
                "Event Type Filter (optional)",
                placeholder="e.g., EXECVE, SYSCALL, PATH",
                help="Filter by audit event type (comma-separated)"
            )

        with col2:
            max_events = st.number_input(
                "Max events to process",
                min_value=100,
                max_value=1000000,
                value=50000,
                step=5000,
                help="Limit for large log files"
            )

    if st.button("🔄 Process Auditd Log", type="primary", width="stretch"):
        with st.spinner("Parsing auditd log file..."):
            try:
                # Read uploaded file
                content = auditd_file.getvalue().decode('utf-8')
                lines = content.split('\n')

                # Parse auditd events
                events = []
                current_event = {}
                event_filters = [f.strip().upper() for f in event_type_filter.split(',')] if event_type_filter else []

                def parse_auditd_line(line):
                    """Parse a single auditd log line into key-value pairs"""
                    if not line.strip() or line.startswith('#'):
                        return None

                    # Extract timestamp and event type
                    parts = line.split(':', 1)
                    if len(parts) < 2:
                        return None

                    event = {}

                    # Parse timestamp (format: type=TYPE msg=audit(timestamp:sequence))
                    if 'type=' in line and 'msg=audit' in line:
                        # Extract type
                        type_match = line.split('type=', 1)[1].split()[0]
                        event['type'] = type_match

                        # Extract timestamp
                        if 'msg=audit(' in line:
                            ts_part = line.split('msg=audit(', 1)[1].split(')', 1)[0]
                            timestamp = ts_part.split(':')[0]
                            try:
                                event['timestamp'] = float(timestamp)
                                event['datetime'] = pd.to_datetime(float(timestamp), unit='s')
                            except:
                                event['timestamp'] = 0
                                event['datetime'] = pd.NaT

                        # Parse key-value pairs in the rest of the line
                        kv_part = line.split(')', 1)[1] if ')' in line else ''

                        # Common fields to extract
                        fields = ['pid', 'ppid', 'uid', 'gid', 'euid', 'suid', 'comm', 'exe',
                                 'syscall', 'success', 'exit', 'key', 'name', 'cwd', 'a0', 'a1', 'a2', 'a3']

                        for field in fields:
                            pattern = f'{field}='
                            if pattern in kv_part:
                                try:
                                    value = kv_part.split(pattern, 1)[1].split()[0]
                                    # Remove quotes
                                    value = value.strip('"\'')
                                    event[field] = value
                                except:
                                    pass

                        return event

                    return None

                # Process lines
                event_count = 0
                for line in lines:
                    if event_count >= max_events:
                        break

                    event = parse_auditd_line(line)
                    if event:
                        # Apply event type filter
                        if event_filters and event.get('type') not in event_filters:
                            continue

                        events.append(event)
                        event_count += 1

                if events:
                    df_auditd = pd.DataFrame(events)

                    # Clean and process data
                    for col in ['pid', 'ppid', 'uid', 'gid', 'euid', 'suid']:
                        if col in df_auditd.columns:
                            df_auditd[col] = pd.to_numeric(df_auditd[col], errors='coerce')

                    # Decode hex-encoded strings (common in auditd for comm and exe)
                    for col in ['comm', 'exe', 'name', 'cwd']:
                        if col in df_auditd.columns:
                            df_auditd[col] = df_auditd[col].apply(lambda x:
                                bytes.fromhex(x).decode('utf-8', errors='ignore') if isinstance(x, str) and len(x) > 0 and all(c in '0123456789ABCDEFabcdef' for c in x) else x
                            )

                    st.session_state['auditd_events'] = df_auditd
                    st.success(f"✅ Parsed {len(events)} audit events")

                    # Summary metrics
                    st.markdown("### 📊 Auditd Summary")
                    col1, col2, col3, col4, col5 = st.columns(5)

                    with col1:
                        st.metric("Total Events", f"{len(events):,}")
                    with col2:
                        event_types = df_auditd['type'].nunique() if 'type' in df_auditd.columns else 0
                        st.metric("Event Types", event_types)
                    with col3:
                        unique_procs = df_auditd['comm'].nunique() if 'comm' in df_auditd.columns else 0
                        st.metric("Unique Processes", unique_procs)
                    with col4:
                        if 'datetime' in df_auditd.columns and not df_auditd['datetime'].isna().all():
                            time_range = df_auditd['datetime'].max() - df_auditd['datetime'].min()
                            st.metric("Time Span", f"{time_range.total_seconds():.1f}s")
                        else:
                            st.metric("Time Span", "N/A")
                    with col5:
                        unique_users = df_auditd['uid'].nunique() if 'uid' in df_auditd.columns else 0
                        st.metric("Unique UIDs", unique_users)
                else:
                    st.error("No valid audit events found in log file")

            except Exception as e:
                st.error(f"Error processing auditd log: {e}")
                import traceback
                st.text(traceback.format_exc())

# Visualizations section
if st.session_state['pcap_flows'] is not None:
    df = st.session_state['pcap_flows']

    st.markdown("---")
    st.markdown("## 📈 Traffic Analysis & Visualizations")

    # ===== TRAFFIC OVERVIEW =====
    st.markdown("### 🌊 Traffic Overview")

    col1, col2 = st.columns(2)

    with col1:
        # Protocol distribution pie chart
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Traffic by Protocol",
            hole=0.4
        )
        st.plotly_chart(fig_protocol, width="stretch")

    with col2:
        # Traffic over time
        df_time = df.copy()
        df_time['minute'] = df_time['first_seen_dt'].dt.floor('T')
        time_traffic = df_time.groupby('minute').agg({
            'byte_count': 'sum',
            'packet_count': 'sum'
        }).reset_index()

        fig_time = go.Figure()
        fig_time.add_trace(go.Scatter(
            x=time_traffic['minute'],
            y=time_traffic['byte_count'] / (1024 * 1024),
            mode='lines',
            name='MB/min',
            fill='tozeroy'
        ))
        fig_time.update_layout(
            title="Traffic Volume Over Time",
            xaxis_title="Time",
            yaxis_title="MB per Minute"
        )
        st.plotly_chart(fig_time, width="stretch")

    # ===== TOP TALKERS =====
    st.markdown("### 🔝 Top Talkers")

    col1, col2, col3 = st.columns(3)

    with col1:
        # Top source IPs
        top_src = df.groupby('src_ip')['byte_count'].sum().nlargest(10)
        fig_src = px.bar(
            x=top_src.values / (1024 * 1024),
            y=top_src.index,
            orientation='h',
            title="Top 10 Source IPs (by data sent)",
            labels={'x': 'MB', 'y': 'Source IP'}
        )
        st.plotly_chart(fig_src, width="stretch")

    with col2:
        # Top destination IPs
        top_dst = df.groupby('dst_ip')['byte_count'].sum().nlargest(10)
        fig_dst = px.bar(
            x=top_dst.values / (1024 * 1024),
            y=top_dst.index,
            orientation='h',
            title="Top 10 Destination IPs (by data received)",
            labels={'x': 'MB', 'y': 'Destination IP'}
        )
        st.plotly_chart(fig_dst, width="stretch")

    with col3:
        # Top ports
        top_ports = df.groupby('dst_port')['byte_count'].sum().nlargest(10)
        port_labels = []
        common_ports = {
            '80': 'HTTP', '443': 'HTTPS', '22': 'SSH', '53': 'DNS',
            '21': 'FTP', '25': 'SMTP', '3306': 'MySQL', '5432': 'PostgreSQL',
            '6379': 'Redis', '27017': 'MongoDB', '8080': 'HTTP-Alt'
        }
        for port in top_ports.index:
            port_str = str(port)
            label = f"{port_str} ({common_ports.get(port_str, 'unknown')})"
            port_labels.append(label)

        fig_ports = px.bar(
            x=top_ports.values / (1024 * 1024),
            y=port_labels,
            orientation='h',
            title="Top 10 Destination Ports",
            labels={'x': 'MB', 'y': 'Port'}
        )
        st.plotly_chart(fig_ports, width="stretch")

    # ===== FLOW CHARACTERISTICS =====
    st.markdown("### 📊 Flow Characteristics")

    col1, col2 = st.columns(2)

    with col1:
        # Flow duration distribution
        fig_duration = px.histogram(
            df[df['duration'] > 0],
            x='duration',
            nbins=50,
            title="Flow Duration Distribution",
            labels={'duration': 'Duration (seconds)', 'count': 'Number of Flows'},
            log_y=True
        )
        st.plotly_chart(fig_duration, width="stretch")

    with col2:
        # Packet count distribution
        fig_packets = px.histogram(
            df,
            x='packet_count',
            nbins=50,
            title="Packets per Flow Distribution",
            labels={'packet_count': 'Packets per Flow', 'count': 'Number of Flows'},
            log_y=True
        )
        st.plotly_chart(fig_packets, width="stretch")

    # ===== CONNECTION PATTERNS =====
    st.markdown("### 🔗 Connection Patterns")

    # Scatter plot: Duration vs Bytes
    fig_scatter = px.scatter(
        df[df['duration'] > 0].head(1000),  # Limit to 1000 for performance
        x='duration',
        y='byte_count',
        size='packet_count',
        color='protocol',
        hover_data=['src_ip', 'dst_ip', 'dst_port'],
        title="Flow Characteristics: Duration vs Data Volume",
        labels={
            'duration': 'Duration (seconds)',
            'byte_count': 'Bytes Transferred',
            'packet_count': 'Packets'
        },
        log_y=True
    )
    st.plotly_chart(fig_scatter, width="stretch")

    # ===== TCP ANALYSIS =====
    if 'TCP' in df['protocol'].values:
        st.markdown("### 🔌 TCP Analysis")

        tcp_df = df[df['protocol'] == 'TCP']

        col1, col2 = st.columns(2)

        with col1:
            # TCP flags distribution
            flag_counts = Counter()
            for flags_str in tcp_df['flags_str']:
                if flags_str:
                    flag_counts[flags_str] += 1

            if flag_counts:
                fig_flags = px.bar(
                    x=list(flag_counts.keys())[:15],
                    y=list(flag_counts.values())[:15],
                    title="Top TCP Flag Combinations",
                    labels={'x': 'Flags', 'y': 'Count'}
                )
                st.plotly_chart(fig_flags, width="stretch")

        with col2:
            # Average packet size by protocol
            avg_size_proto = df.groupby('protocol')['avg_packet_size'].mean()
            fig_avgsize = px.bar(
                x=avg_size_proto.index,
                y=avg_size_proto.values,
                title="Average Packet Size by Protocol",
                labels={'x': 'Protocol', 'y': 'Bytes'}
            )
            st.plotly_chart(fig_avgsize, width="stretch")

    # ===== NETWORK MAP =====
    st.markdown("### 🗺️ Communication Network Map")

    # Build network graph (top flows only for performance)
    top_flows = df.nlargest(100, 'byte_count')

    # Create nodes
    nodes = set()
    for _, row in top_flows.iterrows():
        nodes.add(row['src_ip'])
        nodes.add(row['dst_ip'])

    node_list = list(nodes)
    node_indices = {node: i for i, node in enumerate(node_list)}

    # Create edges
    edge_x = []
    edge_y = []
    edge_weights = []

    for _, row in top_flows.iterrows():
        src_idx = node_indices[row['src_ip']]
        dst_idx = node_indices[row['dst_ip']]

        # Simple circular layout
        src_angle = 2 * np.pi * src_idx / len(node_list)
        dst_angle = 2 * np.pi * dst_idx / len(node_list)

        edge_x.extend([np.cos(src_angle), np.cos(dst_angle), None])
        edge_y.extend([np.sin(src_angle), np.sin(dst_angle), None])
        edge_weights.append(row['byte_count'])

    # Node positions
    node_x = [np.cos(2 * np.pi * i / len(node_list)) for i in range(len(node_list))]
    node_y = [np.sin(2 * np.pi * i / len(node_list)) for i in range(len(node_list))]

    # Node sizes (by total traffic)
    node_traffic = df.groupby('src_ip')['byte_count'].sum() + df.groupby('dst_ip')['byte_count'].sum()
    node_sizes = [node_traffic.get(node, 0) / 1024 / 1024 for node in node_list]

    fig_network = go.Figure()

    # Add edges
    fig_network.add_trace(go.Scatter(
        x=edge_x,
        y=edge_y,
        mode='lines',
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        showlegend=False
    ))

    # Add nodes
    fig_network.add_trace(go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers+text',
        marker=dict(
            size=[max(10, min(50, s / 10)) for s in node_sizes],
            color=node_sizes,
            colorscale='Viridis',
            showscale=True,
            colorbar=dict(title="Traffic (MB)")
        ),
        text=node_list,
        textposition="top center",
        hovertemplate='%{text}<br>Traffic: %{marker.color:.2f} MB<extra></extra>',
        showlegend=False
    ))

    fig_network.update_layout(
        title="Network Communication Graph (Top 100 Flows)",
        showlegend=False,
        hovermode='closest',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=600
    )

    st.plotly_chart(fig_network, width="stretch")

    # ===== DETAILED FLOW TABLE =====
    st.markdown("### 📋 Detailed Flow Data")

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        filter_protocol = st.multiselect(
            "Filter by Protocol",
            options=df['protocol'].unique(),
            default=[]
        )

    with col2:
        filter_ip = st.text_input("Filter by IP (source or destination)", "")

    with col3:
        sort_by = st.selectbox(
            "Sort by",
            options=['byte_count', 'packet_count', 'duration', 'first_seen_dt'],
            index=0
        )

    # Apply filters
    filtered_df = df.copy()

    if filter_protocol:
        filtered_df = filtered_df[filtered_df['protocol'].isin(filter_protocol)]

    if filter_ip:
        filtered_df = filtered_df[
            (filtered_df['src_ip'].str.contains(filter_ip, case=False)) |
            (filtered_df['dst_ip'].str.contains(filter_ip, case=False))
        ]

    # Sort
    filtered_df = filtered_df.sort_values(by=sort_by, ascending=False)

    # Display table
    display_cols = ['first_seen_dt', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                    'protocol', 'packet_count', 'byte_count', 'duration', 'flags_str']

    st.dataframe(
        filtered_df[display_cols].head(100),
        width="stretch",
        hide_index=True
    )

    # ===== EXPORT OPTIONS =====
    st.markdown("### 📥 Export Options")

    col1, col2 = st.columns(2)

    with col1:
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download Full Dataset (CSV)",
            data=csv,
            file_name=f"pcap_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            width="stretch"
        )

    with col2:
        # Export top flows as JSON
        top_flows_json = df.nlargest(100, 'byte_count').to_json(orient='records', date_format='iso')
        st.download_button(
            label="Download Top 100 Flows (JSON)",
            data=top_flows_json,
            file_name=f"top_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            width="stretch"
        )

# ===== AUDITD VISUALIZATIONS =====
if st.session_state['auditd_events'] is not None:
    df_audit = st.session_state['auditd_events']

    st.markdown("---")
    st.markdown("## 🔍 Auditd Event Analysis")

    # ===== EVENT OVERVIEW =====
    st.markdown("### 📋 Event Overview")

    col1, col2 = st.columns(2)

    with col1:
        # Event type distribution
        if 'type' in df_audit.columns:
            type_counts = df_audit['type'].value_counts().head(15)
            fig_types = px.bar(
                x=type_counts.values,
                y=type_counts.index,
                orientation='h',
                title="Top 15 Audit Event Types",
                labels={'x': 'Count', 'y': 'Event Type'}
            )
            st.plotly_chart(fig_types, width="stretch")

    with col2:
        # Events over time
        if 'datetime' in df_audit.columns and not df_audit['datetime'].isna().all():
            df_time = df_audit.copy()
            df_time['minute'] = df_time['datetime'].dt.floor('T')
            time_events = df_time.groupby('minute').size().reset_index(name='count')

            fig_time = go.Figure()
            fig_time.add_trace(go.Scatter(
                x=time_events['minute'],
                y=time_events['count'],
                mode='lines',
                fill='tozeroy',
                name='Events/min'
            ))
            fig_time.update_layout(
                title="Audit Events Over Time",
                xaxis_title="Time",
                yaxis_title="Events per Minute"
            )
            st.plotly_chart(fig_time, width="stretch")

    # ===== PROCESS ACTIVITY =====
    st.markdown("### 👤 Process & User Activity")

    col1, col2, col3 = st.columns(3)

    with col1:
        # Top processes
        if 'comm' in df_audit.columns:
            top_procs = df_audit['comm'].value_counts().head(10)
            fig_procs = px.bar(
                x=top_procs.values,
                y=top_procs.index,
                orientation='h',
                title="Top 10 Processes (by event count)",
                labels={'x': 'Events', 'y': 'Process'}
            )
            st.plotly_chart(fig_procs, width="stretch")

    with col2:
        # Top executables
        if 'exe' in df_audit.columns:
            top_exes = df_audit['exe'].value_counts().head(10)
            fig_exes = px.bar(
                x=top_exes.values,
                y=top_exes.index,
                orientation='h',
                title="Top 10 Executables",
                labels={'x': 'Events', 'y': 'Executable'}
            )
            st.plotly_chart(fig_exes, width="stretch")

    with col3:
        # User activity (by UID)
        if 'uid' in df_audit.columns:
            uid_counts = df_audit['uid'].value_counts().head(10)
            fig_uids = px.bar(
                x=uid_counts.values,
                y=uid_counts.index.astype(str),
                orientation='h',
                title="Top 10 User IDs (by activity)",
                labels={'x': 'Events', 'y': 'UID'}
            )
            st.plotly_chart(fig_uids, width="stretch")

    # ===== SYSCALL ANALYSIS =====
    if 'syscall' in df_audit.columns:
        st.markdown("### 🔧 Syscall Analysis")

        col1, col2 = st.columns(2)

        with col1:
            # Syscall distribution
            syscall_counts = df_audit['syscall'].value_counts().head(15)
            fig_syscalls = px.bar(
                x=syscall_counts.values,
                y=syscall_counts.index,
                orientation='h',
                title="Top 15 Syscalls",
                labels={'x': 'Count', 'y': 'Syscall'}
            )
            st.plotly_chart(fig_syscalls, width="stretch")

        with col2:
            # Success/failure analysis
            if 'success' in df_audit.columns:
                success_counts = df_audit['success'].value_counts()
                fig_success = px.pie(
                    values=success_counts.values,
                    names=success_counts.index,
                    title="Syscall Success vs Failure",
                    hole=0.4
                )
                st.plotly_chart(fig_success, width="stretch")

    # ===== FILE ACCESS ANALYSIS =====
    if 'name' in df_audit.columns:
        st.markdown("### 📁 File Access Patterns")

        col1, col2 = st.columns(2)

        with col1:
            # Top accessed files
            top_files = df_audit['name'].value_counts().head(15)
            fig_files = px.bar(
                x=top_files.values,
                y=top_files.index,
                orientation='h',
                title="Top 15 Accessed Files/Paths",
                labels={'x': 'Access Count', 'y': 'Path'}
            )
            st.plotly_chart(fig_files, width="stretch")

        with col2:
            # Directory analysis (extract directory from path)
            df_dirs = df_audit[df_audit['name'].notna()].copy()
            df_dirs['directory'] = df_dirs['name'].apply(lambda x: '/'.join(str(x).split('/')[:-1]) if '/' in str(x) else '/')
            top_dirs = df_dirs['directory'].value_counts().head(15)
            fig_dirs = px.bar(
                x=top_dirs.values,
                y=top_dirs.index,
                orientation='h',
                title="Top 15 Accessed Directories",
                labels={'x': 'Access Count', 'y': 'Directory'}
            )
            st.plotly_chart(fig_dirs, width="stretch")

    # ===== PROCESS TREE VISUALIZATION =====
    if 'pid' in df_audit.columns and 'ppid' in df_audit.columns and 'comm' in df_audit.columns:
        st.markdown("### 🌳 Process Relationships")

        # Build process tree (sample top processes)
        df_procs = df_audit[['pid', 'ppid', 'comm']].dropna()
        top_pids = df_procs['pid'].value_counts().head(50).index
        df_tree = df_procs[df_procs['pid'].isin(top_pids)]

        # Create network graph
        edges = []
        for _, row in df_tree.iterrows():
            if row['ppid'] != row['pid'] and row['ppid'] in top_pids:
                edges.append((row['ppid'], row['pid'], row['comm']))

        if edges:
            # Sunburst chart showing process hierarchy
            tree_data = []
            for ppid, pid, comm in edges:
                tree_data.append({
                    'parent': f"PID {int(ppid)}",
                    'child': f"PID {int(pid)}",
                    'comm': comm
                })

            if tree_data:
                df_tree_viz = pd.DataFrame(tree_data)
                # Create a simple hierarchy visualization
                parent_child_counts = df_tree_viz.groupby(['parent', 'child']).size().reset_index(name='count')

                st.info(f"📊 Showing process relationships for top 50 most active PIDs ({len(edges)} parent-child relationships)")

    # ===== DETAILED EVENT TABLE =====
    st.markdown("### 📋 Detailed Event Data")

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        if 'type' in df_audit.columns:
            filter_type = st.multiselect(
                "Filter by Event Type",
                options=df_audit['type'].unique(),
                default=[]
            )
        else:
            filter_type = []

    with col2:
        if 'comm' in df_audit.columns:
            filter_comm = st.text_input("Filter by Process Name", "")
        else:
            filter_comm = ""

    with col3:
        sort_by_audit = st.selectbox(
            "Sort by",
            options=['timestamp', 'type', 'comm', 'uid'] if 'timestamp' in df_audit.columns else df_audit.columns.tolist()[:4],
            index=0
        )

    # Apply filters
    filtered_audit = df_audit.copy()

    if filter_type:
        filtered_audit = filtered_audit[filtered_audit['type'].isin(filter_type)]

    if filter_comm:
        if 'comm' in filtered_audit.columns:
            filtered_audit = filtered_audit[filtered_audit['comm'].str.contains(filter_comm, case=False, na=False)]

    # Sort
    if sort_by_audit in filtered_audit.columns:
        filtered_audit = filtered_audit.sort_values(by=sort_by_audit, ascending=False)

    # Display table
    display_cols = [col for col in ['datetime', 'type', 'comm', 'exe', 'pid', 'ppid', 'uid', 'syscall', 'success', 'name'] if col in filtered_audit.columns]

    st.dataframe(
        filtered_audit[display_cols].head(100),
        width="stretch",
        hide_index=True
    )

    # ===== EXPORT OPTIONS =====
    st.markdown("### 📥 Auditd Export Options")

    col1, col2 = st.columns(2)

    with col1:
        csv_audit = df_audit.to_csv(index=False)
        st.download_button(
            label="Download Full Auditd Dataset (CSV)",
            data=csv_audit,
            file_name=f"auditd_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            width="stretch"
        )

    with col2:
        # Export filtered data as JSON
        filtered_json = filtered_audit.head(1000).to_json(orient='records', date_format='iso')
        st.download_button(
            label="Download Filtered Events (JSON)",
            data=filtered_json,
            file_name=f"auditd_filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            width="stretch"
        )

# ===== CORRELATION ANALYSIS =====
if st.session_state['pcap_flows'] is not None and st.session_state['auditd_events'] is not None:
    st.markdown("---")
    st.markdown("## 🔗 PCAP-Auditd Correlation Analysis")

    df_pcap = st.session_state['pcap_flows']
    df_audit = st.session_state['auditd_events']

    # Check if both have timestamps
    if 'first_seen_dt' in df_pcap.columns and 'datetime' in df_audit.columns and not df_audit['datetime'].isna().all():
        st.markdown("### ⏰ Timeline Correlation")

        # Time tolerance for correlation
        time_tolerance = st.slider(
            "Time correlation tolerance (seconds)",
            min_value=1,
            max_value=300,
            value=30,
            help="Match PCAP flows with auditd events within this time window"
        )

        # Find overlapping time range
        pcap_start = df_pcap['first_seen_dt'].min()
        pcap_end = df_pcap['last_seen_dt'].max()
        audit_start = df_audit['datetime'].min()
        audit_end = df_audit['datetime'].max()

        overlap_start = max(pcap_start, audit_start)
        overlap_end = min(pcap_end, audit_end)

        if overlap_start < overlap_end:
            st.success(f"✅ Found overlapping time period: {overlap_start} to {overlap_end}")

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("PCAP Flows in overlap", len(df_pcap[(df_pcap['first_seen_dt'] >= overlap_start) & (df_pcap['first_seen_dt'] <= overlap_end)]))
            with col2:
                st.metric("Auditd Events in overlap", len(df_audit[(df_audit['datetime'] >= overlap_start) & (df_audit['datetime'] <= overlap_end)]))
            with col3:
                overlap_duration = (overlap_end - overlap_start).total_seconds()
                st.metric("Overlap Duration", f"{overlap_duration:.1f}s")

            # Combined timeline visualization
            st.markdown("### 📊 Combined Timeline")

            # Create combined timeline data
            df_pcap_timeline = df_pcap.copy()
            df_pcap_timeline['minute'] = df_pcap_timeline['first_seen_dt'].dt.floor('T')
            pcap_timeline = df_pcap_timeline.groupby('minute').size().reset_index(name='pcap_count')

            df_audit_timeline = df_audit.copy()
            df_audit_timeline['minute'] = df_audit_timeline['datetime'].dt.floor('T')
            audit_timeline = df_audit_timeline.groupby('minute').size().reset_index(name='audit_count')

            # Merge timelines
            combined_timeline = pd.merge(pcap_timeline, audit_timeline, on='minute', how='outer').fillna(0)
            combined_timeline = combined_timeline.sort_values('minute')

            # Plot combined timeline
            fig_combined = go.Figure()
            fig_combined.add_trace(go.Scatter(
                x=combined_timeline['minute'],
                y=combined_timeline['pcap_count'],
                mode='lines',
                name='PCAP Flows',
                line=dict(color='blue')
            ))
            fig_combined.add_trace(go.Scatter(
                x=combined_timeline['minute'],
                y=combined_timeline['audit_count'],
                mode='lines',
                name='Audit Events',
                line=dict(color='red'),
                yaxis='y2'
            ))
            fig_combined.update_layout(
                title="Combined Activity Timeline",
                xaxis_title="Time",
                yaxis_title="PCAP Flows",
                yaxis2=dict(
                    title="Audit Events",
                    overlaying='y',
                    side='right'
                ),
                hovermode='x unified'
            )
            st.plotly_chart(fig_combined, width="stretch")

            # Process-Network correlation
            st.markdown("### 🔍 Process-Network Correlation")

            # Try to correlate network connections with processes
            if 'comm' in df_audit.columns and 'pid' in df_audit.columns:
                st.info("💡 Analyzing which processes were active during network flows...")

                # Get processes active during PCAP capture
                pcap_processes = df_audit[
                    (df_audit['datetime'] >= overlap_start) &
                    (df_audit['datetime'] <= overlap_end)
                ]

                if len(pcap_processes) > 0:
                    col1, col2 = st.columns(2)

                    with col1:
                        # Top processes during network activity
                        top_net_procs = pcap_processes['comm'].value_counts().head(10)
                        fig_net_procs = px.bar(
                            x=top_net_procs.values,
                            y=top_net_procs.index,
                            orientation='h',
                            title="Top Processes During PCAP Capture",
                            labels={'x': 'Event Count', 'y': 'Process'}
                        )
                        st.plotly_chart(fig_net_procs, width="stretch")

                    with col2:
                        # Protocol distribution for context
                        protocol_dist = df_pcap['protocol'].value_counts()
                        fig_proto = px.pie(
                            values=protocol_dist.values,
                            names=protocol_dist.index,
                            title="Network Protocol Distribution",
                            hole=0.4
                        )
                        st.plotly_chart(fig_proto, width="stretch")

                    # Correlation table
                    st.markdown("### 📋 Potential Process-Flow Correlations")

                    # Find processes that might be responsible for network activity
                    correlations = []

                    for _, flow in df_pcap.head(50).iterrows():  # Limit to top 50 flows
                        flow_time = flow['first_seen_dt']
                        time_window_start = flow_time - pd.Timedelta(seconds=time_tolerance)
                        time_window_end = flow_time + pd.Timedelta(seconds=time_tolerance)

                        # Find processes active in this time window
                        matching_procs = df_audit[
                            (df_audit['datetime'] >= time_window_start) &
                            (df_audit['datetime'] <= time_window_end)
                        ]

                        if len(matching_procs) > 0:
                            for proc in matching_procs['comm'].unique()[:3]:  # Top 3 processes
                                correlations.append({
                                    'time': flow_time,
                                    'src_ip': flow['src_ip'],
                                    'dst_ip': flow['dst_ip'],
                                    'dst_port': flow['dst_port'],
                                    'protocol': flow['protocol'],
                                    'process': proc,
                                    'bytes': flow['byte_count']
                                })

                    if correlations:
                        df_corr = pd.DataFrame(correlations).head(100)
                        st.dataframe(
                            df_corr,
                            width="stretch",
                            hide_index=True
                        )
                        st.caption(f"Showing potential correlations (processes active within ±{time_tolerance}s of network flows)")
                    else:
                        st.warning("No strong correlations found with current tolerance settings")

        else:
            st.warning("⚠️ No overlapping time period found between PCAP and auditd data")
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**PCAP Time Range:**")
                st.write(f"Start: {pcap_start}")
                st.write(f"End: {pcap_end}")
            with col2:
                st.write(f"**Auditd Time Range:**")
                st.write(f"Start: {audit_start}")
                st.write(f"End: {audit_end}")
    else:
        st.info("⏰ Both datasets need valid timestamps for correlation analysis")

else:
    if st.session_state['pcap_flows'] is None and st.session_state['auditd_events'] is None:
        st.info("👆 Upload a PCAP file or auditd log above to begin analysis")
