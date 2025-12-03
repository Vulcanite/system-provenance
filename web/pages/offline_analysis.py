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

st.title("📊 Offline PCAP Analysis")
st.markdown("### Network Traffic Forensics & Visualization")

# Session state
if 'pcap_flows' not in st.session_state:
    st.session_state['pcap_flows'] = None

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

    if st.button("🔄 Process PCAP File", type="primary", use_container_width=True):
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
        st.plotly_chart(fig_protocol, use_container_width=True)

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
        st.plotly_chart(fig_time, use_container_width=True)

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
        st.plotly_chart(fig_src, use_container_width=True)

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
        st.plotly_chart(fig_dst, use_container_width=True)

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
        st.plotly_chart(fig_ports, use_container_width=True)

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
        st.plotly_chart(fig_duration, use_container_width=True)

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
        st.plotly_chart(fig_packets, use_container_width=True)

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
    st.plotly_chart(fig_scatter, use_container_width=True)

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
                st.plotly_chart(fig_flags, use_container_width=True)

        with col2:
            # Average packet size by protocol
            avg_size_proto = df.groupby('protocol')['avg_packet_size'].mean()
            fig_avgsize = px.bar(
                x=avg_size_proto.index,
                y=avg_size_proto.values,
                title="Average Packet Size by Protocol",
                labels={'x': 'Protocol', 'y': 'Bytes'}
            )
            st.plotly_chart(fig_avgsize, use_container_width=True)

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

    st.plotly_chart(fig_network, use_container_width=True)

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
        use_container_width=True,
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
            use_container_width=True
        )

    with col2:
        # Export top flows as JSON
        top_flows_json = df.nlargest(100, 'byte_count').to_json(orient='records', date_format='iso')
        st.download_button(
            label="Download Top 100 Flows (JSON)",
            data=top_flows_json,
            file_name=f"top_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )

else:
    st.info("👆 Upload a PCAP file above to begin analysis")
