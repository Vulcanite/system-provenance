#!/usr/bin/env python3
"""PCAP Flows Viewer Page"""

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from collections import defaultdict
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch, get_event_count, fetch_events, to_epoch_ms, get_unique_hostnames

st.title("🌐 PCAP Network Flows")
st.markdown("### Aggregated Network Traffic Analysis")

# Load configuration
config = load_config()
es_config = config.get("es_config", {})
pcap_index = es_config.get("pcap_index", "pcap-flows")

# Connect to Elasticsearch
es = connect_elasticsearch(es_config)

# Sidebar filters
st.sidebar.header("🔍 Filters")

# Time range selection
time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days", "Custom"],
    index=0
)

if time_range == "Custom":
    col1, col2 = st.sidebar.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.now().date())
        start_time = st.time_input("Start Time", datetime.now().time())
    with col2:
        end_date = st.date_input("End Date", datetime.now().date())
        end_time = st.time_input("End Time", datetime.now().time())

    start_dt = datetime.combine(start_date, start_time)
    end_dt = datetime.combine(end_date, end_time)
else:
    end_dt = datetime.now()
    if time_range == "Last 1 hour":
        start_dt = end_dt - timedelta(hours=1)
    elif time_range == "Last 6 hours":
        start_dt = end_dt - timedelta(hours=6)
    elif time_range == "Last 24 hours":
        start_dt = end_dt - timedelta(hours=24)
    elif time_range == "Last 7 days":
        start_dt = end_dt - timedelta(days=7)

start_ms = to_epoch_ms(start_dt)
end_ms = to_epoch_ms(end_dt)

# Hostname filter
hostnames = get_unique_hostnames(es, pcap_index)
hostname_filter = st.sidebar.selectbox("Hostname", hostnames)

# Protocol filter
protocol_filter = st.sidebar.selectbox("Protocol", ["All", "TCP", "UDP"])

# Flow ID filter (for correlation with eBPF events)
flow_id_filter = st.sidebar.text_input("Flow ID (exact match)", "", help="Enter flow ID to correlate with eBPF network events")

# Sort by option (for table display only)
sort_by = st.sidebar.selectbox(
    "Sort Table By",
    ["Bytes (Highest)", "Packets (Highest)", "Duration (Longest)", "Most Recent"],
    index=0
)
st.sidebar.caption("Note: Visualizations use ALL flows in time range")

# Build filters dict
filters = {}
if hostname_filter != "All":
    filters["host.name"] = hostname_filter
if protocol_filter != "All":
    filters["network.transport"] = protocol_filter
if flow_id_filter:
    filters["flow.id"] = flow_id_filter

# Main content
st.markdown("---")

# Get total count
total_count = get_event_count(es, pcap_index, start_ms, end_ms, filters)
st.info(f"📊 **Total Flows in Selected Time Range:** {total_count:,}")

if total_count > 0:
    # Determine sort field and order based on selection
    if sort_by == "Bytes (Highest)":
        sort_field = "network.bytes"
        sort_order = "desc"
    elif sort_by == "Packets (Highest)":
        sort_field = "network.packets"
        sort_order = "desc"
    elif sort_by == "Duration (Longest)":
        sort_field = "epoch_last"
        sort_order = "desc"
    else:  # Most Recent
        sort_field = "epoch_first"
        sort_order = "desc"

    # Fetch top 100 flows for table display
    with st.spinner("Loading top 100 flows for table..."):
        top_flows = fetch_events(es, pcap_index, start_ms, end_ms, filters, page=1, page_size=100, sort_field=sort_field, sort_order=sort_order)

    # Fetch ALL flows for visualizations (up to 10,000 to avoid memory issues)
    viz_limit = min(total_count, 10000)
    with st.spinner(f"Loading {viz_limit} flows for visualizations..."):
        all_flows = fetch_events(es, pcap_index, start_ms, end_ms, filters, page=1, page_size=viz_limit, sort_field="epoch_first", sort_order="asc")

    if top_flows:
        st.success(f"✅ Table: Showing top 100 flows (sorted by {sort_by}) | Visualizations: Using {len(all_flows):,} flows from selected time range")

        # Create DataFrame for table view (top 100)
        table_data = []
        for flow in top_flows:
            duration_s = (flow.get('epoch_last', 0) - flow.get('epoch_first', 0)) / 1000.0
            flow_id = flow.get("flow.id", "N/A")
            src_ip = flow.get("source.ip", "N/A")
            dst_ip = flow.get("destination.ip", "N/A")
            src_port = flow.get("source.port", 0)
            dst_port = flow.get("destination.port", 0)
            table_data.append({
                "Flow ID": flow_id,
                "Hostname": flow.get("host.name", "N/A"),
                "Protocol": flow.get("network.transport", "N/A"),
                "Source": f"{src_ip}:{src_port}",
                "Destination": f"{dst_ip}:{dst_port}",
                "Domain": flow.get("destination.domain", "-") if flow.get("dns_resolved") else "-",
                "Packets": flow.get("network.packets", 0),
                "Bytes": flow.get("network.bytes", 0),
                "Duration (s)": round(duration_s, 2),
                "First Seen": flow.get("event.start", flow.get("@timestamp", "N/A"))[:19] if flow.get("event.start") or flow.get("@timestamp") else "N/A",
                # Keep raw data for visualizations and correlation
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": flow.get("network.tcp_flags", []),
                "epoch_first": flow.get("epoch_first", 0),
            })

        df_table = pd.DataFrame(table_data)

        # Display table (without raw data columns)
        display_df = df_table[["Flow ID", "Hostname", "Protocol", "Source", "Destination", "Domain", "Packets", "Bytes", "Duration (s)", "First Seen"]]

        # Add interactive flow ID copying for correlation
        st.dataframe(
            display_df,
            width="stretch",
            hide_index=True
        )

        # Flow ID correlation helper
        if not flow_id_filter:
            with st.expander("🔗 How to Correlate with eBPF Events", expanded=False):
                st.markdown("""
                **Flow ID Correlation Guide:**
                1. Copy a Flow ID from the table above (you can click and select the text)
                2. Go to the **eBPF Events** page
                3. Paste the Flow ID into the "Flow ID" filter in the sidebar
                4. View all syscalls (connect, sendto, recvfrom) associated with that network flow

                This allows you to see which process generated the network traffic!
                """)

                # Show a sample flow ID if available
                if len(df_table) > 0 and df_table['Flow ID'].iloc[0] != "N/A":
                    st.code(df_table['Flow ID'].iloc[0], language="text")
                    st.caption("↑ Example Flow ID (copy this to filter eBPF events)")

        # Create DataFrame for visualizations (ALL flows in time range)
        viz_data = []
        for flow in all_flows:
            duration_s = (flow.get('epoch_last', 0) - flow.get('epoch_first', 0)) / 1000.0
            src_ip = flow.get("source.ip", "N/A")
            dst_ip = flow.get("destination.ip", "N/A")
            src_port = flow.get("source.port", "")
            dst_port = flow.get("destination.port", "")
            viz_data.append({
                "Hostname": flow.get("host.name", "N/A"),
                "Protocol": flow.get("network.transport", "N/A"),
                "Source": f"{src_ip}:{src_port}",
                "Destination": f"{dst_ip}:{dst_port}",
                "Domain": flow.get("destination.domain", "-") if flow.get("dns_resolved") else "-",
                "Packets": flow.get("network.packets", 0),
                "Bytes": flow.get("network.bytes", 0),
                "Duration (s)": round(duration_s, 2),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": flow.get("network.tcp_flags", []),
                "epoch_first": flow.get("epoch_first", 0),
            })

        df = pd.DataFrame(viz_data)

        st.markdown("---")
        st.header("📊 Traffic Visualizations")
        st.caption(f"Based on {len(df):,} flows from selected time range")

        # Row 1: Protocol distribution and Traffic over time
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Protocol Distribution")
            protocol_counts = df['Protocol'].value_counts()
            protocol_bytes = df.groupby('Protocol')['Bytes'].sum()

            fig_protocol = go.Figure(data=[
                go.Pie(
                    labels=protocol_counts.index,
                    values=protocol_counts.values,
                    hole=0.4,
                    marker=dict(colors=['#636EFA', '#EF553B']),
                    textinfo='label+percent+value',
                    hovertemplate='<b>%{label}</b><br>Flows: %{value}<br>Percentage: %{percent}<extra></extra>'
                )
            ])
            fig_protocol.update_layout(
                showlegend=True,
                height=350,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            st.plotly_chart(fig_protocol, width="stretch")

        with col2:
            st.subheader("Traffic Over Time")
            # Convert epoch to datetime
            df['timestamp'] = pd.to_datetime(df['epoch_first'], unit='ms')
            df_time = df.groupby([pd.Grouper(key='timestamp', freq='5min'), 'Protocol']).agg({
                'Bytes': 'sum',
                'Packets': 'sum'
            }).reset_index()

            fig_time = px.line(
                df_time,
                x='timestamp',
                y='Bytes',
                color='Protocol',
                title='Bytes Transferred Over Time',
                labels={'Bytes': 'Bytes', 'timestamp': 'Time'},
                color_discrete_map={'TCP': '#636EFA', 'UDP': '#EF553B'}
            )
            fig_time.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_time, width="stretch")

        # Row 2: Top sources and destinations
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Top 10 Source IPs (by Bytes)")
            top_src = df.groupby('src_ip')['Bytes'].sum().sort_values(ascending=False).head(10)
            fig_src = px.bar(
                x=top_src.values,
                y=top_src.index,
                orientation='h',
                labels={'x': 'Bytes', 'y': 'Source IP'},
                color=top_src.values,
                color_continuous_scale='Blues'
            )
            fig_src.update_layout(
                showlegend=False,
                height=400,
                margin=dict(l=20, r=20, t=20, b=20),
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig_src, width="stretch")

        with col2:
            st.subheader("Top 10 Destination IPs (by Bytes)")
            top_dst = df.groupby('dst_ip')['Bytes'].sum().sort_values(ascending=False).head(10)
            fig_dst = px.bar(
                x=top_dst.values,
                y=top_dst.index,
                orientation='h',
                labels={'x': 'Bytes', 'y': 'Destination IP'},
                color=top_dst.values,
                color_continuous_scale='Reds'
            )
            fig_dst.update_layout(
                showlegend=False,
                height=400,
                margin=dict(l=20, r=20, t=20, b=20),
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig_dst, width="stretch")

        # Row 3: Port analysis
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Top 10 Destination Ports (by Flow Count)")
            port_counts = df['dst_port'].value_counts().head(10)
            port_names = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP",
                         3306: "MySQL", 3389: "RDP", 21: "FTP", 23: "Telnet", 8080: "HTTP-Alt"}
            port_labels = [f"{port} ({port_names.get(port, 'Unknown')})" for port in port_counts.index]

            fig_ports = px.bar(
                x=port_counts.values,
                y=port_labels,
                orientation='h',
                labels={'x': 'Flow Count', 'y': 'Port'},
                color=port_counts.values,
                color_continuous_scale='Viridis'
            )
            fig_ports.update_layout(
                showlegend=False,
                height=400,
                margin=dict(l=20, r=20, t=20, b=20),
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig_ports, width="stretch")

        with col2:
            st.subheader("Top 10 Destination Ports (by Bytes)")
            port_bytes = df.groupby('dst_port')['Bytes'].sum().sort_values(ascending=False).head(10)
            port_labels_bytes = [f"{port} ({port_names.get(port, 'Unknown')})" for port in port_bytes.index]

            fig_ports_bytes = px.bar(
                x=port_bytes.values,
                y=port_labels_bytes,
                orientation='h',
                labels={'x': 'Bytes', 'y': 'Port'},
                color=port_bytes.values,
                color_continuous_scale='Plasma'
            )
            fig_ports_bytes.update_layout(
                showlegend=False,
                height=400,
                margin=dict(l=20, r=20, t=20, b=20),
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig_ports_bytes, width="stretch")

        # Row 4: Flow characteristics
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Flow Duration Distribution")
            # Create duration bins
            duration_bins = [0, 1, 5, 10, 30, 60, 300, float('inf')]
            duration_labels = ['0-1s', '1-5s', '5-10s', '10-30s', '30-60s', '1-5m', '5m+']
            df['duration_bin'] = pd.cut(df['Duration (s)'], bins=duration_bins, labels=duration_labels)
            duration_dist = df['duration_bin'].value_counts().sort_index()

            fig_duration = px.bar(
                x=duration_dist.index,
                y=duration_dist.values,
                labels={'x': 'Duration Range', 'y': 'Flow Count'},
                color=duration_dist.values,
                color_continuous_scale='Turbo'
            )
            fig_duration.update_layout(
                showlegend=False,
                height=350,
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig_duration, width="stretch")

        with col2:
            st.subheader("Bytes vs Packets Scatter")
            fig_scatter = px.scatter(
                df.head(100),
                x='Packets',
                y='Bytes',
                color='Protocol',
                size='Duration (s)',
                hover_data=['Source', 'Destination', 'Domain'],
                labels={'Bytes': 'Bytes', 'Packets': 'Packets'},
                color_discrete_map={'TCP': '#636EFA', 'UDP': '#EF553B'}
            )
            fig_scatter.update_layout(height=350, margin=dict(l=20, r=20, t=20, b=20))
            st.plotly_chart(fig_scatter, width="stretch")

        # Row 5: TCP Analysis (if TCP flows exist)
        tcp_flows = df[df['Protocol'] == 'TCP']
        if len(tcp_flows) > 0:
            st.subheader("TCP Flag Analysis")

            # Flatten TCP flags
            flag_counts = defaultdict(int)
            for flags in tcp_flows['tcp_flags']:
                if flags:
                    for flag in flags:
                        flag_counts[flag] += 1

            if flag_counts:
                fig_flags = px.bar(
                    x=list(flag_counts.keys()),
                    y=list(flag_counts.values()),
                    labels={'x': 'TCP Flag', 'y': 'Occurrence Count'},
                    color=list(flag_counts.values()),
                    color_continuous_scale='Sunset'
                )
                fig_flags.update_layout(
                    showlegend=False,
                    height=350,
                    margin=dict(l=20, r=20, t=20, b=20)
                )
                st.plotly_chart(fig_flags, width="stretch")
            else:
                st.info("No TCP flag data available in captured flows")

        # Row 6: Traffic heatmap by hour
        st.subheader("Traffic Heatmap (Bytes by Hour and Protocol)")
        df['hour'] = df['timestamp'].dt.hour
        heatmap_data = df.groupby(['hour', 'Protocol'])['Bytes'].sum().reset_index()
        heatmap_pivot = heatmap_data.pivot(index='Protocol', columns='hour', values='Bytes').fillna(0)

        fig_heatmap = px.imshow(
            heatmap_pivot,
            labels=dict(x="Hour of Day", y="Protocol", color="Bytes"),
            x=heatmap_pivot.columns,
            y=heatmap_pivot.index,
            color_continuous_scale='YlOrRd',
            aspect='auto'
        )
        fig_heatmap.update_layout(height=250, margin=dict(l=20, r=20, t=20, b=20))
        st.plotly_chart(fig_heatmap, width="stretch")

        # Row 7: Domain analysis (if DNS resolved data exists)
        domains_resolved = df[df['Domain'] != '-']
        if len(domains_resolved) > 0:
            st.subheader("Top 10 Domains (by Flow Count)")
            top_domains = domains_resolved['Domain'].value_counts().head(10)

            fig_domains = px.bar(
                x=top_domains.values,
                y=top_domains.index,
                orientation='h',
                labels={'x': 'Flow Count', 'y': 'Domain'},
                color=top_domains.values,
                color_continuous_scale='Teal'
            )
            fig_domains.update_layout(
                showlegend=False,
                height=400,
                margin=dict(l=20, r=20, t=20, b=20),
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig_domains, width="stretch")

        # Summary statistics
        st.markdown("---")
        st.subheader("📈 Summary Statistics")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Packets", f"{df['Packets'].sum():,}")
        with col2:
            st.metric("Total Bytes", f"{df['Bytes'].sum():,}")
        with col3:
            avg_duration = df['Duration (s)'].mean()
            st.metric("Avg Flow Duration", f"{avg_duration:.2f}s")
        with col4:
            unique_ips = len(set(df['src_ip'].unique()) | set(df['dst_ip'].unique()))
            st.metric("Unique IPs", unique_ips)

    else:
        st.warning("No flows found matching the filters.")
else:
    st.warning("No flows found matching the filters.")
