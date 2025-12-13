#!/usr/bin/env python3
"""
SPECTRA Unified Timeline Dashboard
Displays eBPF, PCAP, and Auditd events in a single chronological timeline
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import json

st.set_page_config(page_title="Unified Timeline | SPECTRA", page_icon="📅", layout="wide")

# Load configuration
config_path = '/var/monitoring/config.json'
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
except Exception as e:
    st.error(f"Failed to load configuration: {e}")
    st.stop()

es_config = config.get('es_config', {})
output_dir = config.get('output_dir', '/var/monitoring/outputs')

# Initialize Elasticsearch
@st.cache_resource
def get_es_client():
    es_host = es_config.get("es_host", "localhost")
    es_port = es_config.get("es_port", "9200")
    es_user = es_config.get("es_user", None)
    es_pass = es_config.get("es_password", None)
    is_ssl = es_config.get("secure", False)

    host_url = f"{'https' if is_ssl else 'http'}://{es_host}:{es_port}"

    return Elasticsearch(
        [host_url],
        basic_auth=(es_user, es_pass),
        verify_certs=False,
        ssl_show_warn=False,
        request_timeout=30
    )

es = get_es_client()

# Page Header
st.title("📅 SPECTRA Unified Timeline")
st.markdown("**Multi-Source Event Correlation Dashboard**")
st.caption("Visualize eBPF, PCAP, and Auditd events in a single timeline for comprehensive attack analysis")

# Sidebar Filters
st.sidebar.header("🔍 Timeline Filters")

# Time range selection
col1, col2 = st.sidebar.columns(2)
with col1:
    start_date = st.date_input("Start Date", value=datetime.now().date() - timedelta(days=1))
    start_time = st.time_input("Start Time", value=datetime.now().time())

with col2:
    end_date = st.date_input("End Date", value=datetime.now().date())
    end_time = st.time_input("End Time", value=datetime.now().time())

start_dt = datetime.combine(start_date, start_time)
end_dt = datetime.combine(end_date, end_time)

start_ms = int(start_dt.timestamp() * 1000)
end_ms = int(end_dt.timestamp() * 1000)

# Hostname filter
hostname = st.sidebar.text_input("Hostname (optional)", placeholder="e.g., server-02")

# Source selection
st.sidebar.subheader("📊 Data Sources")
include_ebpf = st.sidebar.checkbox("eBPF Events", value=True)
include_pcap = st.sidebar.checkbox("PCAP Flows", value=True)
include_auditd = st.sidebar.checkbox("Auditd Events", value=True)

# Event limit
max_events = st.sidebar.slider("Max Events per Source", 100, 10000, 1000, step=100)

# Process filter
process_filter = st.sidebar.text_input("Filter by Process Name", placeholder="e.g., attack.sh")

# Load button
load_button = st.sidebar.button("📥 Load Timeline", type="primary", width="stretch")

# Helper functions
def load_ebpf_events(start_ms, end_ms, hostname=None, max_events=1000, process_filter=None):
    """Load eBPF events from Elasticsearch"""
    must_filters = [
        {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}
    ]

    if hostname:
        must_filters.append({"term": {"hostname.keyword": hostname}})

    if process_filter:
        must_filters.append({"term": {"process.name.keyword": process_filter}})

    query = {
        "size": max_events,
        "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"must": must_filters}}
    }

    try:
        result = es.search(index=es_config.get("ebpf_index", "ebpf-events"), body=query)
        events = []
        for hit in result['hits']['hits']:
            src = hit['_source']
            events.append({
                'timestamp': src.get('timestamp', 0),
                'datetime': src.get('datetime', ''),
                'source': 'eBPF',
                'event_type': src.get('event.type', 'unknown'),
                'process': src.get('process.name', 'unknown'),
                'pid': src.get('process.pid', 0),
                'syscall': src.get('syscall', ''),
                'file': src.get('file.path', ''),
                'details': f"{src.get('syscall', '')} on {src.get('file.path', 'N/A')}"
            })
        return events
    except Exception as e:
        st.error(f"Error loading eBPF events: {e}")
        return []

def load_pcap_flows(start_ms, end_ms, hostname=None, max_events=1000):
    """Load PCAP flows from Elasticsearch"""
    must_filters = [
        {"range": {"epoch_first": {"gte": start_ms, "lte": end_ms}}}
    ]

    if hostname:
        must_filters.append({"term": {"hostname.keyword": hostname}})

    query = {
        "size": max_events,
        "sort": [{"epoch_first": "asc"}],
        "query": {"bool": {"must": must_filters}}
    }

    try:
        result = es.search(index=es_config.get("pcap_index", "pcap-flows"), body=query)
        flows = []
        for hit in result['hits']['hits']:
            src = hit['_source']
            flows.append({
                'timestamp': src.get('epoch_first', 0),
                'datetime': src.get('@timestamp', ''),
                'source': 'PCAP',
                'event_type': 'network',
                'process': f"{src.get('source.ip', '')}:{src.get('source.port', '')}",
                'pid': 0,
                'syscall': src.get('network.transport', 'TCP'),
                'file': f"{src.get('destination.ip', '')}:{src.get('destination.port', '')}",
                'details': f"{src.get('packet_count', 0)} pkts, {src.get('byte_count', 0)} bytes to {src.get('dns.query', src.get('destination.ip', ''))}"
            })
        return flows
    except Exception as e:
        st.error(f"Error loading PCAP flows: {e}")
        return []

def load_auditd_events(start_ms, end_ms, hostname=None, max_events=1000, process_filter=None):
    """Load Auditd events from Elasticsearch"""
    must_filters = [
        {"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}
    ]

    if hostname:
        must_filters.append({"term": {"hostname.keyword": hostname}})

    if process_filter:
        must_filters.append({"term": {"process.name.keyword": process_filter}})

    query = {
        "size": max_events,
        "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"must": must_filters}}
    }

    try:
        result = es.search(index=es_config.get("auditd_index", "auditd-events"), body=query)
        events = []
        for hit in result['hits']['hits']:
            src = hit['_source']
            raw = src.get('raw_data', {})
            events.append({
                'timestamp': src.get('timestamp', 0),
                'datetime': src.get('datetime', ''),
                'source': 'Auditd',
                'event_type': src.get('event.category', 'unknown'),
                'process': src.get('process.name', raw.get('comm', 'unknown')),
                'pid': src.get('process.pid', raw.get('pid', 0)),
                'syscall': raw.get('syscall', src.get('message', '')),
                'file': raw.get('object', raw.get('name', '')),
                'details': f"{src.get('message', '')} - {raw.get('result', '')}"
            })
        return events
    except Exception as e:
        st.error(f"Error loading Auditd events: {e}")
        return []

# Main content
if load_button or 'timeline_data' not in st.session_state:
    with st.spinner("Loading multi-source timeline..."):
        all_events = []

        # Load data from selected sources
        if include_ebpf:
            ebpf_events = load_ebpf_events(start_ms, end_ms, hostname, max_events, process_filter)
            all_events.extend(ebpf_events)
            st.sidebar.success(f"✅ eBPF: {len(ebpf_events)} events")

        if include_pcap:
            pcap_flows = load_pcap_flows(start_ms, end_ms, hostname, max_events)
            all_events.extend(pcap_flows)
            st.sidebar.success(f"✅ PCAP: {len(pcap_flows)} flows")

        if include_auditd:
            auditd_events = load_auditd_events(start_ms, end_ms, hostname, max_events, process_filter)
            all_events.extend(auditd_events)
            st.sidebar.success(f"✅ Auditd: {len(auditd_events)} events")

        # Store in session state
        st.session_state['timeline_data'] = all_events
        st.session_state['start_ms'] = start_ms
        st.session_state['end_ms'] = end_ms

# Display timeline if data is available
if 'timeline_data' in st.session_state and st.session_state['timeline_data']:
    df = pd.DataFrame(st.session_state['timeline_data'])

    # Sort by timestamp
    df = df.sort_values('timestamp')

    # Convert timestamp to datetime for display
    df['time'] = pd.to_datetime(df['timestamp'], unit='ms')

    # Summary metrics
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Events", len(df))

    with col2:
        ebpf_count = len(df[df['source'] == 'eBPF'])
        st.metric("eBPF Events", ebpf_count)

    with col3:
        pcap_count = len(df[df['source'] == 'PCAP'])
        st.metric("PCAP Flows", pcap_count)

    with col4:
        auditd_count = len(df[df['source'] == 'Auditd'])
        st.metric("Auditd Events", auditd_count)

    # Tabs for different visualizations
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Timeline Chart", "📋 Event Table", "🔀 Correlation Matrix", "📈 Statistics"])

    with tab1:
        st.markdown("### Unified Event Timeline")
        st.caption("Events colored by source - eBPF (blue), PCAP (green), Auditd (orange)")

        # Create timeline visualization
        fig = go.Figure()

        # Color mapping for sources
        colors = {
            'eBPF': '#3498db',     # Blue
            'PCAP': '#2ecc71',     # Green
            'Auditd': '#e67e22'    # Orange
        }

        for source in df['source'].unique():
            source_df = df[df['source'] == source]

            fig.add_trace(go.Scatter(
                x=source_df['time'],
                y=source_df['process'],
                mode='markers',
                name=source,
                marker=dict(
                    size=10,
                    color=colors.get(source, '#95a5a6'),
                    symbol='circle'
                ),
                text=source_df['details'],
                hovertemplate='<b>%{text}</b><br>Process: %{y}<br>Time: %{x}<extra></extra>'
            ))

        fig.update_layout(
            height=600,
            xaxis_title="Time",
            yaxis_title="Process/Source",
            hovermode='closest',
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )

        st.plotly_chart(fig, width="stretch")

    with tab2:
        st.markdown("### Event Details Table")

        # Add color coding to source column
        def highlight_source(row):
            if row['source'] == 'eBPF':
                return ['background-color: #3498db20'] * len(row)
            elif row['source'] == 'PCAP':
                return ['background-color: #2ecc7120'] * len(row)
            elif row['source'] == 'Auditd':
                return ['background-color: #e67e2220'] * len(row)
            return [''] * len(row)

        # Display table
        display_df = df[['time', 'source', 'process', 'pid', 'syscall', 'file', 'details']].copy()
        display_df['time'] = display_df['time'].dt.strftime('%Y-%m-%d %H:%M:%S.%f')

        st.dataframe(
            display_df.style.apply(highlight_source, axis=1),
            width="stretch",
            height=600
        )

        # Download button
        csv = display_df.to_csv(index=False)
        st.download_button(
            label="📥 Download CSV",
            data=csv,
            file_name=f"unified_timeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

    with tab3:
        st.markdown("### Cross-Source Correlation Matrix")
        st.caption("Showing temporal correlation between different data sources")

        # Create correlation heatmap
        # Group by time windows (1 second intervals)
        df['time_window'] = df['time'].dt.floor('1S')

        pivot_data = df.groupby(['time_window', 'source']).size().unstack(fill_value=0)

        if not pivot_data.empty:
            fig = px.imshow(
                pivot_data.T,
                labels=dict(x="Time Window", y="Data Source", color="Event Count"),
                aspect="auto",
                color_continuous_scale="Blues"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("Not enough data for correlation matrix")

    with tab4:
        st.markdown("### Timeline Statistics")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Events by Source")
            source_counts = df['source'].value_counts()
            fig = px.pie(
                values=source_counts.values,
                names=source_counts.index,
                color=source_counts.index,
                color_discrete_map=colors
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, width="stretch")

        with col2:
            st.markdown("#### Events by Process")
            process_counts = df['process'].value_counts().head(10)
            fig = px.bar(
                x=process_counts.values,
                y=process_counts.index,
                orientation='h',
                labels={'x': 'Event Count', 'y': 'Process'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, width="stretch")

        # Time distribution
        st.markdown("#### Event Distribution Over Time")
        df['hour'] = df['time'].dt.hour
        hourly_dist = df.groupby(['hour', 'source']).size().unstack(fill_value=0)

        fig = go.Figure()
        for source in hourly_dist.columns:
            fig.add_trace(go.Bar(
                x=hourly_dist.index,
                y=hourly_dist[source],
                name=source,
                marker_color=colors.get(source, '#95a5a6')
            ))

        fig.update_layout(
            barmode='stack',
            height=400,
            xaxis_title="Hour of Day",
            yaxis_title="Event Count"
        )
        st.plotly_chart(fig, width="stretch")

else:
    st.info("👆 Configure filters in the sidebar and click **Load Timeline** to visualize multi-source events")

# Footer
st.markdown("---")
st.markdown("**SPECTRA Unified Timeline** | Multi-source provenance analysis platform")
