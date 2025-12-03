#!/usr/bin/env python3
"""
Flow-Process Correlation Analysis Page
Matches network flows (PCAP) with system processes (eBPF) to identify 'Who' made the connection.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path to import utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch, to_epoch_ms

st.set_page_config(layout="wide")
st.title("🔗 Network-Process Correlation")
st.markdown("### Linking Packet Flows to System Processes")

# --- CONFIGURATION ---
config = load_config()
es_config = config.get("es_config", {})
pcap_index = es_config.get("pcap_index", "pcap-flows")
ebpf_index = es_config.get("ebpf_index", "ebpf-events")

es = connect_elasticsearch(es_config)

# --- SIDEBAR FILTERS ---
st.sidebar.header("🔍 Analysis Parameters")

# Hostname filter (for multi-host deployments)
from utils import get_unique_hostnames
hostnames = get_unique_hostnames(es, pcap_index)
hostname_options = ["All"] + hostnames
hostname_filter = st.sidebar.selectbox("Hostname", hostname_options)

# Time Range
time_range = st.sidebar.selectbox(
    "Analysis Window",
    ["Last 15 Minutes", "Last 1 Hour", "Last 6 Hours", "Last 24 Hours"],
    index=1
)

# Correlation Window (Sensitivity)
correlation_window = st.sidebar.slider(
    "Time Correlation Window (seconds)",
    min_value=1,
    max_value=30,
    value=5,
    help="Max time difference between a network packet flow starting and a process syscall occurring."
)

# Calculate timestamps
end_dt = datetime.now()
if time_range == "Last 15 Minutes":
    start_dt = end_dt - timedelta(minutes=15)
elif time_range == "Last 1 Hour":
    start_dt = end_dt - timedelta(hours=1)
elif time_range == "Last 6 Hours":
    start_dt = end_dt - timedelta(hours=6)
else:
    start_dt = end_dt - timedelta(hours=24)

start_ms = to_epoch_ms(start_dt)
end_ms = to_epoch_ms(end_dt)

# --- DATA FETCHING ---

@st.cache_data(ttl=60)
def fetch_data(start_ms, end_ms, hostname_filter=None):
    # Build hostname filter
    hostname_clause = []
    if hostname_filter and hostname_filter != "All":
        hostname_clause = [{"term": {"hostname.keyword": hostname_filter}}]

    # 1. Fetch PCAP Flows
    pcap_query = {
        "size": 10000,  # Increased from 5000
        "query": {
            "bool": {
                "must": [
                    {"range": {"epoch_first": {"gte": start_ms, "lte": end_ms}}}
                ] + hostname_clause
            }
        },
        "sort": [{"epoch_first": "asc"}]
    }

    # 2. Fetch eBPF Network Events (connect, accept, sendto, recvfrom)
    ebpf_query = {
        "size": 10000,  # Increased from 5000 for high-traffic environments
        "query": {
            "bool": {
                "must": [
                    {"range": {"epoch_timestamp": {"gte": start_ms, "lte": end_ms}}},
                    {"terms": {"syscall.keyword": ["connect", "accept", "accept4", "sendto", "recvfrom"]}}
                ] + hostname_clause
            }
        },
        "sort": [{"epoch_timestamp": "asc"}]  # Sort for efficient processing
    }

    try:
        pcap_res = es.search(index=pcap_index, body=pcap_query)
        ebpf_res = es.search(index=ebpf_index, body=ebpf_query)
        
        pcap_hits = [h['_source'] for h in pcap_res['hits']['hits']]
        ebpf_hits = [h['_source'] for h in ebpf_res['hits']['hits']]
        
        return pcap_hits, ebpf_hits
    except Exception as e:
        st.error(f"Elasticsearch error: {e}")
        return [], []

def perform_correlation(flows, events, window_sec):
    correlated_data = []

    # Bucket events by timestamp for performance
    event_map = {}

    for e in events:
        ts_sec = int(e.get('epoch_timestamp', 0) / 1000)
        if ts_sec not in event_map:
            event_map[ts_sec] = []
        event_map[ts_sec].append(e)

    # Iterate PCAP flows (The "Truth")
    for f in flows:
        # PCAP always has full 5-tuple
        pcap_src = f.get('src_ip')
        pcap_dst = f.get('dst_ip')
        pcap_sport = f.get('src_port')
        pcap_dport = f.get('dst_port')

        flow_start_ms = f.get('epoch_first', 0)
        start_ts_sec = int(flow_start_ms / 1000)

        match = None
        time_delta = None  # For confidence scoring

        # Search window
        for offset in range(-window_sec, window_sec + 1):
            check_ts = start_ts_sec + offset
            if check_ts not in event_map:
                continue

            for e in event_map[check_ts]:
                syscall = e.get('syscall')
                event_ts_ms = e.get('epoch_timestamp', 0)

                # LOGIC: Match on the "Remote Peer" only
                candidate_match = None

                # Case 1: Outgoing (connect/sendto)
                # PCAP: Local -> Remote
                # eBPF: Knows Dest (Remote)
                if syscall in ['connect', 'sendto']:
                    if (e.get('dest_ip') == pcap_dst and
                        e.get('dest_port') == pcap_dport):
                        candidate_match = e

                # Case 2: Incoming (accept/recvfrom)
                # PCAP: Remote -> Local
                # eBPF: Knows Src (Remote)
                elif syscall in ['accept', 'accept4', 'recvfrom']:
                    if (e.get('src_ip') == pcap_src and
                        e.get('src_port') == pcap_sport):
                        candidate_match = e

                # Validate candidate with PID reuse protection
                if candidate_match:
                    process_start_time = candidate_match.get('process_start_time', 0)

                    # PID Reuse Check: Process must exist BEFORE flow started
                    # process_start_time is in nanoseconds, convert to ms
                    process_start_ms = process_start_time / 1_000_000  # ns -> ms

                    # If process started AFTER flow, it's likely PID reuse - reject
                    if process_start_ms > 0 and process_start_ms > flow_start_ms:
                        # Process started after flow - PID was recycled
                        continue

                    # Valid match - calculate time delta for confidence
                    delta_ms = abs(event_ts_ms - flow_start_ms)

                    # Keep best match (closest in time)
                    if match is None or delta_ms < time_delta:
                        match = candidate_match
                        time_delta = delta_ms

            # Continue searching for better match within window

        # Calculate confidence based on time delta
        confidence = "Unknown"
        if match and time_delta is not None:
            delta_sec = time_delta / 1000.0
            if delta_sec <= 1.0:
                confidence = "🟢 High"
            elif delta_sec <= 3.0:
                confidence = "🟡 Medium"
            else:
                confidence = "🟠 Low"

        # Build Entry
        entry = {
            'Time': f.get('datetime_first'),
            'Source': f"{pcap_src}:{pcap_sport}",
            'Destination': f"{pcap_dst}:{pcap_dport}",
            'Bytes': f.get('byte_count'),
            'Protocol': f.get('protocol'),
            'Domain': f.get('domain_name', '-'),
            'Process': match['comm'] if match else '❓ Unidentified',
            'PID': match['pid'] if match else None,
            'Syscall': match['syscall'] if match else None,
            'Confidence': confidence,
            'Time_Delta_ms': int(time_delta) if time_delta is not None else None,
            'Match': True if match else False
        }
        correlated_data.append(entry)

    return pd.DataFrame(correlated_data)
# --- MAIN LOGIC ---

with st.spinner("Fetching data from Elasticsearch..."):
    pcap_data, ebpf_data = fetch_data(start_ms, end_ms, hostname_filter)

if not pcap_data:
    st.warning("No PCAP flow data found for this time range.")
else:
    col1, col2, col3 = st.columns(3)
    col1.metric("Network Flows (PCAP)", len(pcap_data))
    col2.metric("Process Events (eBPF)", len(ebpf_data))
    
    # RUN CORRELATION
    df = perform_correlation(pcap_data, ebpf_data, correlation_window)
    
    match_count = len(df[df['Match'] == True])
    match_pct = (match_count / len(df)) * 100 if len(df) > 0 else 0
    
    col3.metric("Correlated Flows", f"{match_count}", f"{match_pct:.1f}% Match Rate")
    
    st.markdown("---")

    # --- VISUALIZATIONS ---
    
    # 1. SANKEY DIAGRAM (Process -> Domain/Dest)
    st.subheader("📊 Flow Attribution Sankey")
    
    if match_count > 0:
        matched_df = df[df['Match'] == True].copy()
        
        # Aggregate for cleaner graph
        # Group by Process -> Destination (IP or Domain if avail)
        matched_df['Target'] = matched_df.apply(lambda x: x['Domain'] if x['Domain'] != '-' else x['Destination'].split(':')[0], axis=1)
        
        sankey_data = matched_df.groupby(['Process', 'Target'])['Bytes'].sum().reset_index()
        sankey_data = sankey_data.sort_values('Bytes', ascending=False).head(30) # Top 30 heavy flows
        
        # Create nodes
        all_nodes = list(pd.concat([sankey_data['Process'], sankey_data['Target']]).unique())
        node_map = {node: i for i, node in enumerate(all_nodes)}
        
        fig = go.Figure(data=[go.Sankey(
            node = dict(
                pad = 15,
                thickness = 20,
                line = dict(color = "black", width = 0.5),
                label = all_nodes,
                color = "blue"
            ),
            link = dict(
                source = [node_map[x] for x in sankey_data['Process']],
                target = [node_map[x] for x in sankey_data['Target']],
                value = sankey_data['Bytes']
            )
        )])
        
        fig.update_layout(title_text="Data Volume: Process ⮕ Destination", font_size=10, height=500)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Not enough correlated data to generate Sankey diagram.")

    # 2. SHADOW IT / UNIDENTIFIED TRAFFIC
    st.subheader("🕵️ Unidentified Traffic (Ghost Flows)")
    unmatched = df[df['Match'] == False]
    
    if len(unmatched) > 0:
        st.caption("Flows where no matching Process start/connect event was found (Potential Rootkits, Kernel Traffic, or Sampling Gaps)")
        
        # Show top unmatched by Bytes
        top_ghosts = unmatched.sort_values('Bytes', ascending=False).head(10)
        st.dataframe(
            top_ghosts[['Time', 'Source', 'Destination', 'Protocol', 'Bytes', 'Domain']], 
            use_container_width=True,
            hide_index=True
        )
    else:
        st.success("✅ Amazing! 100% of network traffic has been attributed to specific processes.")

    # 3. DETAILED DATA TABLE
    st.subheader("📝 Full Enriched Flow Log")

    # Formatting for display
    display_df = df.copy()
    display_df['Match Status'] = display_df['Match'].apply(lambda x: "✅ Verified" if x else "⚠️ Unknown")

    # Reorder columns (added Confidence and Time_Delta_ms)
    cols = ['Time', 'Match Status', 'Confidence', 'Process', 'PID', 'Source', 'Destination', 'Domain', 'Protocol', 'Bytes', 'Syscall', 'Time_Delta_ms']
    st.dataframe(
        display_df[cols].sort_values('Time', ascending=False),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Time_Delta_ms": st.column_config.NumberColumn("Time Δ (ms)", help="Time difference between flow start and syscall")
        }
    )

    # Add confidence distribution metrics
    st.markdown("---")
    st.subheader("🎯 Correlation Quality Metrics")

    if match_count > 0:
        col1, col2, col3, col4 = st.columns(4)

        high_conf = len(df[df['Confidence'] == '🟢 High'])
        medium_conf = len(df[df['Confidence'] == '🟡 Medium'])
        low_conf = len(df[df['Confidence'] == '🟠 Low'])

        col1.metric("High Confidence", high_conf, f"{(high_conf/match_count)*100:.1f}%")
        col2.metric("Medium Confidence", medium_conf, f"{(medium_conf/match_count)*100:.1f}%")
        col3.metric("Low Confidence", low_conf, f"{(low_conf/match_count)*100:.1f}%")

        # Average time delta
        avg_delta = df[df['Time_Delta_ms'].notna()]['Time_Delta_ms'].mean()
        col4.metric("Avg Time Delta", f"{avg_delta:.0f} ms")
    else:
        st.info("No correlated flows to analyze confidence metrics.")