#!/usr/bin/env python3
"""PCAP Flows Viewer Page"""

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import json
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
    index=1
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
hostname_options = ["All"] + hostnames
hostname_filter = st.sidebar.selectbox("Hostname", hostname_options)

# Protocol filter
protocol_filter = st.sidebar.selectbox("Protocol", ["All", "TCP", "UDP"])

# IP filters
src_ip_filter = st.sidebar.text_input("Source IP (exact match)", "")
dst_ip_filter = st.sidebar.text_input("Destination IP (exact match)", "")
port_filter = st.sidebar.text_input("Port (src or dst)", "")

# Build filters dict
filters = {}
if hostname_filter != "All":
    filters["hostname"] = hostname_filter
if protocol_filter != "All":
    filters["protocol"] = protocol_filter
if src_ip_filter:
    filters["src_ip"] = src_ip_filter
if dst_ip_filter:
    filters["dst_ip"] = dst_ip_filter

# Pagination
page_size = st.sidebar.selectbox("Flows per page", [50, 100, 200, 500], index=1)

# Main content
st.markdown("---")

# Get total count
total_count = get_event_count(es, pcap_index, start_ms, end_ms, filters)
st.info(f"📊 **Total Flows:** {total_count:,}")

if total_count > 0:
    total_pages = (total_count + page_size - 1) // page_size

    col1, col2, col3 = st.columns([2, 3, 2])
    with col2:
        page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)

    # Fetch flows
    with st.spinner(f"Loading page {page}/{total_pages}..."):
        flows = fetch_events(es, pcap_index, start_ms, end_ms, filters, page, page_size, sort_field="first_seen")

    if flows:
        st.success(f"✅ Showing {len(flows)} flows (Page {page} of {total_pages})")

        # Display as table and expandable cards
        # Create DataFrame for table view
        table_data = []
        for flow in flows:
            table_data.append({
                "Hostname": flow.get("hostname", "N/A"),
                "Protocol": flow.get("protocol", "N/A"),
                "Source": f"{flow.get('src_ip', 'N/A')}:{flow.get('src_port', '')}",
                "Destination": f"{flow.get('dst_ip', 'N/A')}:{flow.get('dst_port', '')}",
                "Domain": flow.get("domain_name", "-") if flow.get("dns_resolved") else "-",
                "Packets": flow.get("packet_count", 0),
                "Bytes": flow.get("byte_count", 0),
                "Duration": f"{(flow.get('epoch_last', 0) - flow.get('epoch_first', 0)) / 1000:.2f}s",
                "First Seen": flow.get("datetime_first", "N/A")[:19] if flow.get("datetime_first") else "N/A"
            })

        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.subheader("📋 Detailed Flow Information")

        # Display detailed info in expanders
        for idx, flow in enumerate(flows):
            src = f"{flow.get('src_ip', 'N/A')}:{flow.get('src_port', '')}"
            dst = f"{flow.get('dst_ip', 'N/A')}:{flow.get('dst_port', '')}"
            protocol = flow.get("protocol", "N/A")
            domain = flow.get("domain_name", "")

            # Title with domain if available
            if domain:
                title = f"🌐 {protocol} | {src} → {dst} | **{domain}**"
            else:
                title = f"🌐 {protocol} | {src} → {dst}"

            with st.expander(title):
                # Hostname display
                st.markdown(f"**🖥️ Hostname:** `{flow.get('hostname', 'N/A')}`")
                st.markdown("---")

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.markdown("**Source:**")
                    st.write(f"- **IP:** {flow.get('src_ip', 'N/A')}")
                    st.write(f"- **Port:** {flow.get('src_port', 'N/A')}")

                with col2:
                    st.markdown("**Destination:**")
                    st.write(f"- **IP:** {flow.get('dst_ip', 'N/A')}")
                    st.write(f"- **Port:** {flow.get('dst_port', 'N/A')}")
                    if domain:
                        st.write(f"- **Domain:** `{domain}`")
                        st.write(f"- **DNS Resolved:** ✅")

                with col3:
                    st.markdown("**Statistics:**")
                    st.write(f"- **Protocol:** {protocol}")
                    st.write(f"- **Packets:** {flow.get('packet_count', 0):,}")
                    st.write(f"- **Bytes:** {flow.get('byte_count', 0):,}")

                # TCP Flags
                if flow.get("tcp_flags"):
                    st.markdown("**TCP Flags:**")
                    st.code(", ".join(flow.get("tcp_flags", [])))

                # Timing
                st.markdown("**Timing:**")
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"- **First Seen:** {flow.get('datetime_first', 'N/A')}")
                with col2:
                    st.write(f"- **Last Seen:** {flow.get('datetime_last', 'N/A')}")

                duration_ms = flow.get('epoch_last', 0) - flow.get('epoch_first', 0)
                st.write(f"- **Duration:** {duration_ms / 1000:.3f} seconds")

                # Raw JSON
                with st.expander("🔍 Raw JSON"):
                    st.json(flow)

    else:
        st.warning("No flows found for this page.")
else:
    st.warning("No flows found matching the filters.")

# Statistics
if total_count > 0:
    st.markdown("---")
    st.subheader("📈 Flow Statistics")

    try:
        # Top destinations by packet count
        query = {
            "query": {
                "range": {"epoch_first": {"gte": start_ms, "lte": end_ms}}
            },
            "aggs": {
                "top_destinations": {
                    "terms": {"field": "dst_ip", "size": 10, "order": {"total_packets": "desc"}},
                    "aggs": {
                        "total_packets": {"sum": {"field": "packet_count"}}
                    }
                },
                "top_ports": {
                    "terms": {"field": "dst_port", "size": 10, "order": {"total_packets": "desc"}},
                    "aggs": {
                        "total_packets": {"sum": {"field": "packet_count"}}
                    }
                }
            },
            "size": 0
        }

        if es.indices.exists(index=pcap_index):
            response = es.search(index=pcap_index, body=query)

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**Top Destination IPs** (by packet count)")
                if "aggregations" in response and "top_destinations" in response["aggregations"]:
                    for bucket in response["aggregations"]["top_destinations"]["buckets"]:
                        st.write(f"- `{bucket['key']}`: {int(bucket['total_packets']['value']):,} packets")

            with col2:
                st.markdown("**Top Destination Ports** (by packet count)")
                if "aggregations" in response and "top_ports" in response["aggregations"]:
                    for bucket in response["aggregations"]["top_ports"]["buckets"]:
                        port = bucket['key']
                        # Common ports
                        port_names = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP", 3306: "MySQL"}
                        port_label = f"{port} ({port_names.get(port, 'Unknown')})"
                        st.write(f"- `{port_label}`: {int(bucket['total_packets']['value']):,} packets")

    except Exception as e:
        st.warning(f"Unable to fetch statistics: {e}")

# Export option
if total_count > 0:
    st.markdown("---")
    if st.button("📥 Export Current Page as JSON"):
        json_str = json.dumps(flows, indent=2)
        st.download_button(
            label="Download JSON",
            data=json_str,
            file_name=f"pcap_flows_page_{page}.json",
            mime="application/json"
        )
