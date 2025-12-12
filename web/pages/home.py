#!/usr/bin/env python3
"""Home/Dashboard page for System Provenance Monitor"""

import streamlit as st
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch, get_event_count, get_unique_hostnames

st.title("🏠 Dashboard")
st.markdown("### Real-time System Monitoring Overview")

# Load configuration
config = load_config()
es_config = config.get("es_config", {})

# Connection status
col3, col4 = st.columns(2)

with col3:
    try:
        es = connect_elasticsearch(es_config)
        st.metric("✅ Elasticsearch", "Connected", delta="Healthy")
    except:
        st.metric("❌ Elasticsearch", "Disconnected", delta="Error")

with col4:
    try:
        es = connect_elasticsearch(es_config)
        ebpf_index = es_config.get("ebpf_index", "ebpf-events")
        hostnames = get_unique_hostnames(es, ebpf_index)
        st.metric("🖥️ Monitored Hosts", len(hostnames))
    except:
        st.metric("🖥️ Monitored Hosts", "N/A")

st.markdown("---")

# Event Statistics (Last 24 hours)
st.subheader("📊 Last 24 Hours Activity")

now = datetime.now()
start_24h = now - timedelta(hours=24)
start_ms = int(start_24h.timestamp() * 1000)
end_ms = int(now.timestamp() * 1000)

try:
    es = connect_elasticsearch(es_config)
    col1, col2, col3 = st.columns(3)

    with col1:
        ebpf_index = es_config.get("ebpf_index", "ebpf-events")
        total_events = get_event_count(es, ebpf_index, start_ms, end_ms)
        st.metric("📝 eBPF Events", f"{total_events:,}")

    with col2:
        pcap_index = es_config.get("pcap_index", "pcap-flows")
        total_flows = get_event_count(es, pcap_index, start_ms, end_ms)
        st.metric("🌐 PCAP Flows", f"{total_flows:,}")

    with col3:
        auditd_index = es_config.get("auditd_index", "auditd-events")
        total_flows = get_event_count(es, auditd_index, start_ms, end_ms)
        st.metric("📊 Auditd Events", f"{total_flows:,}")

except Exception as e:
    st.error(f"Unable to fetch statistics: {e}")

st.markdown("---")

# Recent Activity Summary
st.subheader("🕐 Recent Activity (Last Hour)")

try:
    start_1h = now - timedelta(hours=1)
    start_ms_1h = int(start_1h.timestamp() * 1000)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Top Syscalls**")
        # Simple aggregation for top syscalls
        query = {
            "query": {
                "range": {"epoch_timestamp": {"gte": start_ms_1h, "lte": end_ms}}
            },
            "aggs": {
                "top_syscalls": {
                    "terms": {"field": "syscall.keyword", "size": 5}
                }
            },
            "size": 0
        }

        if es.indices.exists(index=ebpf_index):
            response = es.search(index=ebpf_index, body=query)
            if "aggregations" in response and "top_syscalls" in response["aggregations"]:
                for bucket in response["aggregations"]["top_syscalls"]["buckets"]:
                    st.write(f"- `{bucket['key']}`: {bucket['doc_count']:,} events")

    with col2:
        st.markdown("**Top Processes**")
        query["aggs"] = {
            "top_procs": {
                "terms": {"field": "comm.keyword", "size": 5}
            }
        }

        if es.indices.exists(index=ebpf_index):
            response = es.search(index=ebpf_index, body=query)
            if "aggregations" in response and "top_procs" in response["aggregations"]:
                for bucket in response["aggregations"]["top_procs"]["buckets"]:
                    st.write(f"- `{bucket['key']}`: {bucket['doc_count']:,} events")

except Exception as e:
    st.warning(f"Unable to fetch recent activity: {e}")

st.markdown("---")

# Quick Actions
st.subheader("⚡ Quick Actions")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("📝 View eBPF Events", width="stretch"):
        st.switch_page("pages/ebpf_events.py")

with col2:
    if st.button("🌐 View PCAP Flows", width="stretch"):
        st.switch_page("pages/pcap_flows.py")

with col3:
    if st.button("🔍 View Auditd Events", width="stretch"):
        st.switch_page("pages/auditd_events.py")

st.markdown("---")
st.caption("💡 Tip: Use the sidebar to navigate between different analysis views.")
