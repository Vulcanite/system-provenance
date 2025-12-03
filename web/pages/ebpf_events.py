#!/usr/bin/env python3
"""eBPF Events Viewer Page"""

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch, get_event_count, fetch_events, to_epoch_ms, get_unique_hostnames

st.title("📝 eBPF Events")
st.markdown("### Real-time Syscall Event Viewer")

# Load configuration
config = load_config()
es_config = config.get("es_config", {})
ebpf_index = es_config.get("ebpf_index", "ebpf-events")

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
hostnames = get_unique_hostnames(es, ebpf_index)
hostname_options = ["All"] + hostnames
hostname_filter = st.sidebar.selectbox("Hostname", hostname_options)

# Additional filters
syscall_filter = st.sidebar.text_input("Syscall (exact match)", "")
comm_filter = st.sidebar.text_input("Process Name (exact match)", "")
pid_filter = st.sidebar.text_input("PID", "")
ppid_filter = st.sidebar.text_input("PPID", "")

# Build filters dict
filters = {}
if hostname_filter != "All":
    filters["hostname"] = hostname_filter
if syscall_filter:
    filters["syscall"] = syscall_filter
if comm_filter:
    filters["comm"] = comm_filter
if pid_filter:
    filters["pid"] = int(pid_filter)
if ppid_filter:
    filters["ppid"] = int(ppid_filter)

# Pagination
page_size = st.sidebar.selectbox("Events per page", [100, 500, 1000, 2000], index=1)

# Main content
st.markdown("---")

# Get total count
total_count = get_event_count(es, ebpf_index, start_ms, end_ms, filters)
st.info(f"📊 **Total Events:** {total_count:,}")

if total_count > 0:
    total_pages = (total_count + page_size - 1) // page_size

    col1, col2, col3 = st.columns([2, 3, 2])
    with col2:
        page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)

    # Fetch events
    with st.spinner(f"Loading page {page}/{total_pages}..."):
        events = fetch_events(es, ebpf_index, start_ms, end_ms, filters, page, page_size)

    if events:
        st.success(f"✅ Showing {len(events)} events (Page {page} of {total_pages})")

        # Display as expandable cards
        for idx, event in enumerate(events):
            timestamp = event.get("datetime", "N/A")
            syscall = event.get("syscall", "unknown")
            comm = event.get("comm", "unknown")
            pid = event.get("pid", "N/A")
            filename = event.get("filename", "")
            ret_val = event.get("ret", 0)

            # Determine event type for styling
            if syscall in ["connect", "bind", "listen", "accept", "sendto", "recvfrom"]:
                event_type = "🌐 Network"
            elif syscall in ["execve", "clone", "vfork"]:
                event_type = "⚙️ Process"
            elif syscall in ["openat", "read", "write", "unlinkat"]:
                event_type = "📂 File"
            else:
                event_type = "📝 Other"

            # Create expander title
            title = f"{event_type} | `{syscall}` | **{comm}** (PID:{pid}) | {timestamp}"

            with st.expander(title):
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("**Process Info:**")
                    st.write(f"- **Hostname:** `{event.get('hostname', 'N/A')}`")
                    st.write(f"- **Command:** `{comm}`")
                    st.write(f"- **PID:** {pid}")
                    st.write(f"- **PPID:** {event.get('ppid', 'N/A')}")
                    st.write(f"- **UID:** {event.get('uid', 'N/A')}")

                with col2:
                    st.markdown("**Syscall Details:**")
                    st.write(f"- **Syscall:** `{syscall}`")
                    st.write(f"- **Return Value:** {ret_val}")
                    if event.get("error"):
                        st.write(f"- **Error:** {event.get('error')}")

                # Additional details based on syscall type
                if filename:
                    st.markdown("**File:**")
                    st.code(filename, language=None)

                # Network details
                if event.get("dest_ip") or event.get("src_ip"):
                    st.markdown("**Network:**")
                    if event.get("src_ip"):
                        st.write(f"- **Source:** {event.get('src_ip')}:{event.get('src_port', '')}")
                    if event.get("dest_ip"):
                        st.write(f"- **Destination:** {event.get('dest_ip')}:{event.get('dest_port', '')}")
                    if event.get("sa_family"):
                        st.write(f"- **Family:** {event.get('sa_family')}")
                    if event.get("protocol"):
                        st.write(f"- **Protocol:** {event.get('protocol')}")

                # I/O details
                if event.get("bytes_rw"):
                    st.write(f"**Bytes:** {event.get('bytes_rw')} bytes")

                # Raw JSON
                with st.expander("🔍 Raw JSON"):
                    st.json(event)

    else:
        st.warning("No events found for this page.")
else:
    st.warning("No events found matching the filters.")

# Export option
if total_count > 0:
    st.markdown("---")
    if st.button("📥 Export Current Page as JSON"):
        json_str = json.dumps(events, indent=2)
        st.download_button(
            label="Download JSON",
            data=json_str,
            file_name=f"ebpf_events_page_{page}.json",
            mime="application/json"
        )
