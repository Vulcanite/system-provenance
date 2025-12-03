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
    try:
        filters["pid"] = int(pid_filter)
    except ValueError:
        st.sidebar.error("PID must be a number")
if ppid_filter:
    try:
        filters["ppid"] = int(ppid_filter)
    except ValueError:
        st.sidebar.error("PPID must be a number")

# Events per page - default to 1000
page_size = st.sidebar.selectbox("Events per page", [500, 1000, 2000, 5000], index=1)

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

        # Create DataFrame for table view
        table_data = []
        for event in events:
            # Determine event type
            syscall = event.get("syscall", "unknown")
            if syscall in ["connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom"]:
                event_type = "🌐 Network"
            elif syscall in ["execve", "clone", "clone3", "vfork"]:
                event_type = "⚙️ Process"
            elif syscall in ["openat", "openat2", "read", "write", "unlinkat"]:
                event_type = "📂 File"
            else:
                event_type = "📝 Other"

            # Build target field based on syscall type
            target = ""
            if event.get("filename"):
                target = event.get("filename", "")
            elif event.get("dest_ip"):
                target = f"{event.get('dest_ip', '')}:{event.get('dest_port', '')}"
            elif event.get("src_ip"):
                target = f"{event.get('src_ip', '')}:{event.get('src_port', '')}"

            # Truncate target if too long
            if len(target) > 60:
                target = target[:57] + "..."

            # Format return value
            ret_val = event.get("ret", 0)
            if ret_val < 0:
                ret_str = f"❌ {ret_val}"
            else:
                ret_str = str(ret_val)

            table_data.append({
                "Timestamp": event.get("datetime", "N/A")[:19] if event.get("datetime") else "N/A",
                "Hostname": event.get("hostname", "N/A"),
                "Type": event_type,
                "Syscall": syscall,
                "Process": event.get("comm", "unknown"),
                "PID": event.get("pid", "N/A"),
                "PPID": event.get("ppid", "N/A"),
                "UID": event.get("uid", "N/A"),
                "Target": target,
                "Return": ret_str,
                "Error": event.get("error", ""),
            })

        df = pd.DataFrame(table_data)

        # Configure column widths and display
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "Hostname": st.column_config.TextColumn("Hostname", width="small"),
                "Type": st.column_config.TextColumn("Type", width="small"),
                "Syscall": st.column_config.TextColumn("Syscall", width="small"),
                "Process": st.column_config.TextColumn("Process", width="small"),
                "PID": st.column_config.NumberColumn("PID", width="small"),
                "PPID": st.column_config.NumberColumn("PPID", width="small"),
                "UID": st.column_config.NumberColumn("UID", width="small"),
                "Target": st.column_config.TextColumn("Target", width="large"),
                "Return": st.column_config.TextColumn("Return", width="small"),
                "Error": st.column_config.TextColumn("Error", width="small"),
            }
        )

        # Summary statistics
        st.markdown("---")
        st.subheader("📊 Event Statistics (Current Page)")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            syscall_counts = df['Syscall'].value_counts()
            st.metric("Unique Syscalls", len(syscall_counts))

        with col2:
            process_counts = df['Process'].value_counts()
            st.metric("Unique Processes", len(process_counts))

        with col3:
            error_count = len(df[df['Error'] != ''])
            st.metric("Errors", error_count)

        with col4:
            network_events = len(df[df['Type'] == '🌐 Network'])
            st.metric("Network Events", network_events)

        # Top syscalls and processes
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Top 10 Syscalls**")
            top_syscalls = df['Syscall'].value_counts().head(10)
            for syscall, count in top_syscalls.items():
                st.write(f"- `{syscall}`: {count:,}")

        with col2:
            st.markdown("**Top 10 Processes**")
            top_processes = df['Process'].value_counts().head(10)
            for process, count in top_processes.items():
                st.write(f"- `{process}`: {count:,}")

        # Export option
        st.markdown("---")
        if st.button("📥 Export Current Page as JSON"):
            json_str = json.dumps(events, indent=2)
            st.download_button(
                label="Download JSON",
                data=json_str,
                file_name=f"ebpf_events_page_{page}.json",
                mime="application/json"
            )

    else:
        st.warning("No events found for this page.")
else:
    st.warning("No events found matching the filters.")
