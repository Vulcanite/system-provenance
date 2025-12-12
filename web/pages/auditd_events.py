#!/usr/bin/env python3
"""Auditd Events Viewer Page"""

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch, get_event_count, fetch_events, to_epoch_ms, get_unique_hostnames

st.title("🔐 Auditd Events")
st.markdown("### Linux Audit System - Identity, Persistence & Privilege Events")

# Load configuration
config = load_config()
es_config = config.get("es_config", {})
auditd_index = es_config.get("auditd_index", "auditd-events")

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
hostnames = get_unique_hostnames(es, auditd_index)
hostname_filter = st.sidebar.selectbox("Hostname", hostnames)

# Category filter
category_filter = st.sidebar.selectbox(
    "Event Category",
    ["All", "Executions", "Identity Changes", "Persistence", "Privilege Escalation", "Network Tools", "External Media"],
    index=0
)

# User filter
user_filter = st.sidebar.text_input("User ID (AUID)", "", help="Filter by audit user ID")

# Build filters dict
filters = {}
if hostname_filter != "All":
    filters["hostname"] = hostname_filter
if user_filter:
    filters["user.id"] = user_filter

# Category-specific tag mapping
category_tag_map = {
    "Executions": "audit_exec",
    "Identity Changes": "identity",
    "Persistence": "persistence",
    "Privilege Escalation": "priv-esc",
    "Network Tools": "network-tool",
    "External Media": "external-media"
}

if category_filter != "All":
    # Filter by tags array - this requires a special query structure
    tag = category_tag_map.get(category_filter)
    if tag:
        # Note: This will be handled in the fetch_events function if it supports tag filtering
        # For now, we'll filter after fetching
        pass

# Main content
st.markdown("---")

# Get total count
total_count = get_event_count(es, auditd_index, start_ms, end_ms, filters)
st.info(f"📊 **Total Events:** {total_count:,}")

if total_count > 0:
    # Fetch events for analysis and display
    with st.spinner("Loading audit events..."):
        analysis_events = fetch_events(es, auditd_index, start_ms, end_ms, filters, page=1, page_size=min(5000, total_count))

    if analysis_events:
        # Filter by category if needed
        if category_filter != "All":
            tag = category_tag_map.get(category_filter)
            if tag:
                analysis_events = [e for e in analysis_events if tag in e.get("tags", [])]

        # Create visualization section
        st.markdown("### 📊 Security Event Analysis")

        # Row 1: Top Privileged Users and Event Category Distribution
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Top 10 Active Users (by Event Count)")
            user_counts = {}
            for event in analysis_events:
                user_id = event.get("user.id", "unknown")
                if user_id and user_id != "unset" and user_id != "-1":
                    user_counts[user_id] = user_counts.get(user_id, 0) + 1

            if user_counts:
                top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                user_df = pd.DataFrame(top_users, columns=["User ID", "Event Count"])

                fig_users = px.bar(
                    user_df,
                    x="Event Count",
                    y="User ID",
                    orientation='h',
                    labels={'Event Count': 'Events', 'User ID': 'User'},
                    color="Event Count",
                    color_continuous_scale='Reds'
                )
                fig_users.update_layout(
                    showlegend=False,
                    height=400,
                    margin=dict(l=20, r=20, t=20, b=20),
                    yaxis={'categoryorder': 'total ascending'}
                )
                st.plotly_chart(fig_users, width="stretch")
            else:
                st.info("No user information available in audit events")

        with col2:
            st.subheader("Event Type Distribution")
            type_counts = {}
            for event in analysis_events:
                event_type = event.get("event.category", "unknown")
                type_counts[event_type] = type_counts.get(event_type, 0) + 1

            if type_counts:
                type_df = pd.DataFrame(type_counts.items(), columns=["Type", "Count"])

                fig_types = go.Figure(data=[
                    go.Pie(
                        labels=type_df['Type'],
                        values=type_df['Count'],
                        hole=0.4,
                        textinfo='label+percent',
                        hovertemplate='<b>%{label}</b><br>Events: %{value}<br>Percentage: %{percent}<extra></extra>'
                    )
                ])
                fig_types.update_layout(
                    showlegend=True,
                    height=400,
                    margin=dict(l=20, r=20, t=20, b=20)
                )
                st.plotly_chart(fig_types, width="stretch")

        # Row 2: Execution Timeline
        st.markdown("---")
        st.subheader("📈 Activity Timeline")

        # Create timeline dataframe
        timeline_data = []
        for event in analysis_events:
            timestamp = event.get("timestamp", 0)
            if timestamp:
                dt = datetime.fromtimestamp(timestamp / 1000)
                timeline_data.append({
                    "timestamp": dt,
                    "type": event.get("event.category", "unknown")
                })

        if timeline_data:
            timeline_df = pd.DataFrame(timeline_data)
            timeline_grouped = timeline_df.groupby([pd.Grouper(key='timestamp', freq='10min'), 'type']).size().reset_index(name='count')

            fig_timeline = px.line(
                timeline_grouped,
                x='timestamp',
                y='count',
                color='type',
                title='Audit Events Over Time (10-minute intervals)',
                labels={'count': 'Event Count', 'timestamp': 'Time', 'type': 'Event Type'}
            )
            fig_timeline.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_timeline, width="stretch")

        # Row 3: Persistence Watch
        st.markdown("---")
        st.subheader("🔒 Persistence Watch")
        st.caption("Monitoring writes to startup locations and identity files")

        persistence_events = []
        for event in analysis_events:
            # Check if event involves persistence locations
            obj = event.get("raw_data", {}).get("object", "")
            primary_actor = event.get("raw_data", {}).get("primary_actor", "")

            # Check for persistence-related paths
            persistence_paths = ["/etc/cron", "/etc/systemd/system", "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh"]
            is_persistence = any(path in obj for path in persistence_paths)

            if is_persistence or "persistence" in event.get("tags", []) or "identity" in event.get("tags", []):
                timestamp = event.get("timestamp", 0)
                dt = datetime.fromtimestamp(timestamp / 1000).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "N/A"

                persistence_events.append({
                    "Timestamp": dt,
                    "User": event.get("user.id", "N/A"),
                    "Process": event.get("process.name", "N/A"),
                    "PID": event.get("process.pid", "N/A"),
                    "Action": event.get("message", "N/A"),
                    "Target": obj if obj else event.get("raw_data", {}).get("primary_actor", "N/A"),
                    "Result": event.get("raw_data", {}).get("result", "N/A")
                })

        if persistence_events:
            persistence_df = pd.DataFrame(persistence_events)
            st.dataframe(
                persistence_df,
                width="stretch",
                hide_index=True,
                height=400
            )
            st.caption(f"Found {len(persistence_events)} persistence-related events")
        else:
            st.info("No persistence-related events found in this time range")

        # Row 4: Execution Events with Command Lines
        st.markdown("---")
        st.subheader("⚙️ Execution Events")
        st.caption("Process executions with full command lines")

        exec_events = []
        for event in analysis_events:
            if "audit_exec" in event.get("tags", []) or event.get("event.category") == "EXECVE":
                timestamp = event.get("timestamp", 0)
                dt = datetime.fromtimestamp(timestamp / 1000).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "N/A"

                # Try to get command line from raw_data
                raw_data = event.get("raw_data", {})
                cmd = raw_data.get("a0", "")  # First argument is usually the command
                exe = event.get("process.executable", raw_data.get("exe", "N/A"))

                exec_events.append({
                    "Timestamp": dt,
                    "User": event.get("user.id", "N/A"),
                    "PID": event.get("process.pid", "N/A"),
                    "Executable": exe,
                    "Process": event.get("process.name", "N/A"),
                    "Summary": event.get("message", "N/A")
                })

        if exec_events:
            exec_df = pd.DataFrame(exec_events)
            st.dataframe(
                exec_df,
                width="stretch",
                hide_index=True,
                height=400
            )
            st.caption(f"Showing {len(exec_events)} execution events")
        else:
            st.info("No execution events found in this time range")

        # Summary statistics
        st.markdown("---")
        st.subheader("📈 Summary Statistics")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            unique_users = len(set(e.get("user.id", "") for e in analysis_events if e.get("user.id") not in ["", "unset", "-1"]))
            st.metric("Unique Users", unique_users)

        with col2:
            unique_processes = len(set(e.get("process.name", "") for e in analysis_events if e.get("process.name")))
            st.metric("Unique Processes", unique_processes)

        with col3:
            persistence_count = len([e for e in analysis_events if "persistence" in e.get("tags", []) or "identity" in e.get("tags", [])])
            st.metric("Persistence Events", persistence_count)

        with col4:
            priv_esc_count = len([e for e in analysis_events if "priv-esc" in e.get("tags", [])])
            st.metric("Privilege Escalations", priv_esc_count)

        # Export option
        st.markdown("---")
        if st.button("📥 Export Events as JSON"):
            json_str = json.dumps(analysis_events, indent=2)
            st.download_button(
                label="Download JSON",
                data=json_str,
                file_name=f"auditd_events_{int(datetime.now().timestamp())}.json",
                mime="application/json"
            )

    else:
        st.warning("No events found matching the filters.")
else:
    st.warning("No events found matching the filters.")
