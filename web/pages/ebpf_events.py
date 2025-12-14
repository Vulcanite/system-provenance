#!/usr/bin/env python3
"""eBPF Events Viewer Page"""

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import json
import sys
import os
import plotly.express as px

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
hostnames = get_unique_hostnames(es, ebpf_index)
hostname_filter = st.sidebar.selectbox("Hostname", hostnames)

# Additional filters
syscall_filter = st.sidebar.text_input("Syscall (exact match)", "")
comm_filter = st.sidebar.text_input("Process Name (exact match)", "")
pid_filter = st.sidebar.text_input("PID", "")
ppid_filter = st.sidebar.text_input("PPID", "")
flow_id_filter = st.sidebar.text_input("Flow ID (exact match)", "", help="Enter flow ID to see network events from PCAP flows")

# Build filters dict
filters = {}
if hostname_filter != "All":
    filters["host.name"] = hostname_filter
if syscall_filter:
    filters["syscall"] = syscall_filter
if comm_filter:
    filters["process.name"] = comm_filter
if pid_filter:
    try:
        filters["process.pid"] = int(pid_filter)
    except ValueError:
        st.sidebar.error("PID must be a number")
if ppid_filter:
    try:
        filters["process.parent.pid"] = int(ppid_filter)
    except ValueError:
        st.sidebar.error("PPID must be a number")

if flow_id_filter:
    filters["flow.id"] = flow_id_filter

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
            if event.get("file.path"):
                target = event.get("file.path", "")
            elif event.get("destination.ip"):
                target = f"{event.get('destination.ip', '')}:{event.get('destination.port', '')}"
            elif event.get("source.ip"):
                target = f"{event.get('source.ip', '')}:{event.get('source.port', '')}"

            # Truncate target if too long
            if len(target) > 60:
                target = target[:57] + "..."

            # Format return value
            ret_val = event.get("ret", 0)
            if ret_val < 0:
                ret_str = f"❌ {ret_val}"
            else:
                ret_str = str(ret_val)

            # Get flow ID for network events
            flow_id = ""
            if event_type == "🌐 Network":
                flow_id_full = event.get("flow.id", "")
                if flow_id_full:
                    flow_id = flow_id_full[:12] + "..." if len(flow_id_full) > 12 else flow_id_full

            table_data.append({
                "Timestamp": datetime.fromtimestamp(event.get("@timestamp") / 1000).strftime("%Y-%m-%d %H:%M:%S"),
                "Hostname": event.get("host.name", "N/A"),
                "Type": event_type,
                "Syscall": syscall,
                "Process": event.get("process.name", "unknown"),
                "PID": event.get("process.pid", "N/A"),
                "PPID": event.get("process.parent.pid", "N/A"),
                "UID": event.get("user.id", "N/A"),
                "Flow ID": flow_id if flow_id else "-",
                "Target": target,
                "Return": ret_str,
                "Error": event.get("error.message", ""),
            })

        df = pd.DataFrame(table_data)

        # Add visualizations section
        st.markdown("---")
        st.subheader("📊 Event Analytics & Visualizations")

        # Create tabs for different visualization categories
        viz_tab1, viz_tab2, viz_tab3, viz_tab4 = st.tabs(["📈 Timeline", "🎯 Distribution", "🔝 Top Activity", "🔍 Deep Dive"])

        with viz_tab1:
            st.markdown("#### Event Timeline")

            # Parse timestamps for timeline
            df['timestamp_dt'] = pd.to_datetime(df['Timestamp'])

            # Events over time
            timeline_df = df.groupby([pd.Grouper(key='timestamp_dt', freq='1min'), 'Type']).size().reset_index(name='count')

            fig_timeline = px.line(
                timeline_df,
                x='timestamp_dt',
                y='count',
                color='Type',
                title='Events Over Time (1-minute intervals)',
                labels={'timestamp_dt': 'Time', 'count': 'Event Count', 'Type': 'Event Type'}
            )
            fig_timeline.update_layout(height=400)
            st.plotly_chart(fig_timeline, width='stretch')

            # Syscall activity timeline
            syscall_timeline = df.groupby([pd.Grouper(key='timestamp_dt', freq='1min'), 'Syscall']).size().reset_index(name='count')
            top_syscalls_for_timeline = df['Syscall'].value_counts().head(5).index.tolist()
            syscall_timeline_filtered = syscall_timeline[syscall_timeline['Syscall'].isin(top_syscalls_for_timeline)]

            fig_syscall_timeline = px.line(
                syscall_timeline_filtered,
                x='timestamp_dt',
                y='count',
                color='Syscall',
                title='Top 5 Syscalls Activity Over Time',
                labels={'timestamp_dt': 'Time', 'count': 'Count'}
            )
            fig_syscall_timeline.update_layout(height=350)
            st.plotly_chart(fig_syscall_timeline, width='stretch')

        with viz_tab2:
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### Event Type Distribution")
                type_counts = df['Type'].value_counts()
                fig_type_pie = px.pie(
                    values=type_counts.values,
                    names=type_counts.index,
                    title='Events by Type',
                    hole=0.4
                )
                fig_type_pie.update_layout(height=350)
                st.plotly_chart(fig_type_pie, width='stretch')

            with col2:
                st.markdown("#### Return Status Distribution")
                df['status'] = df['Return'].apply(lambda x: 'Error' if '❌' in str(x) else 'Success')
                status_counts = df['status'].value_counts()
                fig_status_pie = px.pie(
                    values=status_counts.values,
                    names=status_counts.index,
                    title='Success vs Error',
                    hole=0.4,
                    color=status_counts.index,
                    color_discrete_map={'Success': '#00cc66', 'Error': '#ff4444'}
                )
                fig_status_pie.update_layout(height=350)
                st.plotly_chart(fig_status_pie, width='stretch')

            # Syscall distribution
            st.markdown("#### Syscall Distribution")
            syscall_counts = df['Syscall'].value_counts().head(15)
            fig_syscall_bar = px.bar(
                x=syscall_counts.values,
                y=syscall_counts.index,
                orientation='h',
                title='Top 15 Syscalls',
                labels={'x': 'Count', 'y': 'Syscall'},
                color=syscall_counts.values,
                color_continuous_scale='Blues'
            )
            fig_syscall_bar.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig_syscall_bar, width='stretch')

        with viz_tab3:
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### Top 15 Active Processes")
                process_counts = df['Process'].value_counts().head(15)
                fig_process_bar = px.bar(
                    x=process_counts.values,
                    y=process_counts.index,
                    orientation='h',
                    title='Process Activity',
                    labels={'x': 'Event Count', 'y': 'Process'},
                    color=process_counts.values,
                    color_continuous_scale='Greens'
                )
                fig_process_bar.update_layout(height=500, showlegend=False)
                st.plotly_chart(fig_process_bar, width='stretch')

            with col2:
                st.markdown("#### Top 10 PIDs")
                pid_counts = df['PID'].value_counts().head(10)
                fig_pid_bar = px.bar(
                    x=pid_counts.values,
                    y=[str(p) for p in pid_counts.index],
                    orientation='h',
                    title='Most Active PIDs',
                    labels={'x': 'Event Count', 'y': 'PID'},
                    color=pid_counts.values,
                    color_continuous_scale='Oranges'
                )
                fig_pid_bar.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig_pid_bar, width='stretch')

                # UID distribution
                st.markdown("#### User Activity (UID)")
                uid_counts = df['UID'].value_counts().head(10)
                fig_uid_bar = px.bar(
                    x=uid_counts.values,
                    y=[str(u) for u in uid_counts.index],
                    orientation='h',
                    title='Top UIDs',
                    labels={'x': 'Event Count', 'y': 'UID'},
                    color=uid_counts.values,
                    color_continuous_scale='Purples'
                )
                fig_uid_bar.update_layout(height=350, showlegend=False)
                st.plotly_chart(fig_uid_bar, width='stretch')

        with viz_tab4:
            # Process-Syscall heatmap
            st.markdown("#### Process-Syscall Activity Heatmap")
            st.caption("Shows which processes are making which syscalls (Top 10 processes × Top 10 syscalls)")

            # Get top processes and syscalls
            top_10_processes = df['Process'].value_counts().head(10).index.tolist()
            top_10_syscalls = df['Syscall'].value_counts().head(10).index.tolist()

            # Filter and create pivot table
            filtered_df = df[df['Process'].isin(top_10_processes) & df['Syscall'].isin(top_10_syscalls)]
            heatmap_data = filtered_df.groupby(['Process', 'Syscall']).size().reset_index(name='count')
            heatmap_pivot = heatmap_data.pivot(index='Process', columns='Syscall', values='count').fillna(0)

            fig_heatmap = px.imshow(
                heatmap_pivot,
                labels=dict(x="Syscall", y="Process", color="Event Count"),
                x=heatmap_pivot.columns,
                y=heatmap_pivot.index,
                color_continuous_scale='YlOrRd',
                aspect='auto'
            )
            fig_heatmap.update_layout(height=500)
            st.plotly_chart(fig_heatmap, width='stretch')

            # File operations breakdown
            file_events = df[df['Type'] == '📂 File']
            if len(file_events) > 0:
                st.markdown("#### File Operations Analysis")

                col1, col2 = st.columns(2)

                with col1:
                    file_syscalls = file_events['Syscall'].value_counts()
                    fig_file_ops = px.pie(
                        values=file_syscalls.values,
                        names=file_syscalls.index,
                        title='File Syscall Distribution',
                        hole=0.3
                    )
                    fig_file_ops.update_layout(height=350)
                    st.plotly_chart(fig_file_ops, width='stretch')

                with col2:
                    # Top files accessed
                    file_targets = file_events[file_events['Target'] != '']['Target'].value_counts().head(10)
                    if len(file_targets) > 0:
                        fig_files = px.bar(
                            x=file_targets.values,
                            y=file_targets.index,
                            orientation='h',
                            title='Top 10 File Targets',
                            labels={'x': 'Access Count', 'y': 'File Path'}
                        )
                        fig_files.update_layout(height=350, showlegend=False)
                        st.plotly_chart(fig_files, width='stretch')

            # Network activity
            network_events = df[df['Type'] == '🌐 Network']
            if len(network_events) > 0:
                st.markdown("#### Network Activity Analysis")

                col1, col2 = st.columns(2)

                with col1:
                    net_syscalls = network_events['Syscall'].value_counts()
                    fig_net_ops = px.bar(
                        x=net_syscalls.index,
                        y=net_syscalls.values,
                        title='Network Syscall Distribution',
                        labels={'x': 'Syscall', 'y': 'Count'},
                        color=net_syscalls.values,
                        color_continuous_scale='Blues'
                    )
                    fig_net_ops.update_layout(height=350, showlegend=False)
                    st.plotly_chart(fig_net_ops, width='stretch')

                with col2:
                    # Network targets
                    net_targets = network_events[network_events['Target'] != '']['Target'].value_counts().head(10)
                    if len(net_targets) > 0:
                        fig_net_targets = px.bar(
                            x=net_targets.values,
                            y=net_targets.index,
                            orientation='h',
                            title='Top 10 Network Destinations',
                            labels={'x': 'Connection Count', 'y': 'Destination'}
                        )
                        fig_net_targets.update_layout(height=350, showlegend=False)
                        st.plotly_chart(fig_net_targets, width='stretch')

        # Configure column widths and display
        st.markdown("---")
        st.subheader("📋 Event Details Table")
        st.dataframe(
            df,
            width="stretch",
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
                "Flow ID": st.column_config.TextColumn("Flow ID", width="small", help="Correlates with PCAP flows"),
                "Target": st.column_config.TextColumn("Target", width="large"),
                "Return": st.column_config.TextColumn("Return", width="small"),
                "Error": st.column_config.TextColumn("Error", width="small"),
            }
        )

        # Flow ID correlation helper for network events
        network_events_with_flow = df[(df['Type'] == '🌐 Network') & (df['Flow ID'] != '-')]
        if not flow_id_filter and len(network_events_with_flow) > 0:
            with st.expander("🔗 How to Correlate with PCAP Flows", expanded=False):
                st.markdown("""
                **Flow ID Correlation Guide:**
                1. Copy a Flow ID from the "Flow ID" column above (for network events)
                2. Go to the **PCAP Network Flows** page
                3. Paste the Flow ID into the "Flow ID" filter in the sidebar
                4. View the aggregated network flow statistics for this connection

                This allows you to see packet counts, byte volumes, and DNS resolution for the network traffic!
                """)

                # Show example if available
                example_flow_id = network_events_with_flow['Flow ID'].iloc[0]
                if example_flow_id != "-":
                    st.code(example_flow_id, language="text")
                    st.caption("↑ Example Flow ID from a network event")

        # Quick summary metrics
        st.markdown("---")
        st.subheader("📊 Quick Summary (Current Page)")

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric("Total Events", len(df))

        with col2:
            syscall_counts = df['Syscall'].value_counts()
            st.metric("Unique Syscalls", len(syscall_counts))

        with col3:
            process_counts = df['Process'].value_counts()
            st.metric("Unique Processes", len(process_counts))

        with col4:
            error_count = len(df[df['Error'] != ''])
            error_pct = (error_count / len(df) * 100) if len(df) > 0 else 0
            st.metric("Errors", error_count, delta=f"{error_pct:.1f}%", delta_color="inverse")

        with col5:
            network_events = len(df[df['Type'] == '🌐 Network'])
            net_pct = (network_events / len(df) * 100) if len(df) > 0 else 0
            st.metric("Network Events", network_events, delta=f"{net_pct:.1f}%")

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
