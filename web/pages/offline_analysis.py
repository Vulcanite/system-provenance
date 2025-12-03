#!/usr/bin/env python3
"""Offline Analysis Page - PCAP and Audit Log Correlation"""

import streamlit as st
import pandas as pd
import json
import sys
import os
from datetime import datetime, timedelta
import tempfile
import subprocess
from collections import defaultdict
import plotly.express as px
import plotly.graph_objects as go

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

st.title("📊 Offline Analysis")
st.markdown("### PCAP and Audit Log Correlation for Forensic Investigation")

st.info("💡 **Use Case:** Upload previously captured PCAP files and audit logs (auditd/auditbeat) from the same time period to correlate network activity with process behavior.")

# Session state initialization
if 'pcap_flows' not in st.session_state:
    st.session_state['pcap_flows'] = None
if 'audit_events' not in st.session_state:
    st.session_state['audit_events'] = None
if 'correlations' not in st.session_state:
    st.session_state['correlations'] = None

# Create tabs
tab1, tab2, tab3, tab4 = st.tabs(["📤 Upload Files", "🔗 Correlation Analysis", "📈 Visualizations", "🤖 AI Insights"])

with tab1:
    st.subheader("Upload Forensic Data")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🌐 PCAP File Upload")
        st.caption("Supports: .pcap, .pcapng files")

        pcap_file = st.file_uploader(
            "Upload PCAP file",
            type=['pcap', 'pcapng'],
            help="Network packet capture file from tcpdump, Wireshark, or similar tools"
        )

        if pcap_file:
            st.success(f"✅ Uploaded: {pcap_file.name} ({pcap_file.size:,} bytes)")

            # Option to filter PCAP
            with st.expander("⚙️ PCAP Processing Options"):
                bpf_filter = st.text_input(
                    "BPF Filter (optional)",
                    placeholder="e.g., tcp port 80 or host 192.168.1.1",
                    help="Berkeley Packet Filter to reduce dataset"
                )
                max_packets = st.number_input(
                    "Max packets to process",
                    min_value=100,
                    max_value=1000000,
                    value=10000,
                    step=1000,
                    help="Limit processing for large files"
                )

            if st.button("🔄 Process PCAP File", type="primary"):
                with st.spinner("Parsing PCAP file..."):
                    # Save uploaded file temporarily
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

                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                        if result.returncode == 0:
                            packets = json.loads(result.stdout)

                            # Extract flow information
                            flows = []
                            flow_dict = {}

                            for pkt in packets:
                                layers = pkt.get('_source', {}).get('layers', {})

                                # Extract timestamp
                                frame = layers.get('frame', {})
                                timestamp = frame.get('frame.time_epoch', '0')

                                # Extract IP layer
                                ip_layer = layers.get('ip', {})
                                src_ip = ip_layer.get('ip.src', 'N/A')
                                dst_ip = ip_layer.get('ip.dst', 'N/A')

                                # Extract transport layer
                                protocol = None
                                src_port = None
                                dst_port = None

                                if 'tcp' in layers:
                                    protocol = 'TCP'
                                    tcp = layers['tcp']
                                    src_port = tcp.get('tcp.srcport', 'N/A')
                                    dst_port = tcp.get('tcp.dstport', 'N/A')
                                elif 'udp' in layers:
                                    protocol = 'UDP'
                                    udp = layers['udp']
                                    src_port = udp.get('udp.srcport', 'N/A')
                                    dst_port = udp.get('udp.dstport', 'N/A')

                                if protocol:
                                    flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"

                                    if flow_key not in flow_dict:
                                        flow_dict[flow_key] = {
                                            'src_ip': src_ip,
                                            'dst_ip': dst_ip,
                                            'src_port': src_port,
                                            'dst_port': dst_port,
                                            'protocol': protocol,
                                            'first_seen': float(timestamp),
                                            'last_seen': float(timestamp),
                                            'packet_count': 0,
                                            'byte_count': 0
                                        }

                                    flow_dict[flow_key]['packet_count'] += 1
                                    flow_dict[flow_key]['byte_count'] += int(frame.get('frame.len', 0))
                                    flow_dict[flow_key]['last_seen'] = max(flow_dict[flow_key]['last_seen'], float(timestamp))

                            flows = list(flow_dict.values())

                            # Convert to DataFrame
                            df_flows = pd.DataFrame(flows)
                            df_flows['first_seen_dt'] = pd.to_datetime(df_flows['first_seen'], unit='s')
                            df_flows['last_seen_dt'] = pd.to_datetime(df_flows['last_seen'], unit='s')
                            df_flows['duration'] = df_flows['last_seen'] - df_flows['first_seen']

                            st.session_state['pcap_flows'] = df_flows

                            st.success(f"✅ Parsed {len(packets)} packets into {len(flows)} unique flows")

                            # Show summary
                            st.markdown("**PCAP Summary:**")
                            col_a, col_b, col_c, col_d = st.columns(4)
                            with col_a:
                                st.metric("Total Flows", len(flows))
                            with col_b:
                                st.metric("Total Packets", df_flows['packet_count'].sum())
                            with col_c:
                                time_range = df_flows['last_seen_dt'].max() - df_flows['first_seen_dt'].min()
                                st.metric("Time Range", f"{time_range.total_seconds():.1f}s")
                            with col_d:
                                st.metric("Protocols", df_flows['protocol'].nunique())

                            # Show sample
                            with st.expander("View Flow Sample"):
                                st.dataframe(df_flows.head(10), use_container_width=True)

                        else:
                            st.error(f"Failed to parse PCAP: {result.stderr}")

                    except subprocess.TimeoutExpired:
                        st.error("⏱️ PCAP processing timed out. Try using a BPF filter or reducing max packets.")
                    except FileNotFoundError:
                        st.error("❌ tshark not found. Please install: sudo apt-get install tshark")
                    except Exception as e:
                        st.error(f"Error processing PCAP: {e}")
                    finally:
                        os.unlink(tmp_pcap_path)

    with col2:
        st.markdown("#### 📝 Audit Log Upload")
        st.caption("Supports: JSON (auditbeat), native auditd logs")

        audit_file = st.file_uploader(
            "Upload Audit Logs",
            type=['json', 'log', 'txt'],
            help="Audit logs from auditd or auditbeat (JSON format preferred)"
        )

        if audit_file:
            st.success(f"✅ Uploaded: {audit_file.name} ({audit_file.size:,} bytes)")

            with st.expander("⚙️ Audit Log Options"):
                log_format = st.selectbox(
                    "Log Format",
                    ["Auto-detect", "Auditbeat JSON", "Auditd Native", "Custom JSON"],
                    help="Format of the audit logs"
                )

                filter_syscalls = st.multiselect(
                    "Filter Syscalls (optional)",
                    ["connect", "bind", "sendto", "recvfrom", "execve", "openat", "socket"],
                    default=["connect", "bind", "socket", "execve"],
                    help="Only process these syscalls to reduce dataset"
                )

            if st.button("🔄 Process Audit Logs", type="primary"):
                with st.spinner("Parsing audit logs..."):
                    try:
                        content = audit_file.getvalue().decode('utf-8')
                        events = []

                        # Try to parse as JSON lines
                        for line in content.split('\n'):
                            if not line.strip():
                                continue

                            try:
                                event = json.loads(line)

                                # Extract common fields (adapt based on format)
                                extracted = {}

                                # Auditbeat format
                                if 'auditd' in event or 'process' in event:
                                    extracted = {
                                        'timestamp': event.get('@timestamp', event.get('timestamp', '')),
                                        'syscall': event.get('auditd', {}).get('data', {}).get('syscall',
                                                   event.get('event', {}).get('action', 'unknown')),
                                        'pid': event.get('process', {}).get('pid',
                                               event.get('auditd', {}).get('data', {}).get('pid', 0)),
                                        'comm': event.get('process', {}).get('name',
                                                event.get('auditd', {}).get('data', {}).get('comm', 'unknown')),
                                        'uid': event.get('user', {}).get('id',
                                               event.get('auditd', {}).get('data', {}).get('uid', 0)),
                                        'src_ip': event.get('source', {}).get('ip', ''),
                                        'dst_ip': event.get('destination', {}).get('ip', ''),
                                        'src_port': event.get('source', {}).get('port', 0),
                                        'dst_port': event.get('destination', {}).get('port', 0),
                                    }
                                # Generic JSON format
                                else:
                                    extracted = {
                                        'timestamp': event.get('timestamp', event.get('datetime', '')),
                                        'syscall': event.get('syscall', 'unknown'),
                                        'pid': event.get('pid', 0),
                                        'comm': event.get('comm', event.get('process_name', 'unknown')),
                                        'uid': event.get('uid', 0),
                                        'src_ip': event.get('src_ip', ''),
                                        'dst_ip': event.get('dest_ip', event.get('dst_ip', '')),
                                        'src_port': event.get('src_port', 0),
                                        'dst_port': event.get('dest_port', event.get('dst_port', 0)),
                                    }

                                # Filter by syscall if specified
                                if not filter_syscalls or extracted['syscall'] in filter_syscalls:
                                    events.append(extracted)

                            except json.JSONDecodeError:
                                continue

                        if events:
                            df_audit = pd.DataFrame(events)

                            # Parse timestamps
                            try:
                                df_audit['timestamp_dt'] = pd.to_datetime(df_audit['timestamp'])
                                df_audit['epoch'] = df_audit['timestamp_dt'].astype(int) / 10**9
                            except:
                                st.warning("Could not parse timestamps. Using event order instead.")
                                df_audit['timestamp_dt'] = pd.NaT
                                df_audit['epoch'] = 0

                            st.session_state['audit_events'] = df_audit

                            st.success(f"✅ Parsed {len(events)} audit events")

                            # Show summary
                            st.markdown("**Audit Log Summary:**")
                            col_a, col_b, col_c, col_d = st.columns(4)
                            with col_a:
                                st.metric("Total Events", len(events))
                            with col_b:
                                st.metric("Unique Processes", df_audit['comm'].nunique())
                            with col_c:
                                st.metric("Unique Syscalls", df_audit['syscall'].nunique())
                            with col_d:
                                network_events = len(df_audit[df_audit['syscall'].isin(['connect', 'bind', 'socket'])])
                                st.metric("Network Events", network_events)

                            # Show sample
                            with st.expander("View Event Sample"):
                                st.dataframe(df_audit.head(10), use_container_width=True)
                        else:
                            st.warning("No events could be parsed. Check log format.")

                    except Exception as e:
                        st.error(f"Error processing audit logs: {e}")

with tab2:
    st.subheader("🔗 PCAP-Audit Correlation")

    if st.session_state['pcap_flows'] is None or st.session_state['audit_events'] is None:
        st.warning("⚠️ Please upload and process both PCAP file and Audit logs in the 'Upload Files' tab first.")
    else:
        df_flows = st.session_state['pcap_flows']
        df_audit = st.session_state['audit_events']

        st.markdown("### Correlation Settings")

        col1, col2 = st.columns(2)
        with col1:
            time_tolerance = st.slider(
                "Time Tolerance (seconds)",
                min_value=0.1,
                max_value=10.0,
                value=2.0,
                step=0.1,
                help="Match events within this time window"
            )

        with col2:
            correlation_method = st.selectbox(
                "Correlation Method",
                ["IP + Port + Time", "IP + Time", "Port + Time"],
                help="How to match PCAP flows with audit events"
            )

        if st.button("🔍 Run Correlation Analysis", type="primary"):
            with st.spinner("Correlating PCAP flows with audit events..."):
                correlations = []

                for idx, flow in df_flows.iterrows():
                    # Find matching audit events
                    time_matches = df_audit[
                        (df_audit['epoch'] >= flow['first_seen'] - time_tolerance) &
                        (df_audit['epoch'] <= flow['last_seen'] + time_tolerance)
                    ]

                    if correlation_method == "IP + Port + Time":
                        matches = time_matches[
                            ((time_matches['dst_ip'] == flow['dst_ip']) &
                             (time_matches['dst_port'] == int(flow['dst_port']))) |
                            ((time_matches['src_ip'] == flow['src_ip']) &
                             (time_matches['src_port'] == int(flow['src_port'])))
                        ]
                    elif correlation_method == "IP + Time":
                        matches = time_matches[
                            (time_matches['dst_ip'] == flow['dst_ip']) |
                            (time_matches['src_ip'] == flow['src_ip'])
                        ]
                    else:  # Port + Time
                        matches = time_matches[
                            (time_matches['dst_port'] == int(flow['dst_port'])) |
                            (time_matches['src_port'] == int(flow['src_port']))
                        ]

                    if len(matches) > 0:
                        # Get most likely process (most common PID in matches)
                        process = matches.groupby(['pid', 'comm']).size().idxmax()

                        correlations.append({
                            'flow_id': idx,
                            'src_ip': flow['src_ip'],
                            'dst_ip': flow['dst_ip'],
                            'src_port': flow['src_port'],
                            'dst_port': flow['dst_port'],
                            'protocol': flow['protocol'],
                            'packets': flow['packet_count'],
                            'bytes': flow['byte_count'],
                            'first_seen': flow['first_seen_dt'],
                            'pid': process[0],
                            'process': process[1],
                            'match_count': len(matches),
                            'syscalls': ', '.join(matches['syscall'].unique()),
                            'confidence': min(100, len(matches) * 10)  # Simple confidence score
                        })

                if correlations:
                    df_corr = pd.DataFrame(correlations)
                    st.session_state['correlations'] = df_corr

                    st.success(f"✅ Found {len(correlations)} correlated flows (out of {len(df_flows)} total flows)")

                    # Summary metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Correlated Flows", len(correlations))
                    with col2:
                        st.metric("Attributed Processes", df_corr['process'].nunique())
                    with col3:
                        high_confidence = len(df_corr[df_corr['confidence'] >= 70])
                        st.metric("High Confidence", high_confidence)
                    with col4:
                        total_traffic = df_corr['bytes'].sum()
                        st.metric("Total Traffic", f"{total_traffic / 1024 / 1024:.1f} MB")

                    st.markdown("---")
                    st.markdown("### Correlated Network Activity")

                    # Display correlated data
                    display_df = df_corr[['first_seen', 'process', 'pid', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'packets', 'bytes', 'syscalls', 'confidence']]
                    st.dataframe(display_df, use_container_width=True, hide_index=True)

                    # Export option
                    st.markdown("---")
                    csv = df_corr.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Correlation Results (CSV)",
                        data=csv,
                        file_name="pcap_audit_correlation.csv",
                        mime="text/csv"
                    )
                else:
                    st.warning("No correlations found. Try adjusting time tolerance or correlation method.")

with tab3:
    st.subheader("📈 Correlation Visualizations")

    if st.session_state['correlations'] is None:
        st.warning("⚠️ Please run correlation analysis first.")
    else:
        df_corr = st.session_state['correlations']

        # Process network activity timeline
        st.markdown("### Network Activity by Process")
        fig_timeline = px.scatter(
            df_corr,
            x='first_seen',
            y='process',
            size='bytes',
            color='protocol',
            hover_data=['dst_ip', 'dst_port', 'packets', 'confidence'],
            title="Timeline of Network Activity (bubble size = bytes transferred)"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top processes by traffic
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Top Processes by Traffic Volume")
            proc_traffic = df_corr.groupby('process')['bytes'].sum().sort_values(ascending=False).head(10)
            fig_proc = px.bar(
                x=proc_traffic.values / 1024 / 1024,
                y=proc_traffic.index,
                orientation='h',
                labels={'x': 'MB', 'y': 'Process'},
                title="Top 10 Processes"
            )
            st.plotly_chart(fig_proc, use_container_width=True)

        with col2:
            st.markdown("### Top Destination IPs")
            ip_traffic = df_corr.groupby('dst_ip')['bytes'].sum().sort_values(ascending=False).head(10)
            fig_ip = px.bar(
                x=ip_traffic.values / 1024 / 1024,
                y=ip_traffic.index,
                orientation='h',
                labels={'x': 'MB', 'y': 'Destination IP'},
                title="Top 10 Destinations"
            )
            st.plotly_chart(fig_ip, use_container_width=True)

        # Protocol distribution
        st.markdown("### Protocol Distribution")
        protocol_counts = df_corr['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Network Traffic by Protocol"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Confidence distribution
        st.markdown("### Correlation Confidence Distribution")
        fig_conf = px.histogram(
            df_corr,
            x='confidence',
            nbins=20,
            title="Distribution of Correlation Confidence Scores",
            labels={'confidence': 'Confidence Score', 'count': 'Number of Flows'}
        )
        st.plotly_chart(fig_conf, use_container_width=True)

with tab4:
    st.subheader("🤖 AI-Powered Insights")

    if st.session_state['correlations'] is None:
        st.warning("⚠️ Please run correlation analysis first.")
    else:
        df_corr = st.session_state['correlations']

        st.markdown("### Automated Anomaly Detection")

        # Simple heuristics for suspicious activity
        anomalies = []

        # Check for unusual port usage
        common_ports = {80, 443, 53, 22, 25, 110, 143, 993, 995}
        unusual_ports = df_corr[~df_corr['dst_port'].astype(int).isin(common_ports)]
        if len(unusual_ports) > 0:
            anomalies.append({
                'type': 'Unusual Ports',
                'severity': 'Medium',
                'count': len(unusual_ports),
                'description': f"Detected {len(unusual_ports)} connections to non-standard ports",
                'details': unusual_ports[['process', 'dst_ip', 'dst_port', 'bytes']].head(5).to_dict('records')
            })

        # Check for high volume transfers
        high_volume = df_corr[df_corr['bytes'] > df_corr['bytes'].quantile(0.95)]
        if len(high_volume) > 0:
            anomalies.append({
                'type': 'High Volume Transfer',
                'severity': 'High',
                'count': len(high_volume),
                'description': f"Detected {len(high_volume)} unusually large data transfers",
                'details': high_volume[['process', 'dst_ip', 'bytes']].head(5).to_dict('records')
            })

        # Check for processes with many outbound connections
        conn_counts = df_corr.groupby('process').size()
        chatty_procs = conn_counts[conn_counts > conn_counts.quantile(0.90)]
        if len(chatty_procs) > 0:
            anomalies.append({
                'type': 'Chatty Processes',
                'severity': 'Medium',
                'count': len(chatty_procs),
                'description': f"Detected {len(chatty_procs)} processes with unusually high connection counts",
                'details': [{'process': proc, 'connections': count} for proc, count in chatty_procs.items()]
            })

        # Display anomalies
        if anomalies:
            st.warning(f"⚠️ Found {len(anomalies)} potential anomalies")

            for anomaly in anomalies:
                severity_color = {'Low': '🟢', 'Medium': '🟡', 'High': '🔴'}

                with st.expander(f"{severity_color.get(anomaly['severity'], '⚪')} {anomaly['type']} - {anomaly['severity']} Severity"):
                    st.write(f"**Description:** {anomaly['description']}")
                    st.write(f"**Count:** {anomaly['count']}")

                    if 'details' in anomaly:
                        st.markdown("**Sample Events:**")
                        st.json(anomaly['details'])
        else:
            st.success("✅ No significant anomalies detected")

        st.markdown("---")
        st.markdown("### AI Analysis Summary")

        # Generate summary statistics for AI context
        summary = f"""
        **Correlation Analysis Summary:**
        - Total correlated flows: {len(df_corr)}
        - Unique processes: {df_corr['process'].nunique()}
        - Time range: {df_corr['first_seen'].min()} to {df_corr['first_seen'].max()}
        - Total data transferred: {df_corr['bytes'].sum() / 1024 / 1024:.2f} MB
        - Most active process: {df_corr.groupby('process')['bytes'].sum().idxmax()}
        - Protocol distribution: {df_corr['protocol'].value_counts().to_dict()}
        """

        st.text_area("Analysis Context", value=summary, height=200)

        st.info("💡 **Tip:** Copy this summary and use it with the Provenance Analysis AI chat for deeper insights about process behavior and network patterns.")
