#!/usr/bin/env python3
"""MF-CSSA Situational Awareness Page"""

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch, to_epoch_ms, fetch_events
from mf_cssa_engine import MFCSSAEngine, export_results

st.set_page_config(layout="wide")
st.title("🛡️ Multi-Source Fusion Cybersecurity Situational Awareness")
st.markdown("### Real-Time Threat Detection & Assessment")

# Load configuration
config = load_config()
es_config = config.get("es_config", {})
ebpf_index = es_config.get("ebpf_index", "ebpf-events")
pcap_index = es_config.get("pcap_index", "pcap-flows")
output_dir = config.get("output_dir", "/var/monitoring/outputs")

# Connect to Elasticsearch
es = connect_elasticsearch(es_config)

# Initialize MF-CSSA engine in session state
if 'mf_cssa_engine' not in st.session_state:
    st.session_state['mf_cssa_engine'] = MFCSSAEngine()
    st.session_state['analysis_history'] = []

engine = st.session_state['mf_cssa_engine']

# Sidebar controls
st.sidebar.header("⚙️ Analysis Settings")

# Time range
time_preset = st.sidebar.selectbox(
    "Time Window",
    ["Last 5 Minutes", "Last 15 Minutes", "Last 1 Hour", "Last 6 Hours"],
    index=1
)

# Map to timedelta
time_map = {
    "Last 5 Minutes": timedelta(minutes=5),
    "Last 15 Minutes": timedelta(minutes=15),
    "Last 1 Hour": timedelta(hours=1),
    "Last 6 Hours": timedelta(hours=6)
}

end_dt = datetime.now()
start_dt = end_dt - time_map[time_preset]
start_ms = to_epoch_ms(start_dt)
end_ms = to_epoch_ms(end_dt)

# Auto-refresh
auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=False)
if auto_refresh:
    st.sidebar.caption("⏱️ Auto-refreshing every 30 seconds")

# Event limits
max_ebpf = st.sidebar.slider("Max eBPF Events", 100, 5000, 1000, 100)
max_pcap = st.sidebar.slider("Max PCAP Flows", 100, 5000, 1000, 100)

st.markdown("---")

# Main analysis button
if st.button("🔍 Run Situational Awareness Analysis", type="primary", use_container_width=True):
    with st.spinner("Analyzing multi-source data..."):
        # Fetch eBPF events (sort by datetime field)
        ebpf_events = fetch_events(es, ebpf_index, start_ms, end_ms, page=1, page_size=max_ebpf, sort_field="datetime")

        # Fetch PCAP flows (sort by epoch_first since pcap index doesn't have datetime field)
        pcap_flows = fetch_events(es, pcap_index, start_ms, end_ms, page=1, page_size=max_pcap, sort_field="epoch_first")
        
        if not ebpf_events and not pcap_flows:
            st.warning("No data found in selected time range")
            st.stop()
        
        # Run MF-CSSA analysis
        results = engine.process_realtime_data(ebpf_events, pcap_flows)
        
        # Store in session state
        st.session_state['current_results'] = results
        st.session_state['analysis_history'].append(results)
        
        # Keep only last 100 analyses
        if len(st.session_state['analysis_history']) > 100:
            st.session_state['analysis_history'].pop(0)
        
        st.success(f"✅ Analysis complete ({len(ebpf_events)} eBPF events, {len(pcap_flows)} PCAP flows)")

# Display results if available
if 'current_results' in st.session_state:
    results = st.session_state['current_results']
    
    # === SITUATIONAL AWARENESS SCORE ===
    st.markdown("## 📊 Situational Awareness Index Ψ(t)")
    
    score = results['situational_awareness_score']
    
    # Determine threat level
    if score >= 0.8:
        level = "🔴 CRITICAL"
        color = "#dc3545"
    elif score >= 0.6:
        level = "🟠 HIGH"
        color = "#fd7e14"
    elif score >= 0.3:
        level = "🟡 MODERATE"
        color = "#ffc107"
    else:
        level = "🟢 LOW"
        color = "#28a745"
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        # Gauge chart
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Threat Level", 'font': {'size': 24}},
            delta = {'reference': 0.5},
            gauge = {
                'axis': {'range': [None, 1]},
                'bar': {'color': color},
                'steps': [
                    {'range': [0, 0.3], 'color': "#d4edda"},
                    {'range': [0.3, 0.6], 'color': "#fff3cd"},
                    {'range': [0.6, 0.8], 'color': "#f8d7da"},
                    {'range': [0.8, 1], 'color': "#f5c6cb"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 0.8
                }
            }
        ))
        
        fig_gauge.update_layout(height=300)
        st.plotly_chart(fig_gauge, use_container_width=True)
    
    with col2:
        st.metric("Threat Level", level)
        st.metric("Score", f"{score:.3f}")
        st.metric("Timestamp", results['timestamp'][11:19])
    
    with col3:
        # Source weights
        st.markdown("**Data Source Trust**")
        for source, weight in results['source_weights'].items():
            st.progress(weight, text=f"{source}: {weight:.2f}")
    
    st.markdown("---")
    
    # === THREAT PROBABILITIES ===
    st.markdown("## 🎯 Threat Scenario Analysis")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        # Top threats table
        st.markdown("### Top Threats Detected")
        
        threat_data = []
        for threat, prob in results['top_threats']:
            scenario = engine.threat_model.threat_scenarios.get(threat)
            if scenario:
                threat_data.append({
                    'Threat': threat,
                    'Probability': f"{prob:.1%}",
                    'Severity': f"{scenario.severity:.1f}",
                    'Description': scenario.description
                })
        
        if threat_data:
            df_threats = pd.DataFrame(threat_data)
            st.dataframe(df_threats, use_container_width=True, hide_index=True)
    
    with col2:
        # All threat probabilities bar chart
        st.markdown("### All Threat Probabilities")
        
        threat_probs = results['threat_probabilities']
        sorted_threats = sorted(threat_probs.items(), key=lambda x: x[1], reverse=True)
        
        fig_threats = go.Figure(data=[
            go.Bar(
                x=[prob for _, prob in sorted_threats],
                y=[threat for threat, _ in sorted_threats],
                orientation='h',
                marker=dict(
                    color=[prob for _, prob in sorted_threats],
                    colorscale='Reds',
                    showscale=True
                ),
                text=[f"{prob:.1%}" for _, prob in sorted_threats],
                textposition='auto',
            )
        ])
        
        fig_threats.update_layout(
            xaxis_title="Probability",
            yaxis_title="Threat Scenario",
            height=400,
            margin=dict(l=20, r=20, t=20, b=20)
        )
        
        st.plotly_chart(fig_threats, use_container_width=True)
    
    st.markdown("---")
    
    # === EVIDENCE INDICATORS ===
    st.markdown("## 🔍 Detected Threat Indicators")
    
    evidence = results['evidence']
    detected = {k: v for k, v in evidence.items() if v == 1}
    
    if detected:
        cols = st.columns(min(len(detected), 4))
        for idx, (indicator, _) in enumerate(detected.items()):
            with cols[idx % 4]:
                scenario = engine.threat_model.threat_scenarios.get(indicator)
                st.error(f"**{indicator}**\n\n{scenario.description if scenario else ''}")
    else:
        st.success("✅ No immediate threat indicators detected")
    
    st.markdown("---")
    
    # === HISTORICAL TREND ===
    if len(st.session_state['analysis_history']) > 1:
        st.markdown("## 📈 Situational Awareness Trend")
        
        history = st.session_state['analysis_history']
        
        df_history = pd.DataFrame([
            {
                'Timestamp': h['timestamp'],
                'Score': h['situational_awareness_score']
            }
            for h in history
        ])
        
        df_history['Timestamp'] = pd.to_datetime(df_history['Timestamp'])
        
        fig_trend = go.Figure()
        
        fig_trend.add_trace(go.Scatter(
            x=df_history['Timestamp'],
            y=df_history['Score'],
            mode='lines+markers',
            name='Awareness Score',
            line=dict(color='#40A8D1', width=3),
            marker=dict(size=8),
            fill='tozeroy'
        ))
        
        # Add threshold lines
        fig_trend.add_hline(y=0.8, line_dash="dash", line_color="red", 
                           annotation_text="Critical", annotation_position="right")
        fig_trend.add_hline(y=0.6, line_dash="dash", line_color="orange", 
                           annotation_text="High", annotation_position="right")
        fig_trend.add_hline(y=0.3, line_dash="dash", line_color="yellow", 
                           annotation_text="Moderate", annotation_position="right")
        
        fig_trend.update_layout(
            xaxis_title="Time",
            yaxis_title="Situational Awareness Score Ψ(t)",
            height=400,
            yaxis_range=[0, 1]
        )
        
        st.plotly_chart(fig_trend, use_container_width=True)
    
    st.markdown("---")
    
    # === ANALYST FEEDBACK ===
    st.markdown("## 💬 Analyst Feedback (Adaptive Learning)")
    
    st.caption("Provide feedback to help the system learn and improve accuracy")
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("👍 Accurate Assessment", type="secondary", use_container_width=True):
            engine.provide_analyst_feedback(1, results)
            st.success("✅ Positive feedback recorded")
    
    with col2:
        if st.button("👎 Inaccurate Assessment", type="secondary", use_container_width=True):
            engine.provide_analyst_feedback(0, results)
            st.warning("⚠️ Negative feedback recorded")
    
    with col3:
        st.caption("Feedback trains the system to adjust source weights and improve future predictions")
    
    # Display feedback history
    if engine.adaptive_learning.feedback_history:
        with st.expander("📊 View Feedback History"):
            feedback_df = pd.DataFrame(engine.adaptive_learning.feedback_history)
            feedback_df['timestamp'] = pd.to_datetime(feedback_df['timestamp'])
            feedback_df['feedback'] = feedback_df['feedback'].map({0: '👎 Disagree', 1: '👍 Agree'})
            
            st.dataframe(
                feedback_df[['timestamp', 'feedback', 'score', 'error']],
                use_container_width=True,
                hide_index=True
            )
    
    st.markdown("---")
    
    # === EXPORT OPTIONS ===
    st.markdown("## 📥 Export Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        json_str = json.dumps(results, indent=2)
        st.download_button(
            label="Download Analysis (JSON)",
            data=json_str,
            file_name=f"mf_cssa_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col2:
        # Export to file
        if st.button("💾 Save to Server", use_container_width=True):
            os.makedirs(output_dir, exist_ok=True)
            filename = os.path.join(
                output_dir,
                f"mf_cssa_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            export_results(results, filename)
            st.success(f"Saved to: {filename}")

else:
    st.info("👆 Click 'Run Situational Awareness Analysis' to begin")

# Auto-refresh logic
if auto_refresh:
    import time
    time.sleep(30)
    st.rerun()