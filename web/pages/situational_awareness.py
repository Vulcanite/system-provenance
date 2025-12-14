#!/usr/bin/env python3
"""
MF-CSSA Situational Awareness Dashboard
Integrates Multi-Source Fusion (PCAP + eBPF + Auditd) with Bayesian Inference
"""

import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import plotly.graph_objects as go
import sys
import os
import numpy as np

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import load_config, connect_elasticsearch

st.set_page_config(layout="wide", page_title="MF-CSSA Dashboard")

# ==========================================
# 🧠 MF-CSSA CORE LOGIC (Normalization & Bayesian)
# ==========================================

class NormalizationEngine:
    def __init__(self, es, config):
        self.es = es
        self.indices = {
            "pcap": config["es_config"].get("pcap_index", "pcap-flows"),
            "ebpf": config["es_config"].get("ebpf_index", "ebpf-events"),
            "auditd": config["es_config"].get("auditd_index", "auditd-events")
        }

    def _get_z_score(self, current_val, mu, sigma):
        if sigma < 1e-6: return 0.0
        return (current_val - mu) / sigma

    def _fetch_baseline_stats(self, index, hostname, field_path=None, count_only=False):
        """
        Fetches Mean (μ) and StdDev (σ) for the last 60 minutes.
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=60)
        
        # Base query filter
        query_filter = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": int(start_time.timestamp() * 1000)}}},
                    {"term": {"host.name.keyword": hostname}}
                ]
            }
        }

        # Build Aggregation
        if count_only:
            # For eBPF/Auditd: We want the RATE (count per minute)
            aggs = {
                "events_over_time": {
                    "date_histogram": {"field": "timestamp", "fixed_interval": "1m"}
                },
                "stats_deriv": {
                    "extended_stats_bucket": {"buckets_path": "events_over_time._count"}
                }
            }
        else:
            # For PCAP: We want the VALUE stats (e.g. Bytes)
            aggs = {
                "stats_window": {"extended_stats": {"field": field_path}}
            }

        try:
            if not self.es.indices.exists(index=index):
                return 0.0, 0.0

            res = self.es.search(index=index, query=query_filter, aggs=aggs, size=0)
            
            if count_only:
                stats = res["aggregations"]["stats_deriv"]
            else:
                stats = res["aggregations"]["stats_window"]

            mu = stats.get("avg", 0.0)
            sigma = stats.get("std_deviation", 0.0)
            
            return (mu if mu else 0.0), (sigma if sigma else 0.0)

        except Exception as e:
            # st.error(f"Baseline error for {index}: {e}")
            return 1.0, 1.0 # Safe fallback to avoid division by zero

    def _get_current_rate(self, index, hostname):
        """Count events in the last 1 minute"""
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=1)
        try:
            res = self.es.count(index=index, body={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": int(start_time.timestamp() * 1000)}}},
                            {"term": {"host.name.keyword": hostname}}
                        ]
                    }
                }
            })
            return res["count"]
        except:
            return 0

    def get_pcap_score(self, hostname):
        # 1. Volume Baseline (Bytes)
        mu, sigma = self._fetch_baseline_stats(self.indices["pcap"], hostname, field_path="network.bytes")
        
        # 2. Current Volume (Last 1m sum)
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=1)
        res = self.es.search(index=self.indices["pcap"], size=0, body={
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": int(start_time.timestamp() * 1000)}}},
                        {"term": {"host.name.keyword": hostname}}
                    ]
                }
            },
            "aggs": {"total_bytes": {"sum": {"field": "network.bytes"}}}
        })
        current_val = res["aggregations"]["total_bytes"]["value"]
        
        return {
            "source": "PCAP (Network Vol)",
            "raw": current_val,
            "baseline_mu": mu,
            "z_score": self._get_z_score(current_val, mu, sigma)
        }

    def get_ebpf_score(self, hostname):
        # 1. Rate Baseline (Events/min)
        mu, sigma = self._fetch_baseline_stats(self.indices["ebpf"], hostname, count_only=True)
        # 2. Current Rate
        current_val = self._get_current_rate(self.indices["ebpf"], hostname)
        
        return {
            "source": "eBPF (Syscall Rate)",
            "raw": current_val,
            "baseline_mu": mu,
            "z_score": self._get_z_score(current_val, mu, sigma)
        }

    def get_auditd_score(self, hostname):
        # 1. Rate Baseline (Events/min)
        mu, sigma = self._fetch_baseline_stats(self.indices["auditd"], hostname, count_only=True)
        # 2. Current Rate
        current_val = self._get_current_rate(self.indices["auditd"], hostname)
        
        return {
            "source": "Auditd (Event Rate)",
            "raw": current_val,
            "baseline_mu": mu,
            "z_score": self._get_z_score(current_val, mu, sigma)
        }

class BayesianInferenceEngine:
    def __init__(self):
        # P(Threat) - Initial prior
        self.prior = 0.01 
        # Sensor Reliability (True Positive Rate)
        self.tpr = {"pcap": 0.95, "ebpf": 0.85, "auditd": 0.80}
        # False Positive Rate (Target 8%)
        self.fpr = {"pcap": 0.08, "ebpf": 0.10, "auditd": 0.12}

    def update_probability(self, prior, is_anomaly, source_type):
        """Bayes Theorem Update"""
        p_e_given_t = self.tpr[source_type] if is_anomaly else (1 - self.tpr[source_type])
        p_e_given_safe = self.fpr[source_type] if is_anomaly else (1 - self.fpr[source_type])
        
        evidence_prob = (p_e_given_t * prior) + (p_e_given_safe * (1 - prior))
        if evidence_prob == 0: return 0
        
        return (p_e_given_t * prior) / evidence_prob

    def compute_psi(self, vectors):
        """
        Compute Situational Awareness Score Ψ(t)
        vectors: dict of normalized results {'pcap': {...}, 'ebpf': {...}, ...}
        """
        # --- THREAT 1: Data Exfiltration ---
        # Influenced heavily by PCAP (Volume) and slightly by eBPF (Socket activity)
        prob_exfil = self.prior
        prob_exfil = self.update_probability(prob_exfil, vectors['pcap']['z_score'] > 3.0, 'pcap')
        prob_exfil = self.update_probability(prob_exfil, vectors['ebpf']['z_score'] > 3.0, 'ebpf')
        
        # --- THREAT 2: System Compromise ---
        # Influenced by eBPF (Syscalls) and Auditd (Policy violations)
        prob_comp = self.prior
        prob_comp = self.update_probability(prob_comp, vectors['ebpf']['z_score'] > 3.0, 'ebpf')
        prob_comp = self.update_probability(prob_comp, vectors['auditd']['z_score'] > 3.0, 'auditd')

        # Equation 2.4: Ψ(t) = Sum(Weight * Prob)
        # Weights defined by analyst priority
        w_exfil = 0.6
        w_comp = 0.4
        
        psi = (w_exfil * prob_exfil) + (w_comp * prob_comp)
        
        return psi, {
            "Data_Exfiltration": prob_exfil,
            "System_Compromise": prob_comp
        }

# ==========================================
# 🖥️ STREAMLIT UI
# ==========================================

st.title("🛡️ MF-CSSA Situational Awareness")
st.markdown("### Multi-Source Fusion & Bayesian Inference")

# 1. Connection & Setup
config = load_config()
es_config = config.get("es_config", {})

try:
    es = connect_elasticsearch(es_config)
    normalizer = NormalizationEngine(es, config)
    inference = BayesianInferenceEngine()
except Exception as e:
    st.error(f"Failed to connect to backend: {e}")
    st.stop()

# 2. Host Selection (Multi-Host Support)
# Discover hosts from eBPF index
try:
    res = es.search(index=es_config.get("ebpf_index"), body={
        "size": 0, "aggs": {"hosts": {"terms": {"field": "host.name.keyword", "size": 50}}}
    })
    hosts = [b['key'] for b in res["aggregations"]["hosts"]["buckets"]]
except:
    hosts = ["localhost"]

selected_host = st.selectbox("🖥️ Select Monitored Host", hosts)

st.markdown("---")

if st.button("🔍 Analyze Real-Time Posture", type="primary", width="stretch"):
    
    with st.spinner(f"Fusing data streams for {selected_host}..."):
        # A. Feature Extraction & Normalization
        vec_pcap = normalizer.get_pcap_score(selected_host)
        vec_ebpf = normalizer.get_ebpf_score(selected_host)
        vec_audit = normalizer.get_auditd_score(selected_host)
        
        vectors = {
            "pcap": vec_pcap,
            "ebpf": vec_ebpf,
            "auditd": vec_audit
        }

        # B. Bayesian Inference
        psi_score, threat_probs = inference.compute_psi(vectors)

    # === C. VISUALIZATION ===
    
    # 1. The Score Ψ(t)
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown("### Situational Awareness Score")
        
        # Color Logic
        color = "green"
        level = "SAFE"
        if psi_score > 0.3: 
            color = "orange" 
            level = "ELEVATED"
        if psi_score > 0.6: 
            color = "red"
            level = "CRITICAL"

        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = psi_score,
            title = {'text': f"Ψ(t) - {level}"},
            gauge = {
                'axis': {'range': [0, 1]},
                'bar': {'color': color},
                'steps': [
                    {'range': [0, 0.3], 'color': "lightgreen"},
                    {'range': [0.3, 0.6], 'color': "lightyellow"},
                    {'range': [0.6, 1.0], 'color': "salmon"}
                ]
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, width='stretch')

    with col2:
        st.markdown("### 🧩 Feature Vector F(t) (Normalization)")
        st.info("Z-Score > 3.0 indicates a statistically significant anomaly.")
        
        # Create DataFrame for display
        df_vec = pd.DataFrame([vec_pcap, vec_ebpf, vec_audit])
        df_vec = df_vec[["source", "raw", "baseline_mu", "z_score"]]
        df_vec.columns = ["Source Sensor", "Real-Time Value", "Baseline (1h Avg)", "Z-Score (Anomaly)"]
        
        # Highlight high Z-scores
        def highlight_anomaly(val):
            color = 'red' if abs(val) > 3.0 else 'red'
            return f'color: {color}; font-weight: bold'

        st.dataframe(
            df_vec.style.map(highlight_anomaly, subset=['Z-Score (Anomaly)'])
                  .format({"Z-Score (Anomaly)": "{:.4f}", "Baseline (1h Avg)": "{:.2f}"}),
            width='stretch'
        )

    st.markdown("---")

    # 2. Threat Probabilities
    st.markdown("### 🕵️ Bayesian Threat Inference P(θ|F)")
    cols = st.columns(2)
    
    idx = 0
    for threat, prob in threat_probs.items():
        with cols[idx]:
            st.metric(
                label=threat.replace("_", " "), 
                value=f"{prob:.4%}",
                delta="Active" if prob > 0.05 else "Dormant",
                delta_color="inverse"
            )
        idx += 1

    # 3. Analyst Feedback (Reinforcement Learning Placeholder)
    st.markdown("---")
    st.caption("🤖 Adaptive Learning Loop")
    if psi_score > 0.5:
        c1, c2 = st.columns(2)
        with c1:
            st.button("✅ Confirm Threat (Reinforce)", type="secondary", width='stretch')
        with c2:
            st.button("❌ False Positive (Adjust Weights)", type="secondary", width='stretch')

else:
    st.info("Click the button above to capture a real-time snapshot.")