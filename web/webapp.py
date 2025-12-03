#!/usr/bin/env python3
"""eBPF Provenance Monitor - Multi-page Web Application"""

import streamlit as st

st.set_page_config(
    page_title="eBPF Provenance Monitor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Define pages
home_page = st.Page("pages/home.py", title="Dashboard", icon="🏠", default=True)
ebpf_events_page = st.Page("pages/ebpf_events.py", title="eBPF Events", icon="📝")
pcap_flows_page = st.Page("pages/pcap_flows.py", title="PCAP Flows", icon="🌐")
provenance_page = st.Page("pages/provenance.py", title="Provenance Analysis", icon="🔍")
offline_analysis_page = st.Page("pages/offline_analysis.py", title="Offline Analysis", icon="📊")

# Create navigation
pg = st.navigation([home_page, ebpf_events_page, pcap_flows_page, provenance_page, offline_analysis_page])

# Run selected page
pg.run()
