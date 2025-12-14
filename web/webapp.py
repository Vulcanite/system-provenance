#!/usr/bin/env python3
"""System Monitor with Provenance Analysis"""

import urllib3
import streamlit as st

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(
    page_title="System Monitor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

home_page = st.Page("pages/home.py", title="Dashboard", icon="🏠", default=True)
ebpf_events_page = st.Page("pages/ebpf_events.py", title="eBPF Events", icon="📝")
auditd_events_page = st.Page("pages/auditd_events.py", title="Auditd Events", icon="📊")
pcap_flows_page = st.Page("pages/pcap_flows.py", title="PCAP Flows", icon="🌐")
provenance_page = st.Page("pages/provenance.py", title="Provenance Analysis", icon="🔍")
offline_analysis_page = st.Page("pages/offline_forensics.py", title="Offline Forensics", icon="📊")
situational_awareness_page = st.Page("pages/situational_awareness.py", title="Situational Awareness", icon="🛡️")

pg = st.navigation([home_page, ebpf_events_page, auditd_events_page, pcap_flows_page, provenance_page, offline_analysis_page, situational_awareness_page])

pg.run()
