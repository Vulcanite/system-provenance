#!/usr/bin/env python3
"""System Monitor with Provenance Analysis"""

import streamlit as st

st.set_page_config(
    page_title="System Monitor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

home_page = st.Page("pages/home.py", title="Dashboard", icon="🏠", default=True)
ebpf_events_page = st.Page("pages/ebpf_events.py", title="eBPF Events", icon="📝")
provenance_page = st.Page("pages/provenance.py", title="Provenance Analysis", icon="🔍")
offline_analysis_page = st.Page("pages/offline_analysis.py", title="Offline Analysis", icon="📊")

pg = st.navigation([home_page, ebpf_events_page, provenance_page, offline_analysis_page])

pg.run()
