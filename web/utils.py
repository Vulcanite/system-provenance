#!/usr/bin/env python3
"""Shared utilities for eBPF Provenance Monitor web application"""

import streamlit as st
from elasticsearch import Elasticsearch
from datetime import datetime
import json
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = "/var/monitoring/config.json"

def load_config():
    """Load configuration from JSON file"""
    if not os.path.exists(CONFIG_PATH):
        st.error(f"Config file not found at {CONFIG_PATH}")
        st.stop()
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def to_epoch_ms(dt: datetime) -> int:
    """Convert datetime to epoch milliseconds"""
    return int(dt.astimezone().timestamp() * 1_000)

@st.cache_resource
def connect_elasticsearch(es_config):
    """Connect to Elasticsearch and return client"""
    es_host = es_config.get("es_host", "localhost")
    es_port = es_config.get("es_port", "9200")
    es_user = es_config.get("es_user", None)
    es_pass = es_config.get("es_password", None)
    is_ssl_enabled = es_config.get("secure", False)

    host = f"http://{es_host}:{es_port}"
    if is_ssl_enabled:
        host = f"https://{es_host}:{es_port}"

    try:
        es = Elasticsearch(host, basic_auth=(es_user, es_pass), verify_certs=False, request_timeout=10)
        if not es.ping():
            st.error("Cannot connect to Elasticsearch")
            st.stop()
        return es
    except Exception as e:
        st.error(f"Elasticsearch connection error: {e}")
        st.stop()

def setup_page_config(page_title="eBPF Provenance Monitor"):
    """Setup common page configuration"""
    st.set_page_config(
        page_title=page_title,
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )

def get_event_count(es, index_name, start_ms=None, end_ms=None, filters=None):
    """Get count of events in index with optional filters"""
    must_conditions = []

    if start_ms and end_ms:
        # PCAP flows use epoch_first, eBPF events use epoch_timestamp
        timestamp_field = "epoch_first" if "pcap" in index_name else "epoch_timestamp"
        must_conditions.append({"range": {timestamp_field: {"gte": start_ms, "lte": end_ms}}})

    if filters:
        # Text fields that need .keyword suffix for term queries
        text_fields = ["hostname", "syscall", "comm", "protocol", "src_ip", "dst_ip"]

        for field, value in filters.items():
            if value:
                # Add .keyword suffix for text fields
                query_field = f"{field}.keyword" if field in text_fields else field
                must_conditions.append({"term": {query_field: value}})

    query = {"query": {"bool": {"must": must_conditions}}} if must_conditions else {"query": {"match_all": {}}}

    try:
        if not es.indices.exists(index=index_name):
            return 0
        response = es.count(index=index_name, body=query)
        return response["count"]
    except Exception:
        return 0

def fetch_events(es, index_name, start_ms, end_ms, filters=None, page=1, page_size=1000, sort_field=None, sort_order="desc"):
    """Fetch events from Elasticsearch with pagination"""
    # PCAP flows use epoch_first, eBPF events use epoch_timestamp
    timestamp_field = "epoch_first" if "pcap" in index_name else "epoch_timestamp"

    # Auto-detect sort field if not specified based on index type
    if sort_field is None:
        sort_field = "epoch_first" if "pcap" in index_name else "datetime"

    must_conditions = [
        {"range": {timestamp_field: {"gte": start_ms, "lte": end_ms}}}
    ]

    if filters:
        # Text fields that need .keyword suffix for term queries
        text_fields = ["hostname", "syscall", "comm", "protocol", "src_ip", "dst_ip"]

        for field, value in filters.items():
            if value:
                # Add .keyword suffix for text fields
                query_field = f"{field}.keyword" if field in text_fields else field
                must_conditions.append({"term": {query_field: value}})

    query = {
        "query": {"bool": {"must": must_conditions}},
        "sort": [{sort_field: {"order": sort_order}}],
        "from": (page - 1) * page_size,
        "size": page_size
    }

    try:
        if not es.indices.exists(index=index_name):
            return []

        response = es.search(index=index_name, body=query)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as e:
        st.error(f"Error fetching events: {e}")
        return []

def get_unique_hostnames(es, index_name):
    """Get list of unique hostnames from index"""
    query = {
        "size": 0,
        "aggs": {
            "unique_hostnames": {
                "terms": {
                    "field": "hostname.keyword",
                    "size": 100
                }
            }
        }
    }

    try:
        if not es.indices.exists(index=index_name):
            return []

        response = es.search(index=index_name, body=query)
        if "aggregations" in response and "unique_hostnames" in response["aggregations"]:
            buckets = response["aggregations"]["unique_hostnames"]["buckets"]
            return [bucket["key"] for bucket in buckets]
        return []
    except Exception:
        return []
