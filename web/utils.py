#!/usr/bin/env python3
"""
Shared utilities for eBPF Provenance Monitor web application
SPECTRA-compliant normalization and correlation helpers
"""

import streamlit as st
from elasticsearch import Elasticsearch
from datetime import datetime, timezone
import json
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = "/var/monitoring/config.json"

# ---------------------------------------------------------------------
# ECS FIELD MAP FOR LEGACY ↔ ECS BIDIRECTIONAL NORMALIZATION
# ---------------------------------------------------------------------
ECS_FIELD_MAP = {
    # Network fields
    "src_ip": "source.ip",
    "dst_ip": "destination.ip",
    "dest_ip": "destination.ip",
    "src_port": "source.port",
    "dst_port": "destination.port",
    "dest_port": "destination.port",
    "protocol": "network.transport",

    # Process fields
    "pid": "process.pid",
    "ppid": "process.parent.pid",
    "comm": "process.name",
    "uid": "user.id",

    # File fields
    "filename": "file.path",

    # Flow field
    "flow_id": "flow.id",
}

OLD_FIELD_MAP = {v: k for k, v in ECS_FIELD_MAP.items()}


# ---------------------------------------------------------------------
# FETCH FIELD WITH LEGACY + ECS FALLBACK
# ---------------------------------------------------------------------
def get_event_field(event, field_name, default=None):
    """Get field from event dict, supporting ECS + legacy names."""
    if field_name in event:
        return event[field_name]

    # Legacy → ECS
    if field_name in ECS_FIELD_MAP:
        ecs = ECS_FIELD_MAP[field_name]
        if ecs in event:
            return event[ecs]

    # ECS → Legacy
    if field_name in OLD_FIELD_MAP:
        legacy = OLD_FIELD_MAP[field_name]
        if legacy in event:
            return event[legacy]

    return default


# ---------------------------------------------------------------------
# NORMALIZE EVENT FOR ANALYZER + UI
# ---------------------------------------------------------------------
def normalize_event_fields(event):
    """Normalize event dict to include ECS + legacy + fusion fields."""
    normalized = event.copy()

    # --- Add legacy fields for ECS keys (and vice-versa) ---
    for legacy, ecs in ECS_FIELD_MAP.items():
        if ecs in event and legacy not in normalized:
            normalized[legacy] = event[ecs]
        if legacy in event and ecs not in normalized:
            normalized[ecs] = event[legacy]

    # -----------------------------------------------------------------
    # TIMESTAMP NORMALIZATION  (ABOVE ALL ELSE)
    # -----------------------------------------------------------------
    # eBPF: timestamp (epoch ms)
    # PCAP: epoch_first (epoch ms)
    # Auditd: timestamp (epoch ms)
    ts = None

    if "timestamp" in event and isinstance(event["timestamp"], (int, float)):
        ts = int(event["timestamp"])

    elif "epoch_first" in event:
        ts = int(event["epoch_first"])

    elif "datetime" in event:
        try:
            ts = int(datetime.fromisoformat(event["datetime"]).timestamp() * 1000)
        except Exception:
            pass

    if ts is not None:
        normalized["@timestamp"] = ts
        normalized["event.start"] = ts
    else:
        normalized["@timestamp"] = None

    # -----------------------------------------------------------------
    # PROCESS IDENTITY NORMALIZATION (critical for SPECTRA provenance)
    # -----------------------------------------------------------------
    normalized["process.entity_id"] = (
        event.get("process.entity_id")
        or event.get("entity_id")
        or f"{event.get('hostname','host')}:{event.get('pid','?')}:{ts}"
    )

    normalized["process.parent.entity_id"] = (
        event.get("process.parent.entity_id")
        or event.get("parent_entity_id")
        or f"{event.get('hostname','host')}:{event.get('ppid','?')}"
    )

    # -----------------------------------------------------------------
    # ERROR / RETURN / EVENT SUBTYPE NORMALIZATION
    # -----------------------------------------------------------------
    normalized["event.ret"] = event.get("ret")
    normalized["error.message"] = event.get("error") or event.get("error.message")

    # -----------------------------------------------------------------
    # NETWORK FIELDS (direction, protocol, iana number)
    # -----------------------------------------------------------------
    if "network.direction" in event:
        normalized["network.direction"] = event["network.direction"]

    if "network.iana_number" in event:
        normalized["network.iana_number"] = event["network.iana_number"]

    # -----------------------------------------------------------------
    # Ensure flow.id exists if flow_id present
    # -----------------------------------------------------------------
    if "flow_id" in event and "flow.id" not in normalized:
        normalized["flow.id"] = event["flow_id"]

    return normalized


# ---------------------------------------------------------------------
# CONFIG LOADER
# ---------------------------------------------------------------------
def load_config():
    if not os.path.exists(CONFIG_PATH):
        st.error(f"Config file not found at {CONFIG_PATH}")
        st.stop()
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------
# TIME UTILS
# ---------------------------------------------------------------------
def to_epoch_ms(dt: datetime) -> int:
    # If dt has no timezone, force it to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
        
    return int(dt.timestamp() * 1000)


# ---------------------------------------------------------------------
# ES CONNECTION
# ---------------------------------------------------------------------
@st.cache_resource
def connect_elasticsearch(es_config):
    es_host = es_config.get("es_host", "localhost")
    es_port = es_config.get("es_port", "9200")
    es_user = es_config.get("es_user", None)
    es_pass = es_config.get("es_password", None)

    scheme = "https" if es_config.get("secure", False) else "http"
    host = f"{scheme}://{es_host}:{es_port}"

    try:
        es = Elasticsearch(host, basic_auth=(es_user, es_pass), verify_certs=False, request_timeout=10)
        if not es.ping():
            st.error("Cannot connect to Elasticsearch")
            st.stop()
        return es
    except Exception as e:
        st.error(f"Elasticsearch connection error: {e}")
        st.stop()


# ---------------------------------------------------------------------
# GENERIC EVENT COUNTS
# ---------------------------------------------------------------------
def get_event_count(es, index_name, start_ms=None, end_ms=None, filters=None):
    """Count events between timestamps."""
    must = []

    # --- FIXED TIMESTAMP ROUTING ---
    if start_ms and end_ms:
        if "pcap" in index_name:
            ts_field = "epoch_first"
        elif "auditd" in index_name:
            ts_field = "timestamp"
        else:
            ts_field = "timestamp" 

        must.append({"range": {ts_field: {"gte": start_ms, "lte": end_ms}}})

    if filters:
        text_fields = [
            "hostname", "syscall", "comm", "protocol",
            "src_ip", "dst_ip", "source.ip", "destination.ip",
            "process.name", "network.transport", "flow.id"
        ]

        for field, value in filters.items():
            if value:
                qf = f"{field}.keyword" if field in text_fields else field
                must.append({"term": {qf: value}})

    query = {"query": {"bool": {"must": must}}} if must else {"query": {"match_all": {}}}

    try:
        if not es.indices.exists(index=index_name):
            return 0
        return es.count(index=index_name, body=query)["count"]
    except Exception:
        return 0


# ---------------------------------------------------------------------
# MULTI-MODAL EVENT FETCHING (SPECTRA: ingestion → fusion layer)
# ---------------------------------------------------------------------
def fetch_events(es, index_name, start_ms, end_ms, filters=None,
                 page=1, page_size=1000, sort_field=None, sort_order="desc",
                 normalize_fields=True):
    """Fetch & normalize events from Elasticsearch."""

    # --- TIMESTAMP FIELD SELECTION ---
    if "pcap" in index_name:
        timestamp_field = "epoch_first"
    elif "auditd" in index_name:
        timestamp_field = "timestamp"
    else:
        timestamp_field = "timestamp"  # eBPF

    # Default sort
    if sort_field is None:
        sort_field = (
            "epoch_first" if "pcap" in index_name
            else "timestamp"
        )

    must = [{"range": {timestamp_field: {"gte": start_ms, "lte": end_ms}}}]

    text_fields = [
        "hostname", "syscall", "comm", "protocol",
        "src_ip", "dst_ip", "source.ip", "destination.ip",
        "process.name", "network.transport", "flow.id"
    ]

    if filters:
        for field, value in filters.items():
            if value:
                qf = f"{field}.keyword" if field in text_fields else field
                must.append({"term": {qf: value}})

    query = {
        "query": {"bool": {"must": must}},
        "sort": [{sort_field: {"order": sort_order}}],
        "from": (page - 1) * page_size,
        "size": page_size
    }

    try:
        if not es.indices.exists(index=index_name):
            return []

        resp = es.search(index=index_name, body=query)
        hits = [hit["_source"] for hit in resp["hits"]["hits"]]

        if normalize_fields:
            hits = [normalize_event_fields(ev) for ev in hits]

        return hits

    except Exception as e:
        st.error(f"Error fetching events: {e}")
        return []


# ---------------------------------------------------------------------
# PCAP FLOW CORRELATION (critical for SPECTRA fusion)
# ---------------------------------------------------------------------
def fetch_pcap_by_flow(es, pcap_index, hostname, flow_id, ts_ms, window=10000):
    """
    Find a PCAP flow matching an eBPF network event by:
    - hostname
    - flow.id
    - timestamp proximity
    """

    if not flow_id:
        return None

    query = {
        "size": 1,
        "query": {
            "bool": {
                "must": [
                    {"term": {"hostname.keyword": hostname}},
                    {"term": {"flow.id.keyword": flow_id}},
                    {"range": {
                        "epoch_first": {
                            "gte": ts_ms - window,
                            "lte": ts_ms + window
                        }
                    }}
                ]
            }
        }
    }

    try:
        resp = es.search(index=pcap_index, body=query)
        hits = resp.get("hits", {}).get("hits", [])
        return hits[0]["_source"] if hits else None
    except Exception:
        return None


# ---------------------------------------------------------------------
# UNIQUE HOST HELPERS
# ---------------------------------------------------------------------
def get_unique_hostnames(es, index_name):
    """List hostnames in an index."""
    aggs = {
        "unique_hostnames": {
            "terms": {"field": "hostname.keyword", "size": 100}
        }
    }
    query = {"size": 0, "aggs": aggs}

    try:
        if not es.indices.exists(index=index_name):
            return []

        resp = es.search(index=index_name, body=query)
        buckets = resp.get("aggregations", {}).get("unique_hostnames", {}).get("buckets", [])
        return [b["key"] for b in buckets]

    except Exception:
        return []

