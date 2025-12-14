#!/usr/bin/env python3
"""
MF-CSSA Normalization Engine (Multi-Host Support)
Implements Z-Score Normalization: x_hat = (x - mu) / sigma
Calculated distinct baselines for each monitored host.
"""

import os
import sys
import json
import urllib3
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def load_config():
    try:
        with open("/var/monitoring/config.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "es_config": {
                "es_host": "localhost",
                "es_port": 9200,
                "es_user": "elastic",
                "es_password": "changeme",
                "secure": False,
                "ebpf_index": "ebpf-events",
                "pcap_index": "pcap-flows",
                "auditd_index": "auditd-events"
            }
        }

def connect_elasticsearch(es_config):
    protocol = "https" if es_config.get("secure") else "http"
    host = es_config.get("es_host", "localhost")
    port = es_config.get("es_port", 9200)
    
    url = f"{protocol}://{host}:{port}"
    
    if es_config.get("es_user") and es_config.get("es_password"):
        return Elasticsearch(
            [url],
            basic_auth=(es_config["es_user"], es_config["es_password"]),
            verify_certs=False
        )
    return Elasticsearch([url])

# --- Helper Functions ---

def get_monitored_hosts(es, index):
    """
    Returns a list of unique hostnames found in the given index.
    """
    try:
        if not es.indices.exists(index=index):
            return []
            
        # Aggregation to find unique host.name.keyword
        query = {
            "size": 0,
            "aggs": {
                "unique_hosts": {
                    "terms": {"field": "host.name.keyword", "size": 100}
                }
            }
        }
        res = es.search(index=index, body=query)
        return [b["key"] for b in res["aggregations"]["unique_hosts"]["buckets"]]
    except Exception as e:
        print(f"[!] Failed to discover hosts in {index}: {e}")
        return []

def calculate_z_score(current_val, window_mean, window_std):
    epsilon = 1e-6
    if window_std < epsilon:
        return 0.0
    return (current_val - window_mean) / window_std

def fetch_sliding_window_stats(es, index, field, hostname, time_window_minutes=60):
    """
    Fetches Mean/StdDev for a specific field AND specific hostname.
    """
    end_time = datetime.now()
    start_time = end_time - timedelta(minutes=time_window_minutes)
    
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": int(start_time.timestamp() * 1000), "lte": int(end_time.timestamp() * 1000)}}},
                    {"term": {"host.name.keyword": hostname}}
                ]
            }
        },
        "aggs": {
            "stats_window": {
                "extended_stats": {
                    "field": field
                }
            }
        }
    }
    
    try:
        if not es.indices.exists(index=index):
            return 0.0, 0.0

        res = es.search(index=index, body=query)
        stats = res["aggregations"]["stats_window"]
        
        mu = stats.get("avg")
        sigma = stats.get("std_deviation")
        
        if mu is None: mu = 0.0
        if sigma is None: sigma = 0.0
        
        return mu, sigma

    except Exception as e:
        print(f"[!] Stats aggregation failed for {index}/{field} on {hostname}: {e}")
        return 0.0, 0.0

# --- Normalization Logic ---

def process_pcap_normalization(es, es_config):
    index = es_config.get("pcap_index", "pcap-flows")
    normalized_events = []
    
    # 1. Discover Hosts
    hosts = get_monitored_hosts(es, index)
    
    for hostname in hosts:
        # 2. Get Baseline for THIS host
        mu_bytes, sigma_bytes = fetch_sliding_window_stats(es, index, "network.bytes", hostname)
        
        if mu_bytes > 0:
            print(f"[+] PCAP Baseline ({hostname}): Bytes(μ={mu_bytes:.2f}, σ={sigma_bytes:.2f})")
        
        # 3. Get Real-time Batch for THIS host
        now = datetime.now()
        start_batch = now - timedelta(minutes=1)
        
        query = {
            "size": 50,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": int(start_batch.timestamp() * 1000)}}},
                        {"term": {"host.name.keyword": hostname}}
                    ]
                }
            },
            "_source": ["flow.id", "network.bytes", "host.name", "timestamp"]
        }
        
        res = es.search(index=index, body=query)
        
        for hit in res["hits"]["hits"]:
            src = hit["_source"]
            bytes_val = src.get("network.bytes", 0)
            norm_score = calculate_z_score(bytes_val, mu_bytes, sigma_bytes)
            
            normalized_events.append({
                "source": "pcap",
                "host": hostname,
                "id": src.get("flow.id"),
                "raw_val": bytes_val,
                "normalized_score": norm_score,
                "timestamp": src.get("timestamp")
            })
            
    return normalized_events

def process_ebpf_normalization(es, es_config):
    index = es_config.get("ebpf_index", "ebpf-events")
    results = []
    
    # 1. Discover Hosts
    hosts = get_monitored_hosts(es, index)
    
    for hostname in hosts:
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=60)
        
        # 2. Get Baseline for THIS host
        query_baseline = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": int(start_time.timestamp() * 1000)}}},
                        {"term": {"host.name.keyword": hostname}}
                    ]
                }
            },
            "aggs": {
                "events_over_time": {
                    "date_histogram": {"field": "timestamp", "fixed_interval": "1m"}
                },
                "stats_deriv": {
                    "extended_stats_bucket": {"buckets_path": "events_over_time._count"}
                }
            }
        }
        
        mu_rate, sigma_rate = 1.0, 1.0
        
        try:
            if es.indices.exists(index=index):
                res = es.search(index=index, body=query_baseline)
                if "aggregations" in res and "stats_deriv" in res["aggregations"]:
                    stats = res["aggregations"]["stats_deriv"]
                    val_avg = stats.get("avg")
                    val_std = stats.get("std_deviation")
                    
                    if val_avg is not None: mu_rate = val_avg
                    if val_std is not None: sigma_rate = val_std
                    print(f"[+] eBPF Baseline ({hostname}): Rate/min(μ={mu_rate:.2f}, σ={sigma_rate:.2f})")
        except Exception as e:
            print(f"[!] eBPF Stats failed for {hostname}: {e}")
        
        # 3. Get Current Rate for THIS host
        start_batch = end_time - timedelta(minutes=1)
        count_res = es.count(index=index, body={
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": int(start_batch.timestamp() * 1000)}}},
                        {"term": {"host.name.keyword": hostname}}
                    ]
                }
            }
        })
        current_count = count_res["count"]
        norm_score = calculate_z_score(current_count, mu_rate, sigma_rate)
        
        results.append({
            "source": "ebpf_rate",
            "host": hostname,
            "id": "system_wide",
            "raw_val": current_count,
            "normalized_score": norm_score,
            "timestamp": int(end_time.timestamp() * 1000)
        })
    
    return results

def main():
    print("--- MF-CSSA Normalization Engine (Multi-Host) ---")
    config = load_config()
    es_config = config.get("es_config", {})
    
    try:
        es = connect_elasticsearch(es_config)
        if not es.ping():
            print("[-] Could not connect to Elasticsearch")
            sys.exit(1)
        print("[+] Connected to Elasticsearch")
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        sys.exit(1)

    pcap_scores = process_pcap_normalization(es, es_config)
    ebpf_scores = process_ebpf_normalization(es, es_config)
    
    all_scores = pcap_scores + ebpf_scores
    
    print(f"\n{'HOST':<20} | {'SOURCE':<10} | {'RAW':<8} | {'Z-SCORE':<8}")
    print("-" * 65)
    
    for item in all_scores:
        prefix = "🔴" if abs(item['normalized_score']) > 3 else "  "
        print(f"{prefix} {item['host']:<18} | {item['source']:<10} | {item['raw_val']:<8} | {item['normalized_score']:.4f}")

    print("\n[+] Normalization Complete.")

if __name__ == "__main__":
    main()