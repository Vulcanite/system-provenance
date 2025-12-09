#!/usr/bin/env python3
"""
Graph Builder Service
Syncs raw eBPF events from Elasticsearch to Neo4j Graph Database in real-time.
"""

import re
import os
import time
import json
import logging
import urllib3
from neo4j import Driver, GraphDatabase
from elasticsearch import Elasticsearch

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
CONFIG_PATH = "/var/graph.json"

NOISY_FILE_PATTERNS = [
    r'^/lib/', r'^/usr/lib/', r'^/usr/lib64/', r'^/lib64/', # Libraries
    r'\.so(\.\d+)*$', # Shared Objects
    r'^/proc/', r'^/sys/', r'^/dev/', # Kernel interfaces
    r'^/usr/share/locale', r'^/usr/share/zoneinfo', # Localization
    r'^/etc/ld\.so\.cache', r'^/etc/localtime', 
    r'^/var/run/', r'^/run/', # Runtime state
    r'\.cache', # User caches
]

NOISY_REGEX = [re.compile(p) for p in NOISY_FILE_PATTERNS]

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/graph_builder.log"),
        logging.StreamHandler()
    ]
)

def load_es_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
                es_config = config.get("es_config", {})
                return es_config
    except Exception as e:
        logging.error(f"Failed to fetch ES config: {e}")

    return {}

def load_neo4j_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
                neo4j_config = config.get("neo4j_config", {})
                return neo4j_config
    except Exception as e:
        logging.error(f"Failed to fetch neo4j config: {e}")

    return {}

def is_noise(filename):
    """Check if file matches any noisy pattern"""
    if not filename: return True
    for pattern in NOISY_REGEX:
        if pattern.search(filename):
            return True
    return False

def sync_batch(driver: Driver, events):
    batches = {'spawn': [], 'exec': [], 'net': [], 'file': []}
    
    for e in events:
        # Skip failed events (except execve which is captured at entry)
        if e.get('syscall') != 'execve' and e.get('ret', 0) < 0:
            continue

        sys = e.get('syscall', '')
        
        if sys in ['clone', 'fork', 'vfork']:
            batches['spawn'].append(e)
        elif sys == 'execve':
            batches['exec'].append(e)
        elif sys == 'connect':
            batches['net'].append(e)
        elif sys in ['openat', 'open', 'write']:
            filename = e.get('filename', '')
            # APPLY NOISE FILTER
            if not is_noise(filename):
                batches['file'].append(e)

    with driver.session() as session:
        if batches['spawn']: session.run(Q_SPAWN, events=batches['spawn'])
        if batches['exec']: session.run(Q_EXEC, events=batches['exec'])
        if batches['net']: session.run(Q_NET, events=batches['net'])
        if batches['file']: session.run(Q_FILE, events=batches['file'])
            
    # Return metrics for logging
    return {k: len(v) for k,v in batches.items()}

Q_SPAWN = """
UNWIND $events AS e
// 1. Create/Find Parent Node
MERGE (parent:Process {unique_id: e.hostname + "_" + toString(e.ppid) + "_" + toString(e.parent_start_time)})
ON CREATE SET 
    parent.pid = e.ppid, 
    parent.hostname = e.hostname,
    parent.start_time = e.parent_start_time,
    parent.comm = "unknown_parent"

// 2. Create/Find Child Node
MERGE (child:Process {unique_id: e.hostname + "_" + toString(e.pid) + "_" + toString(e.process_start_time)})
ON CREATE SET 
    child.pid = e.pid, 
    child.comm = e.comm, 
    child.hostname = e.hostname,
    child.start_time = e.process_start_time

// 3. Link them
MERGE (parent)-[r:SPAWNED]->(child)
ON CREATE SET r.timestamp = e.epoch_timestamp, r.syscall = e.syscall
"""

# 2. PROCESS EXECUTION (Execve)
# Updates the existing process node with its new binary name
Q_EXEC = """
UNWIND $events AS e
// Find the process using its stable ID
MATCH (p:Process {unique_id: e.hostname + "_" + toString(e.pid) + "_" + toString(e.process_start_time)})
SET p.comm = e.comm, p.exe = e.filename

// Create File Node
MERGE (bin:File {unique_id: e.hostname + ":" + e.filename})
ON CREATE SET bin.path = e.filename, bin.hostname = e.hostname

// Link Execution
MERGE (p)-[r:EXECUTED]->(bin)
ON CREATE SET r.timestamp = e.epoch_timestamp
"""

# 3. NETWORK ACTIVITY (Connect)
Q_NET = """
UNWIND $events AS e
MATCH (p:Process {unique_id: e.hostname + "_" + toString(e.pid) + "_" + toString(e.process_start_time)})

// Create Socket/IP Node
MERGE (sock:Socket {unique_id: e.dest_ip + ":" + toString(e.dest_port)})
ON CREATE SET sock.ip = e.dest_ip, sock.port = e.dest_port

// Link Connection
MERGE (p)-[r:CONNECTED_TO]->(sock)
ON CREATE SET r.timestamp = e.epoch_timestamp, r.proto = e.protocol
"""

# 4. FILE ACCESS (Open/Write)
Q_FILE = """
UNWIND $events AS e
MATCH (p:Process {unique_id: e.hostname + "_" + toString(e.pid) + "_" + toString(e.process_start_time)})

MERGE (f:File {unique_id: e.hostname + ":" + e.filename})
ON CREATE SET f.path = e.filename, f.hostname = e.hostname

MERGE (p)-[r:OPENED]->(f)
ON CREATE SET r.timestamp = e.epoch_timestamp, r.mode = e.syscall
"""

def sync_to_neo4j(driver: Driver, batch, db_name="neo4j"):
    """Sorts events into buckets and runs batch Cypher queries"""
    buckets = {
        'spawn': [], # clone, fork
        'exec': [],  # execve
        'net': [],   # connect
        'file': []   # openat, write
    }

    count = 0
    for event in batch:
        sys = event.get('syscall', '')
        
        # Skip failed events (negative ret), EXCEPT for execve (captured at entry)
        # Note: Your current main.bpf.c captures execve at entry, so ret might be 0/garbage. 
        # We process it anyway to capture the attempt.
        if sys != 'execve' and event.get('ret', 0) < 0:
            continue

        if sys in ['clone', 'fork', 'vfork']:
            buckets['spawn'].append(event)
        elif sys == 'execve':
            buckets['exec'].append(event)
        elif sys == 'connect':
            if event.get('dest_ip') and event.get('dest_port'):
                buckets['net'].append(event)
        elif sys in ['openat', 'write']:
            # Filter noise: don't graph /proc, /sys, or /dev/null
            fname = event.get('filename', '')
            if not is_noise(fname):
                buckets['file'].append(event)
        count += 1

    with driver.session(database=db_name) as session:
        if buckets['spawn']:
            session.run(Q_SPAWN, events=buckets['spawn'])
        if buckets['exec']:
            session.run(Q_EXEC, events=buckets['exec'])
        if buckets['net']:
            session.run(Q_NET, events=buckets['net'])
        if buckets['file']:
            session.run(Q_FILE, events=buckets['file'])
            
    return count

def main():
    # 1. Connect to Elasticsearch
    es_config = load_es_config()
    protocol = "http"
    if es_config.get('secure'):
        protocol = "https"
    
    es_url = f"{protocol}://{es_config.get('es_host', 'localhost')}:{es_config.get('es_port', 9200)}"
    es = Elasticsearch(
        [es_url],
        basic_auth=(es_config.get('es_user', 'elastic'), es_config.get('es_password', '')),
        verify_certs=False,
        request_timeout=30
    )

    # 2. Connect to Neo4j
    neo4j_config = load_neo4j_config()
    neo4j_uri = neo4j_config.get("neo4j_uri", "bolt://localhost:7687")
    neo4j_user = neo4j_config.get("neo4j_user", "neo4j")
    neo4j_pass = neo4j_config.get("neo4j_password", "")
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
    
    # 3. Resume State (Bookmark)
    bookmark_file = "/var/monitoring/neo4j_cursor.txt"
    last_ts = 0
    if os.path.exists(bookmark_file):
        try:
            with open(bookmark_file, 'r') as f:
                last_ts = int(f.read().strip())
        except:
            last_ts = 0
            
    logging.info(f"Graph Builder started. Resuming from timestamp: {last_ts}")

    while True:
        try:
            # Poll for new events since last checkpoint
            query = {
                "bool": {
                    "must": [
                        {"range": {"epoch_timestamp": {"gt": last_ts}}}
                    ]
                }
            }

            # Scroll/Search - limit to 1000 to keep batches manageable
            resp = es.search(
                index=es_config.get("ebpf_index", "ebpf-events"),
                query=query,
                sort=[{"epoch_timestamp": "asc"}],
                size=1000
            )

            hits = resp['hits']['hits']
            if not hits:
                time.sleep(2) # No new data, sleep
                continue

            events = [h['_source'] for h in hits]

            # Sync
            database = neo4j_config.get("database", "neo4j")
            processed_count = sync_to_neo4j(driver, events, database)
            
            # Checkpoint
            new_ts = events[-1]['epoch_timestamp']
            if new_ts > last_ts:
                last_ts = new_ts
                with open(bookmark_file, 'w') as f:
                    f.write(str(last_ts))
            
            if processed_count > 0:
                logging.info(f"Synced {len(events)} events (Processed: {processed_count})")

        except Exception as e:
            logging.error(f"Sync loop error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()