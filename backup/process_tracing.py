#!/usr/bin/env python3

from elasticsearch import Elasticsearch
from collections import deque


class ProcessTracer:
    """
    Simple process tree tracer over eBPF events in Elasticsearch.

    Produces a raw graph of the form:

        {
          "1234": {
             "events": [ {...}, {...}, ... ],
             "exec_transitions": [
                 {"timestamp": ..., "new_comm": ..., "binary": ...},
                 ...
             ],
             "children": {"2345", "2346", ...}
          },
          ...
        }

    This structure is what noise_reduce.normalize_graph_for_bipartite()
    expects as input.
    """

    def __init__(self, es: Elasticsearch, index: str):
        self.es = es
        self.index = index
        self.graph = {}
        self.visited = set()

    # ----------------------------------------------------
    # Generic scroll helper
    # ----------------------------------------------------
    def scroll_query(self, query):
        """Perform an unlimited-size scroll query safely."""
        results = []
        resp = self.es.search(
            index=self.index,
            body=query,
            scroll="2m",
            size=5000,  # batch size
        )

        scroll_id = resp.get("_scroll_id")
        hits = resp["hits"]["hits"]

        while hits:
            for h in hits:
                results.append(h["_source"])

            resp = self.es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = resp.get("_scroll_id")
            hits = resp["hits"]["hits"]

        # Cleanup scroll
        if scroll_id:
            try:
                self.es.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass

        return results

    # ----------------------------------------------------
    # Get all PIDs for a given command name
    # ----------------------------------------------------
    def find_seed_pids(self, hostname, process):
        """
        Find all PIDs whose comm matches the given command name.
        """
        must_filters = [
            {"term": {"comm.keyword": process}}
        ]

        if hostname:
            must_filters.append({"term": {"hostname.keyword": hostname}})

        query = {
            "query": {
                "bool": {
                    "must": must_filters
                }
            },
            "_source": ["pid"],
            "size": 5000,
        }

        resp = self.es.search(index=self.index, body=query)
        pids = {hit["_source"]["pid"] for hit in resp["hits"]["hits"]}
        return list(pids)

    # ----------------------------------------------------
    # Load all events for a given PID (hostname + time filter)
    # ----------------------------------------------------
    def load_events(self, hostname, pid, start_ms=None, end_ms=None):
        """
        Load all events for a PID, optionally restricted to a host and
        a [start_ms, end_ms] time window on epoch_timestamp.
        """
        try:
            pid_val = int(pid)
        except Exception:
            pid_val = pid

        must_filters = [
            {"term": {"pid": pid_val}}
        ]

        if hostname:
            must_filters.append({"term": {"hostname.keyword": hostname}})

        if start_ms is not None and end_ms is not None:
            must_filters.append({
                "range": {
                    "epoch_timestamp": {
                        "gte": int(start_ms),
                        "lte": int(end_ms),
                    }
                }
            })

        query = {
            "query": {
                "bool": {
                    "must": must_filters
                }
            },
            "_source": True,
        }

        return self.scroll_query(query)

    # ----------------------------------------------------
    # Find children processes (hostname-aware)
    # ----------------------------------------------------
    def find_children(self, hostname, pid):
        """
        Find all PIDs whose ppid == pid (optionally filtered by hostname).
        """
        try:
            pid_val = int(pid)
        except Exception:
            pid_val = pid

        must_filters = [
            {"term": {"ppid": pid_val}}
        ]

        if hostname:
            must_filters.append({"term": {"hostname.keyword": hostname}})

        query = {
            "query": {
                "bool": {
                    "must": must_filters
                }
            },
            "_source": ["pid"],
        }

        results = self.scroll_query(query)
        return {r["pid"] for r in results}

    # ----------------------------------------------------
    # Extract exec transitions (comm changes)
    # ----------------------------------------------------
    def extract_exec_transitions(self, events):
        execs = []
        for e in events:
            if e.get("syscall") == "execve":
                execs.append({
                    "timestamp": e.get("epoch_timestamp"),
                    "new_comm": e.get("comm"),
                    "binary": e.get("filename"),
                })
        return execs

    # ----------------------------------------------------
    # FULL WALK: from seed PID → descendants (BFS, hostname + time aware)
    # ----------------------------------------------------
    def trace_pid(self, hostname, root_pid, start_ms=None, end_ms=None,
                  max_depth=None):
        """
        Trace a single root PID and all of its descendants.

        Args:
            hostname: optional hostname filter (can be None).
            root_pid: PID to start from.
            start_ms, end_ms: optional epoch_ms window.
            max_depth: int or None. Depth 0 = root only, 1 = children, ...
        """
        queue = deque()
        queue.append((root_pid, 0))

        while queue:
            pid, depth = queue.popleft()
            pid_str = str(pid)

            if pid_str in self.visited:
                continue
            self.visited.add(pid_str)

            # Load this PID’s events (respecting time range)
            events = self.load_events(hostname, pid, start_ms=start_ms,
                                      end_ms=end_ms)

            # Save node data
            exec_transitions = self.extract_exec_transitions(events)
            self.graph[pid_str] = {
                "events": events,
                "exec_transitions": exec_transitions,
                "children": set(),
            }

            # Discover children PIDs (hostname-aware)
            children = self.find_children(hostname, pid)
            child_ids = {str(c) for c in children}
            self.graph[pid_str]["children"] = child_ids

            # BFS expansion with depth limit
            if max_depth is None or depth < max_depth:
                for c in children:
                    c_str = str(c)
                    if c_str not in self.visited:
                        queue.append((c, depth + 1))

        return self.graph

    # ----------------------------------------------------
    # MAIN ENTRYPOINT: trace by command name or PID
    # ----------------------------------------------------
    def trace_process(self, hostname, process=None, pid=None,
                      start_ms=None, end_ms=None, max_depth=None):
        """
        High-level entry:

        - If pid is given: trace from that PID.
        - Else if process (comm) is given: find all PIDs with that comm and
          trace them as roots.

        Returns raw graph (see class docstring).
        """
        self.graph = {}
        self.visited = set()

        seed_pids = []

        if pid is not None:
            seed_pids = [pid]
        elif process:
            seed_pids = self.find_seed_pids(hostname, process)

        if not seed_pids:
            if process:
                print(f"[!] No PIDs found for command: {process}")
            else:
                print(f"[!] No seed PID(s) provided/found.")
            return {}

        print(f"[+] Found {len(seed_pids)} seed PID(s): {seed_pids}")

        for spid in seed_pids:
            print(f"[+] Tracing PID {spid} ...")
            self.trace_pid(
                hostname,
                spid,
                start_ms=start_ms,
                end_ms=end_ms,
                max_depth=max_depth,
            )

        print(f"[✓] Completed tracing. Processes found: {len(self.graph)}")
        return self.graph
