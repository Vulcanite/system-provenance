#!/usr/bin/env python3
"""
SPECTRA Evaluation Metrics
Measures effectiveness of log reduction and graph compression
"""

import networkx as nx
from typing import Dict, List, Tuple, Any
from collections import defaultdict
import json


class EvaluationMetrics:
    """Calculates and tracks SPECTRA performance metrics"""

    def __init__(self):
        self.metrics_history = []

    def compute_log_reduction(self,
                             original_count: int,
                             filtered_count: int) -> Dict[str, Any]:
        """
        Calculate log reduction metrics

        Args:
            original_count: Number of events before filtering
            filtered_count: Number of events after filtering

        Returns:
            Dictionary with reduction metrics
        """
        if original_count == 0:
            return {
                'original_count': 0,
                'filtered_count': 0,
                'reduction_ratio': 0.0,
                'reduction_percentage': 0.0,
                'compression_factor': 1.0
            }

        reduction_ratio = 1 - (filtered_count / original_count)
        reduction_percentage = reduction_ratio * 100
        compression_factor = original_count / filtered_count if filtered_count > 0 else float('inf')

        return {
            'original_count': original_count,
            'filtered_count': filtered_count,
            'reduction_ratio': reduction_ratio,
            'reduction_percentage': reduction_percentage,
            'compression_factor': compression_factor,
            'events_removed': original_count - filtered_count
        }

    def compute_graph_compression(self,
                                  original_graph: nx.DiGraph = None,
                                  reduced_graph: nx.DiGraph = None,
                                  original_nodes: int = None,
                                  original_edges: int = None,
                                  reduced_nodes: int = None,
                                  reduced_edges: int = None) -> Dict[str, Any]:
        """
        Calculate graph compression metrics

        Can accept either graph objects or node/edge counts directly.

        Returns:
            Dictionary with compression metrics
        """
        # Extract counts from graphs if provided
        if original_graph is not None:
            original_nodes = original_graph.number_of_nodes()
            original_edges = original_graph.number_of_edges()

        if reduced_graph is not None:
            reduced_nodes = reduced_graph.number_of_nodes()
            reduced_edges = reduced_graph.number_of_edges()

        # Handle cases where counts are not available
        if original_nodes is None or reduced_nodes is None:
            return {
                'original_nodes': 0,
                'reduced_nodes': 0,
                'node_reduction_ratio': 0.0,
                'node_reduction_percentage': 0.0,
                'original_edges': 0,
                'reduced_edges': 0,
                'edge_reduction_ratio': 0.0,
                'edge_reduction_percentage': 0.0,
                'overall_compression': 0.0
            }

        # Node compression
        node_reduction = 1 - (reduced_nodes / original_nodes) if original_nodes > 0 else 0.0
        node_reduction_pct = node_reduction * 100

        # Edge compression
        edge_reduction = 1 - (reduced_edges / original_edges) if original_edges > 0 else 0.0
        edge_reduction_pct = edge_reduction * 100

        # Overall compression (average of node and edge reduction)
        overall_compression = (node_reduction + edge_reduction) / 2

        return {
            'original_nodes': original_nodes,
            'reduced_nodes': reduced_nodes,
            'nodes_removed': original_nodes - reduced_nodes,
            'node_reduction_ratio': node_reduction,
            'node_reduction_percentage': node_reduction_pct,
            'original_edges': original_edges,
            'reduced_edges': reduced_edges,
            'edges_removed': original_edges - reduced_edges,
            'edge_reduction_ratio': edge_reduction,
            'edge_reduction_percentage': edge_reduction_pct,
            'overall_compression': overall_compression,
            'overall_compression_percentage': overall_compression * 100
        }

    def compute_algorithm_effectiveness(self,
                                       baseline_metrics: Dict,
                                       algorithm_metrics: Dict,
                                       algorithm_name: str) -> Dict[str, Any]:
        """
        Compare algorithm performance against baseline

        Args:
            baseline_metrics: Metrics without algorithm
            algorithm_metrics: Metrics with algorithm applied
            algorithm_name: Name of algorithm (e.g., "BEEP", "HOLMES")

        Returns:
            Effectiveness comparison metrics
        """
        effectiveness = {
            'algorithm': algorithm_name,
            'additional_reduction': 0.0,
            'efficiency_gain': 0.0,
            'overhead': 0.0
        }

        # Calculate additional reduction beyond baseline
        baseline_kept = baseline_metrics.get('filtered_count', 0)
        algorithm_kept = algorithm_metrics.get('filtered_count', 0)

        if baseline_kept > 0:
            additional_reduction = (baseline_kept - algorithm_kept) / baseline_kept
            effectiveness['additional_reduction'] = additional_reduction * 100

        return effectiveness

    def compute_coverage_metrics(self,
                                graph: nx.DiGraph,
                                critical_nodes: List[str] = None) -> Dict[str, Any]:
        """
        Calculate coverage of critical attack paths

        Args:
            graph: Provenance graph
            critical_nodes: List of critical node IDs that must be preserved

        Returns:
            Coverage metrics
        """
        metrics = {
            'total_nodes': graph.number_of_nodes(),
            'total_edges': graph.number_of_edges(),
            'connected_components': nx.number_weakly_connected_components(graph),
            'critical_nodes_preserved': 0,
            'critical_node_coverage': 0.0,
            'average_path_length': 0.0,
            'graph_diameter': 0
        }

        # Check critical node preservation
        if critical_nodes:
            preserved = sum(1 for node in critical_nodes if node in graph.nodes())
            metrics['critical_nodes_preserved'] = preserved
            metrics['critical_node_coverage'] = (preserved / len(critical_nodes) * 100) if critical_nodes else 0.0

        # Graph connectivity metrics
        try:
            if graph.number_of_nodes() > 1:
                # Convert to undirected for path analysis
                undirected = graph.to_undirected()

                # Get largest connected component
                largest_cc = max(nx.connected_components(undirected), key=len)
                subgraph = undirected.subgraph(largest_cc)

                if len(subgraph.nodes()) > 1:
                    metrics['average_path_length'] = nx.average_shortest_path_length(subgraph)
                    metrics['graph_diameter'] = nx.diameter(subgraph)
        except:
            pass  # Skip if graph is disconnected or calculation fails

        return metrics

    def compute_noise_distribution(self, events: List[Dict]) -> Dict[str, Any]:
        """
        Analyze distribution of noise categories in events

        Args:
            events: List of event dictionaries

        Returns:
            Noise distribution metrics
        """
        syscall_counts = defaultdict(int)
        process_counts = defaultdict(int)
        file_categories = defaultdict(int)

        for event in events:
            # Count syscalls
            syscall = event.get('syscall', 'unknown')
            syscall_counts[syscall] += 1

            # Count processes
            comm = event.get('comm') or event.get('process.name', 'unknown')
            process_counts[comm] += 1

            # Categorize files
            filename = event.get('filename') or event.get('file.path', '')
            if filename:
                if filename.startswith('/proc/') or filename.startswith('/sys/'):
                    file_categories['kernel_pseudo_fs'] += 1
                elif filename.startswith('/lib') or filename.startswith('/usr/lib'):
                    file_categories['shared_libraries'] += 1
                elif filename.startswith('/var/log/'):
                    file_categories['system_logging'] += 1
                elif filename.startswith('/tmp/'):
                    file_categories['temp_files'] += 1
                else:
                    file_categories['other'] += 1

        return {
            'total_events': len(events),
            'unique_syscalls': len(syscall_counts),
            'unique_processes': len(process_counts),
            'top_syscalls': dict(sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_processes': dict(sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'file_category_distribution': dict(file_categories)
        }

    def generate_metrics_report(self,
                               log_reduction: Dict = None,
                               graph_compression: Dict = None,
                               coverage: Dict = None,
                               noise_dist: Dict = None,
                               algorithm_name: str = "Standard") -> str:
        """
        Generate comprehensive metrics report

        Returns:
            Formatted metrics report as string
        """
        report_lines = []

        report_lines.append("=" * 70)
        report_lines.append("SPECTRA EVALUATION METRICS REPORT")
        report_lines.append("=" * 70)
        report_lines.append("")

        # Log Reduction Metrics
        if log_reduction:
            report_lines.append("## LOG REDUCTION METRICS")
            report_lines.append("-" * 70)
            report_lines.append(f"Algorithm: {algorithm_name}")
            report_lines.append(f"Original Events:      {log_reduction['original_count']:,}")
            report_lines.append(f"Filtered Events:      {log_reduction['filtered_count']:,}")
            report_lines.append(f"Events Removed:       {log_reduction['events_removed']:,}")
            report_lines.append(f"Reduction Ratio:      {log_reduction['reduction_ratio']:.3f}")
            report_lines.append(f"Reduction Percentage: {log_reduction['reduction_percentage']:.1f}%")
            report_lines.append(f"Compression Factor:   {log_reduction['compression_factor']:.2f}x")
            report_lines.append("")

        # Graph Compression Metrics
        if graph_compression:
            report_lines.append("## GRAPH COMPRESSION METRICS")
            report_lines.append("-" * 70)
            report_lines.append(f"Original Nodes:       {graph_compression['original_nodes']:,}")
            report_lines.append(f"Reduced Nodes:        {graph_compression['reduced_nodes']:,}")
            report_lines.append(f"Nodes Removed:        {graph_compression['nodes_removed']:,} "
                              f"({graph_compression['node_reduction_percentage']:.1f}%)")
            report_lines.append(f"Original Edges:       {graph_compression['original_edges']:,}")
            report_lines.append(f"Reduced Edges:        {graph_compression['reduced_edges']:,}")
            report_lines.append(f"Edges Removed:        {graph_compression['edges_removed']:,} "
                              f"({graph_compression['edge_reduction_percentage']:.1f}%)")
            report_lines.append(f"Overall Compression:  {graph_compression['overall_compression_percentage']:.1f}%")
            report_lines.append("")

        # Coverage Metrics
        if coverage:
            report_lines.append("## COVERAGE METRICS")
            report_lines.append("-" * 70)
            report_lines.append(f"Total Nodes:          {coverage['total_nodes']}")
            report_lines.append(f"Total Edges:          {coverage['total_edges']}")
            report_lines.append(f"Connected Components: {coverage['connected_components']}")
            if coverage.get('critical_nodes_preserved') is not None:
                report_lines.append(f"Critical Nodes:       {coverage['critical_nodes_preserved']} "
                                  f"({coverage['critical_node_coverage']:.1f}% coverage)")
            if coverage.get('average_path_length', 0) > 0:
                report_lines.append(f"Avg Path Length:      {coverage['average_path_length']:.2f}")
                report_lines.append(f"Graph Diameter:       {coverage['graph_diameter']}")
            report_lines.append("")

        # Noise Distribution
        if noise_dist:
            report_lines.append("## NOISE DISTRIBUTION")
            report_lines.append("-" * 70)
            report_lines.append(f"Total Events:         {noise_dist['total_events']:,}")
            report_lines.append(f"Unique Syscalls:      {noise_dist['unique_syscalls']}")
            report_lines.append(f"Unique Processes:     {noise_dist['unique_processes']}")

            if noise_dist.get('top_syscalls'):
                report_lines.append("\nTop Syscalls:")
                for syscall, count in list(noise_dist['top_syscalls'].items())[:5]:
                    report_lines.append(f"  - {syscall:15s} {count:,}")

            if noise_dist.get('file_category_distribution'):
                report_lines.append("\nFile Category Distribution:")
                for category, count in noise_dist['file_category_distribution'].items():
                    pct = (count / noise_dist['total_events'] * 100) if noise_dist['total_events'] > 0 else 0
                    report_lines.append(f"  - {category:20s} {count:6,} ({pct:5.1f}%)")
            report_lines.append("")

        report_lines.append("=" * 70)

        return "\n".join(report_lines)

    def export_metrics_json(self, metrics: Dict, filename: str):
        """Export metrics to JSON file"""
        with open(filename, 'w') as f:
            json.dump(metrics, f, indent=2)

    def record_metrics(self, **kwargs):
        """Record metrics to history for tracking over time"""
        from datetime import datetime

        record = {
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.metrics_history.append(record)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all recorded metrics"""
        if not self.metrics_history:
            return {}

        return {
            'total_analyses': len(self.metrics_history),
            'latest_metrics': self.metrics_history[-1] if self.metrics_history else {},
            'average_reduction': sum(
                m.get('log_reduction', {}).get('reduction_percentage', 0)
                for m in self.metrics_history
            ) / len(self.metrics_history) if self.metrics_history else 0.0
        }
