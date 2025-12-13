#!/usr/bin/env python3
"""
SPECTRA Automated Narrative Generation
Transforms provenance graphs into natural language attack stories
"""

import networkx as nx
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Any
import re


class AttackNarrativeGenerator:
    """Generates natural language narratives from provenance graphs"""

    def __init__(self, graph: nx.DiGraph, mitre_techniques: Dict = None,
                 events: List[Dict] = None, stats: Dict = None):
        self.graph = graph
        self.mitre_techniques = mitre_techniques or {}
        self.events = events or []
        self.stats = stats or {}

        # Attack phase templates
        self.phase_templates = {
            'initial_access': "The attack began at {time} when {actor} {action}.",
            'execution': "The adversary executed {process} which {action}.",
            'persistence': "To maintain access, {actor} {action}.",
            'privilege_escalation': "Privilege escalation occurred when {actor} {action}.",
            'credential_access': "{actor} attempted to access credentials by {action}.",
            'discovery': "The attacker performed reconnaissance by {action}.",
            'lateral_movement': "{actor} moved laterally by {action}.",
            'collection': "Data collection occurred when {actor} {action}.",
            'exfiltration': "Data exfiltration was detected when {actor} {action}.",
            'impact': "System impact occurred when {actor} {action}."
        }

    def generate_narrative(self) -> str:
        """Generate complete attack narrative"""
        narrative_parts = []

        # Title
        narrative_parts.append(self._generate_title())
        narrative_parts.append("")

        # Executive Summary
        narrative_parts.append(self._generate_executive_summary())
        narrative_parts.append("")

        # Attack Timeline
        narrative_parts.append("## Attack Timeline\n")
        narrative_parts.append(self._generate_timeline_narrative())
        narrative_parts.append("")

        # Attack Phases
        narrative_parts.append("## Attack Phase Analysis\n")
        narrative_parts.append(self._generate_phase_analysis())
        narrative_parts.append("")

        # Key Indicators
        narrative_parts.append("## Key Indicators of Compromise\n")
        narrative_parts.append(self._generate_ioc_summary())
        narrative_parts.append("")

        # MITRE ATT&CK Mapping
        if self.mitre_techniques:
            narrative_parts.append("## MITRE ATT&CK Techniques\n")
            narrative_parts.append(self._generate_mitre_narrative())
            narrative_parts.append("")

        # Recommendations
        narrative_parts.append("## Remediation Recommendations\n")
        narrative_parts.append(self._generate_recommendations())

        return "\n".join(narrative_parts)

    def _generate_title(self) -> str:
        """Generate narrative title"""
        attack_type = self._identify_attack_type()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"# Security Incident Report: {attack_type}\n**Generated:** {timestamp}"

    def _identify_attack_type(self) -> str:
        """Identify primary attack type from MITRE techniques"""
        if not self.mitre_techniques:
            return "Suspicious Activity"

        # Map tactics to attack types
        tactic_mapping = {
            'Exfiltration': 'Data Exfiltration Attack',
            'Impact': 'Destructive Attack',
            'Credential Access': 'Credential Theft',
            'Lateral Movement': 'Network Intrusion',
            'Persistence': 'Persistence Establishment',
            'Privilege Escalation': 'Privilege Escalation Attack',
            'Execution': 'Code Execution Attack'
        }

        # Count techniques per tactic
        tactic_counts = defaultdict(int)
        for tech in self.mitre_techniques.values():
            tactic = tech.get('tactic', 'Unknown')
            tactic_counts[tactic] += 1

        if tactic_counts:
            primary_tactic = max(tactic_counts.items(), key=lambda x: x[1])[0]
            return tactic_mapping.get(primary_tactic, f"{primary_tactic} Attack")

        return "Multi-Stage Attack"

    def _generate_executive_summary(self) -> str:
        """Generate executive summary"""
        summary_parts = ["## Executive Summary\n"]

        # Identify key actors
        actors = self._identify_actors()
        if actors:
            primary_actor = actors[0]
            summary_parts.append(
                f"This incident involved suspicious activity initiated by the process "
                f"**{primary_actor['name']}** (PID: {primary_actor['pid']})."
            )

        # Count events and graph complexity
        if self.stats:
            events_loaded = self.stats.get('events_loaded', 0)
            events_filtered = self.stats.get('events_filtered', 0)
            nodes = self.stats.get('nodes', 0)
            edges = self.stats.get('edges', 0)

            summary_parts.append(
                f"Analysis of {events_loaded:,} system events (filtered to {events_filtered:,} relevant events) "
                f"revealed a provenance graph with {nodes} entities and {edges} relationships."
            )

        # Severity assessment
        severity = self._assess_severity()
        summary_parts.append(f"\n**Severity:** {severity['level']} - {severity['description']}")

        return "\n".join(summary_parts)

    def _assess_severity(self) -> Dict[str, str]:
        """Assess attack severity"""
        score = 0

        # Check MITRE techniques
        if self.mitre_techniques:
            high_severity_tactics = ['Exfiltration', 'Impact', 'Credential Access']
            for tech in self.mitre_techniques.values():
                if tech.get('tactic') in high_severity_tactics:
                    score += 3
                else:
                    score += 1

        # Check for sensitive file access
        sensitive_patterns = [r'/etc/shadow', r'/etc/passwd', r'\.ssh', r'secret', r'credential']
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'file':
                label = data.get('label', '')
                if any(re.search(pattern, label, re.I) for pattern in sensitive_patterns):
                    score += 2

        # Check for network activity
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'network':
                score += 1

        # Determine severity level
        if score >= 10:
            return {'level': '🔴 CRITICAL', 'description': 'Immediate action required'}
        elif score >= 5:
            return {'level': '🟠 HIGH', 'description': 'Prompt investigation needed'}
        elif score >= 2:
            return {'level': '🟡 MEDIUM', 'description': 'Further analysis recommended'}
        else:
            return {'level': '🟢 LOW', 'description': 'Routine monitoring'}

    def _identify_actors(self) -> List[Dict[str, Any]]:
        """Identify key process actors in the attack"""
        actors = []

        # Look for process nodes
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'process':
                label = data.get('label', '')
                # Extract PID and name from label (format: "name\nPID:12345")
                parts = label.split('\n')
                name = parts[0] if parts else 'unknown'
                pid = None
                if len(parts) > 1 and 'PID:' in parts[1]:
                    pid = parts[1].replace('PID:', '').strip()

                # Calculate importance (out-degree)
                importance = self.graph.out_degree(node)

                actors.append({
                    'name': name,
                    'pid': pid,
                    'node': node,
                    'importance': importance
                })

        # Sort by importance
        actors.sort(key=lambda x: x['importance'], reverse=True)
        return actors

    def _generate_timeline_narrative(self) -> str:
        """Generate chronological narrative"""
        if not self.events:
            return "Timeline information not available."

        # Sort events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e.get('timestamp_ms', 0))

        if not sorted_events:
            return "No events available for timeline."

        narrative_parts = []

        # Group events by time windows (5-minute intervals)
        time_windows = defaultdict(list)
        for event in sorted_events:
            ts = event.get('timestamp_ms', 0)
            window = (ts // (5 * 60 * 1000)) * (5 * 60 * 1000)  # 5-minute window
            time_windows[window].append(event)

        # Generate narrative for each window
        for window_start, window_events in sorted(time_windows.items()):
            if len(window_events) > 0:
                time_str = datetime.fromtimestamp(window_start / 1000).strftime("%H:%M:%S")
                narrative_parts.append(f"**[{time_str}]** {self._describe_event_window(window_events)}")

        return "\n\n".join(narrative_parts)

    def _describe_event_window(self, events: List[Dict]) -> str:
        """Describe a window of events"""
        if not events:
            return ""

        # Categorize events
        syscalls = [e.get('syscall') for e in events if e.get('syscall')]
        processes = set(e.get('comm') or e.get('process.name') for e in events)
        files = [e.get('filename') or e.get('file.path') for e in events if e.get('filename') or e.get('file.path')]

        # Build description
        parts = []

        if processes:
            process_list = ', '.join(f"`{p}`" for p in list(processes)[:3])
            parts.append(f"Process(es) {process_list}")

        # Describe primary activity
        if syscalls:
            syscall_counts = defaultdict(int)
            for sc in syscalls:
                syscall_counts[sc] += 1
            top_syscall = max(syscall_counts.items(), key=lambda x: x[1])

            activity_desc = {
                'execve': 'executed new processes',
                'openat': 'accessed files',
                'read': 'read data',
                'write': 'wrote data',
                'connect': 'established network connections',
                'sendto': 'sent network data',
                'unlinkat': 'deleted files'
            }

            action = activity_desc.get(top_syscall[0], f'performed {top_syscall[0]}')
            parts.append(action)

            if top_syscall[1] > 1:
                parts.append(f"({top_syscall[1]} times)")

        # Add file context if significant
        if files and len(files) <= 3:
            file_list = ', '.join(f"`{f}`" for f in files[:3] if f)
            if file_list:
                parts.append(f"targeting {file_list}")

        return " ".join(parts) + "."

    def _generate_phase_analysis(self) -> str:
        """Generate attack phase analysis"""
        if not self.mitre_techniques:
            return "No MITRE ATT&CK techniques detected to analyze attack phases."

        # Group techniques by tactic
        tactic_groups = defaultdict(list)
        for tech_id, tech in self.mitre_techniques.items():
            tactic = tech.get('tactic', 'Unknown')
            tactic_groups[tactic].append(tech)

        # Define phase order
        phase_order = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Command and Control', 'Exfiltration', 'Impact'
        ]

        narrative_parts = []

        for phase in phase_order:
            if phase in tactic_groups:
                techniques = tactic_groups[phase]
                narrative_parts.append(f"### {phase}\n")

                for tech in techniques:
                    tech_name = tech.get('name', 'Unknown')
                    tech_id = tech.get('tid', '')
                    description = tech.get('description', '')
                    evidence = tech.get('evidence', [])

                    narrative_parts.append(f"**{tech_id}: {tech_name}**")
                    if description:
                        narrative_parts.append(f"{description}")

                    if evidence:
                        narrative_parts.append("\nEvidence:")
                        for ev in evidence[:3]:  # Limit to top 3
                            narrative_parts.append(f"- {ev}")

                    narrative_parts.append("")

        return "\n".join(narrative_parts)

    def _generate_ioc_summary(self) -> str:
        """Generate IOC summary"""
        iocs = {
            'processes': [],
            'files': [],
            'network': [],
            'users': []
        }

        # Extract IOCs from graph
        for node, data in self.graph.nodes(data=True):
            node_type = data.get('type', '')
            label = data.get('label', '').replace('\n', ' ')

            if node_type == 'process':
                iocs['processes'].append(label)
            elif node_type == 'file':
                iocs['files'].append(label)
            elif node_type == 'network':
                iocs['network'].append(label)

        narrative_parts = []

        if iocs['processes']:
            narrative_parts.append(f"**Suspicious Processes ({len(iocs['processes'])}):**")
            for proc in iocs['processes'][:10]:
                narrative_parts.append(f"- {proc}")
            if len(iocs['processes']) > 10:
                narrative_parts.append(f"- ... and {len(iocs['processes']) - 10} more")
            narrative_parts.append("")

        if iocs['files']:
            narrative_parts.append(f"**Accessed Files ({len(iocs['files'])}):**")
            for file in iocs['files'][:10]:
                narrative_parts.append(f"- {file}")
            if len(iocs['files']) > 10:
                narrative_parts.append(f"- ... and {len(iocs['files']) - 10} more")
            narrative_parts.append("")

        if iocs['network']:
            narrative_parts.append(f"**Network Connections ({len(iocs['network'])}):**")
            for net in iocs['network'][:10]:
                narrative_parts.append(f"- {net}")
            if len(iocs['network']) > 10:
                narrative_parts.append(f"- ... and {len(iocs['network']) - 10} more")
            narrative_parts.append("")

        return "\n".join(narrative_parts) if narrative_parts else "No significant IOCs identified."

    def _generate_mitre_narrative(self) -> str:
        """Generate MITRE ATT&CK narrative"""
        if not self.mitre_techniques:
            return "No MITRE ATT&CK techniques mapped."

        narrative_parts = []

        # Count techniques per tactic
        tactic_counts = defaultdict(int)
        for tech in self.mitre_techniques.values():
            tactic = tech.get('tactic', 'Unknown')
            tactic_counts[tactic] += 1

        narrative_parts.append(
            f"The attack exhibited behaviors consistent with **{len(self.mitre_techniques)} "
            f"MITRE ATT&CK techniques** across **{len(tactic_counts)} tactics**."
        )
        narrative_parts.append("")

        # Highlight top tactics
        top_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_tactics:
            narrative_parts.append("**Primary Tactics:**")
            for tactic, count in top_tactics:
                narrative_parts.append(f"- **{tactic}**: {count} technique(s)")
            narrative_parts.append("")

        return "\n".join(narrative_parts)

    def _generate_recommendations(self) -> str:
        """Generate remediation recommendations"""
        recommendations = []

        # Based on MITRE techniques
        if self.mitre_techniques:
            technique_based_recs = {
                'Credential Access': [
                    "Rotate all credentials that may have been compromised",
                    "Enable multi-factor authentication for privileged accounts",
                    "Review and restrict access to credential stores"
                ],
                'Persistence': [
                    "Review and remove unauthorized scheduled tasks/cron jobs",
                    "Check system startup scripts for malicious modifications",
                    "Audit user accounts for unauthorized additions"
                ],
                'Exfiltration': [
                    "Investigate data accessed before network transmission",
                    "Review firewall rules for unauthorized egress traffic",
                    "Implement DLP controls on sensitive data"
                ],
                'Privilege Escalation': [
                    "Review sudo/SUID configurations",
                    "Patch systems for known privilege escalation vulnerabilities",
                    "Implement least-privilege access controls"
                ],
                'Execution': [
                    "Review executed binaries for malicious code",
                    "Implement application whitelisting",
                    "Restrict script execution in user-writable directories"
                ]
            }

            tactics_seen = set(tech.get('tactic') for tech in self.mitre_techniques.values())

            for tactic in tactics_seen:
                if tactic in technique_based_recs:
                    recommendations.extend(technique_based_recs[tactic])

        # General recommendations
        general_recs = [
            "Conduct forensic analysis of affected systems",
            "Review logs for additional indicators of compromise",
            "Update detection rules based on observed TTPs",
            "Implement enhanced monitoring for similar activities"
        ]

        all_recs = list(set(recommendations + general_recs))  # Remove duplicates

        narrative_parts = []
        for i, rec in enumerate(all_recs[:10], 1):
            narrative_parts.append(f"{i}. {rec}")

        return "\n".join(narrative_parts)

    def generate_short_summary(self) -> str:
        """Generate a concise one-paragraph summary"""
        attack_type = self._identify_attack_type()
        actors = self._identify_actors()
        severity = self._assess_severity()

        if actors:
            primary_actor = actors[0]
            summary = (
                f"{severity['level']} {attack_type} detected. "
                f"The incident was initiated by {primary_actor['name']} (PID: {primary_actor['pid']}). "
            )
        else:
            summary = f"{severity['level']} {attack_type} detected. "

        if self.mitre_techniques:
            tactic_counts = defaultdict(int)
            for tech in self.mitre_techniques.values():
                tactic_counts[tech.get('tactic', 'Unknown')] += 1

            top_tactic = max(tactic_counts.items(), key=lambda x: x[1])[0]
            summary += f"Analysis revealed {len(self.mitre_techniques)} MITRE ATT&CK techniques, "
            summary += f"with primary focus on {top_tactic}. "

        summary += "Immediate investigation and remediation recommended."

        return summary


def generate_narrative_from_analysis(graph: nx.DiGraph,
                                     mitre_techniques: Dict = None,
                                     events: List[Dict] = None,
                                     stats: Dict = None) -> Tuple[str, str]:
    """
    Generate both full and short narratives from analysis results

    Args:
        graph: NetworkX provenance graph
        mitre_techniques: Dictionary of MITRE ATT&CK techniques
        events: List of events used in analysis
        stats: Analysis statistics

    Returns:
        Tuple of (full_narrative, short_summary)
    """
    generator = AttackNarrativeGenerator(graph, mitre_techniques, events, stats)

    full_narrative = generator.generate_narrative()
    short_summary = generator.generate_short_summary()

    return full_narrative, short_summary
