#!/usr/bin/env python3
"""
MF-CSSA Engine Integration
Adapted from research paper for System Provenance Monitor
"""

import numpy as np
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any
import json

class DataSource:
    """Represents a cybersecurity data source with trust tracking"""
    
    def __init__(self, name: str, source_type: str, weight: float = 1.0):
        self.name = name
        self.source_type = source_type
        self.weight = weight
        self.anomaly_rate = 0.0
        self.event_count = 0
        self.anomaly_count = 0
        self.history = []
        
    def update_trust(self, lambda_decay: float = 0.1):
        """T_i(t) = e^(-λ·AnomalyRate_i(t))"""
        self.weight = np.exp(-lambda_decay * self.anomaly_rate)
        
    def record_event(self, is_anomaly: bool = False):
        """Record event and update anomaly rate"""
        self.event_count += 1
        if is_anomaly:
            self.anomaly_count += 1
        self.anomaly_rate = self.anomaly_count / self.event_count if self.event_count > 0 else 0.0
        
    def normalize_features(self, features: np.ndarray, window_size: int = 100) -> np.ndarray:
        """x̂ = (x - μ) / σ"""
        self.history.append(features)
        if len(self.history) > window_size:
            self.history.pop(0)
        
        if len(self.history) < 2:
            return features
        
        window_data = np.array(self.history)
        mean = np.mean(window_data, axis=0)
        std = np.std(window_data, axis=0)
        std[std == 0] = 1.0
        
        return (features - mean) / std


class MultiSourceFusion:
    """Feature-level fusion with weighted concatenation"""
    
    def __init__(self):
        self.sources: Dict[str, DataSource] = {}
        self.lambda_decay = 0.1
        
    def register_source(self, name: str, source_type: str, initial_weight: float = 1.0):
        self.sources[name] = DataSource(name, source_type, initial_weight)
        
    def update_source_weights(self):
        """Update all source weights based on trust scores"""
        for source in self.sources.values():
            source.update_trust(self.lambda_decay)
        
        total_weight = sum(s.weight for s in self.sources.values())
        if total_weight > 0:
            for source in self.sources.values():
                source.weight /= total_weight
                
    def fuse_features(self, source_features: Dict[str, np.ndarray]) -> np.ndarray:
        """F(t) = ⊕ ω_i · x̂_i(t)"""
        fused = []
        
        for source_name, features in source_features.items():
            if source_name not in self.sources:
                continue
                
            source = self.sources[source_name]
            normalized = source.normalize_features(features)
            weighted = source.weight * normalized
            fused.append(weighted)
        
        if not fused:
            return np.array([])
        
        return np.concatenate(fused)


class ThreatScenario:
    """Known threat scenario with severity"""
    
    def __init__(self, name: str, severity: float, description: str = ""):
        self.name = name
        self.severity = severity
        self.description = description
        self.priority_weight = 1.0


class SimpleBayesianInference:
    """Simplified Bayesian threat inference without pgmpy dependency"""
    
    def __init__(self):
        self.threat_scenarios: Dict[str, ThreatScenario] = {}
        self.threat_chain = {}  # parent -> children mapping
        self.base_probs = {}  # prior probabilities
        
    def define_threat_scenarios(self):
        """Define common threat scenarios"""
        scenarios = {
            'PortScan': (0.3, 'Port scanning detected'),
            'NetworkRecon': (0.4, 'Network reconnaissance detected'),
            'Exploit': (0.7, 'Exploitation attempt detected'),
            'Phishing': (0.6, 'Phishing attempt detected'),
            'PrivEsc': (0.8, 'Privilege escalation detected'),
            'LateralMove': (0.7, 'Lateral movement detected'),
            'DataExfil': (0.9, 'Data exfiltration detected'),
            'Ransomware': (1.0, 'Ransomware activity detected'),
            'DDoS': (0.8, 'DDoS attack detected')
        }
        
        for name, (severity, desc) in scenarios.items():
            self.add_scenario(name, severity, desc)
            
        # Define attack chains
        self.threat_chain = {
            'PortScan': ['Exploit'],
            'NetworkRecon': ['Exploit'],
            'Exploit': ['PrivEsc'],
            'Phishing': ['PrivEsc'],
            'PrivEsc': ['LateralMove', 'Ransomware'],
            'LateralMove': ['DataExfil'],
            'DataExfil': ['Ransomware']
        }
        
        # Base probabilities (priors)
        self.base_probs = {
            'PortScan': 0.05,
            'NetworkRecon': 0.10,
            'Phishing': 0.15,
            'Exploit': 0.01,
            'PrivEsc': 0.05,
            'LateralMove': 0.10,
            'DataExfil': 0.15,
            'Ransomware': 0.02,
            'DDoS': 0.05
        }
        
    def add_scenario(self, name: str, severity: float, description: str = ""):
        self.threat_scenarios[name] = ThreatScenario(name, severity, description)
        
    def infer_threats(self, evidence: Dict[str, int]) -> Dict[str, float]:
        """Compute posterior probabilities P(θ|F(t))"""
        threat_probs = {}
        
        for scenario_name in self.threat_scenarios.keys():
            base_prob = self.base_probs.get(scenario_name, 0.01)
            
            # If directly observed
            if scenario_name in evidence and evidence[scenario_name] == 1:
                threat_probs[scenario_name] = 0.95
                continue
            
            # Check if parent threats are detected (chain inference)
            parent_boost = 0.0
            for parent, children in self.threat_chain.items():
                if scenario_name in children and parent in evidence and evidence[parent] == 1:
                    parent_boost += 0.3
            
            # Combine base probability with evidence
            prob = min(0.99, base_prob + parent_boost)
            threat_probs[scenario_name] = prob
        
        return threat_probs


class SituationalAwareness:
    """Calculates situational awareness index Ψ(t)"""
    
    def __init__(self, threat_model: SimpleBayesianInference):
        self.threat_model = threat_model
        self.history = []
        
    def calculate_score(self, threat_probabilities: Dict[str, float]) -> float:
        """Ψ(t) = Σ w_k · P(θ_k|F(t)) · S_k"""
        score = 0.0
        
        for scenario_name, probability in threat_probabilities.items():
            if scenario_name in self.threat_model.threat_scenarios:
                scenario = self.threat_model.threat_scenarios[scenario_name]
                score += scenario.priority_weight * probability * scenario.severity
        
        max_possible = sum(
            s.priority_weight * s.severity 
            for s in self.threat_model.threat_scenarios.values()
        )
        
        if max_possible > 0:
            score /= max_possible
        
        score = max(0.0, min(1.0, score))
        
        self.history.append({
            'timestamp': datetime.now(),
            'score': score,
            'threats': threat_probabilities.copy()
        })
        
        return score
    
    def get_history(self, last_n: int = 100) -> List[Dict]:
        return self.history[-last_n:]


class AdaptiveLearning:
    """Reinforcement learning for source weight updates"""
    
    def __init__(self, fusion: MultiSourceFusion, learning_rate: float = 0.01):
        self.fusion = fusion
        self.learning_rate = learning_rate
        self.feedback_history = []
        
    def provide_feedback(self, 
                        feedback: int,
                        current_score: float,
                        source_contributions: Dict[str, float]):
        """ω_i(t+1) = ω_i(t) + η · (f_t - Ψ(t)) · ∂Ψ(t)/∂ω_i"""
        
        error = feedback - current_score
        
        for source_name, contribution in source_contributions.items():
            if source_name in self.fusion.sources:
                source = self.fusion.sources[source_name]
                gradient = contribution
                source.weight += self.learning_rate * error * gradient
                source.weight = max(0.0, min(1.0, source.weight))
        
        self.fusion.update_source_weights()
        
        self.feedback_history.append({
            'timestamp': datetime.now(),
            'feedback': feedback,
            'score': current_score,
            'error': error
        })


class MFCSSAEngine:
    """Main MF-CSSA engine coordinating all components"""
    
    def __init__(self):
        self.fusion = MultiSourceFusion()
        self.threat_model = SimpleBayesianInference()
        self.situational_awareness = None
        self.adaptive_learning = None
        self._setup()
        
    def _setup(self):
        # Register data sources
        self.fusion.register_source('ebpf_syscalls', 'ebpf', initial_weight=1.0)
        self.fusion.register_source('pcap_flows', 'pcap', initial_weight=1.0)
        
        # Define threat scenarios
        self.threat_model.define_threat_scenarios()
        
        # Initialize components
        self.situational_awareness = SituationalAwareness(self.threat_model)
        self.adaptive_learning = AdaptiveLearning(self.fusion)
    
    def extract_threat_indicators(self, 
                                  ebpf_events: List[Dict],
                                  pcap_flows: List[Dict]) -> Dict[str, int]:
        """Extract threat indicators from raw events"""
        evidence = {
            'PortScan': 0,
            'NetworkRecon': 0,
            'Phishing': 0,
            'Exploit': 0,
            'PrivEsc': 0,
            'LateralMove': 0,
            'DataExfil': 0,
            'Ransomware': 0,
            'DDoS': 0
        }
        
        # Port scanning detection
        if pcap_flows:
            port_diversity = len(set(f.get('dst_port') for f in pcap_flows if f.get('dst_port')))
            unique_dsts = len(set(f.get('dst_ip') for f in pcap_flows if f.get('dst_ip')))
            
            if port_diversity > 10 and unique_dsts > 5:
                evidence['PortScan'] = 1
            
            if unique_dsts > 20:
                evidence['NetworkRecon'] = 1
            
            # DDoS detection (high packet rate to single target)
            dst_counter = defaultdict(int)
            for f in pcap_flows:
                dst_counter[f.get('dst_ip', '')] += f.get('packet_count', 0)
            if any(count > 1000 for count in dst_counter.values()):
                evidence['DDoS'] = 1
        
        # eBPF-based detection
        if ebpf_events:
            for event in ebpf_events:
                comm = event.get('comm', '')
                syscall = event.get('syscall', '')
                filename = event.get('filename', '')
                
                # Privilege escalation
                if comm in ['sudo', 'su', 'pkexec']:
                    evidence['PrivEsc'] = 1
                
                # Exploitation
                if syscall == 'execve':
                    if any(x in filename for x in ['/tmp/', 'bash -c', 'nc ', 'netcat']):
                        evidence['Exploit'] = 1
                
                # Lateral movement
                if syscall == 'connect':
                    port = event.get('dest_port', 0)
                    if port in [22, 3389] and comm not in ['ssh', 'sshd', 'remmina', 'git']:
                        evidence['LateralMove'] = 1
                
                # Data exfiltration
                if syscall in ['write', 'sendto']:
                    bytes_rw = event.get('bytes_rw', 0)
                    fd = event.get('fd', -1)
                    if bytes_rw > 1000000 and fd > 2:
                        evidence['DataExfil'] = 1
                
                # Ransomware
                if syscall == 'unlinkat':
                    evidence['Ransomware'] = 1
        
        return evidence
    
    def process_realtime_data(self,
                             ebpf_events: List[Dict],
                             pcap_flows: List[Dict]) -> Dict[str, Any]:
        """Process real-time data through MF-CSSA pipeline"""
        
        source_features = {}
        
        # eBPF features
        if ebpf_events:
            ebpf_features = np.array([
                len(ebpf_events),
                len(set(e.get('syscall') for e in ebpf_events)),
                len(set(e.get('pid') for e in ebpf_events)),
                sum(1 for e in ebpf_events if e.get('ret', 0) < 0),
            ])
            source_features['ebpf_syscalls'] = ebpf_features
            
            anomaly_rate = sum(1 for e in ebpf_events if e.get('ret', 0) < 0) / len(ebpf_events)
            self.fusion.sources['ebpf_syscalls'].record_event(anomaly_rate > 0.1)
        
        # PCAP features
        if pcap_flows:
            pcap_features = np.array([
                len(pcap_flows),
                sum(f.get('byte_count', 0) for f in pcap_flows),
                len(set(f.get('dst_ip') for f in pcap_flows if f.get('dst_ip'))),
                len(set(f.get('dst_port') for f in pcap_flows if f.get('dst_port'))),
            ])
            source_features['pcap_flows'] = pcap_features
            self.fusion.sources['pcap_flows'].record_event(False)
        
        # Feature fusion
        fused_features = self.fusion.fuse_features(source_features)
        
        # Extract threat indicators
        evidence = self.extract_threat_indicators(ebpf_events, pcap_flows)
        
        # Bayesian inference
        threat_probabilities = self.threat_model.infer_threats(evidence)
        
        # Calculate situational awareness score
        awareness_score = self.situational_awareness.calculate_score(threat_probabilities)
        
        # Update source weights
        self.fusion.update_source_weights()
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'situational_awareness_score': awareness_score,
            'threat_probabilities': threat_probabilities,
            'evidence': evidence,
            'source_weights': {
                name: source.weight 
                for name, source in self.fusion.sources.items()
            },
            'fused_features': fused_features.tolist() if len(fused_features) > 0 else [],
            'top_threats': sorted(
                threat_probabilities.items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]
        }
        
        return results
    
    def provide_analyst_feedback(self, feedback: int, last_results: Dict[str, Any]):
        """Allow analyst to provide feedback for adaptive learning"""
        score = last_results.get('situational_awareness_score', 0.5)
        source_weights = last_results.get('source_weights', {})
        
        self.adaptive_learning.provide_feedback(
            feedback=feedback,
            current_score=score,
            source_contributions=source_weights
        )


def export_results(results: Dict[str, Any], filename: str):
    """Export MF-CSSA results to JSON"""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)