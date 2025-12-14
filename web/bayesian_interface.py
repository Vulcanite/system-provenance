#!/usr/bin/env python3
"""
MF-CSSA Bayesian Inference Engine
Calculates P(Threat | Evidence) and Situational Awareness Score
"""

from normalize_data import process_pcap_normalization, process_ebpf_normalization, connect_elasticsearch, load_config

class BayesianThreatNode:
    def __init__(self, name, prior_probability=0.01):
        self.name = name
        self.prior = prior_probability
        self.evidence = [] # List of boolean observations (True if Z-Score > Threshold)
        
    def add_evidence(self, is_anomalous, true_positive_rate=0.9, false_positive_rate=0.08):
        """
        Updates probability using Bayes' Theorem:
        P(A|B) = P(B|A) * P(A) / P(B)
        
        is_anomalous: Did the sensor flag an alarm? (True/False)
        true_positive_rate: P(Evidence | Threat) - Sensor sensitivity
        false_positive_rate: P(Evidence | No Threat) - Sensor error rate (Paper target: 8%)
        """
        # P(E|T)
        p_evidence_given_threat = true_positive_rate if is_anomalous else (1 - true_positive_rate)
        
        # P(E|~T)
        p_evidence_given_safe = false_positive_rate if is_anomalous else (1 - false_positive_rate)
        
        # P(E) = P(E|T)*P(T) + P(E|~T)*P(~T)
        p_evidence = (p_evidence_given_threat * self.prior) + (p_evidence_given_safe * (1 - self.prior))
        
        # Update Posterior P(T|E)
        self.prior = (p_evidence_given_threat * self.prior) / p_evidence

def calculate_situational_awareness(threats):
    """
    Calculates Ψ(t) as sum of weighted threat probabilities.
    Equation from Section 2.4 of the paper.
    """
    # Weights (w_k) defined by analyst priority
    weights = {
        "Data_Exfiltration": 0.6,
        "System_Compromise": 0.4
    }
    
    score = 0.0
    print(f"\n{'THREAT SCENARIO':<20} | {'PROBABILITY P(θ|F)':<20} | {'WEIGHT'}")
    print("-" * 60)
    
    for threat in threats:
        prob = threat.prior
        w = weights.get(threat.name, 0.0)
        score += w * prob
        print(f"{threat.name:<20} | {prob:.4f}{' '*14} | {w}")
        
    return score

def main():
    print("--- MF-CSSA Bayesian Inference Engine ---")
    config = load_config()
    es = connect_elasticsearch(config["es_config"])
    
    # 1. Get Normalized Evidence (F(t))
    # In a real loop, these would update every second
    pcap_scores = process_pcap_normalization(es, config["es_config"])
    ebpf_scores = process_ebpf_normalization(es, config["es_config"])
    
    # 2. Define Threat Models (Bayesian Networks)
    threat_exfil = BayesianThreatNode("Data_Exfiltration")
    threat_compromise = BayesianThreatNode("System_Compromise")
    
    # 3. Apply Evidence to Threats
    # Threshold: Z-Score > 3.0 indicates an anomaly (99.7% confidence in standard distribution)
    
    # -- Network Evidence (influences Exfiltration) --
    pcap_anomaly = any(item['normalized_score'] > 3.0 for item in pcap_scores)
    threat_exfil.add_evidence(pcap_anomaly, true_positive_rate=0.95, false_positive_rate=0.08)
    
    # -- System Evidence (influences Compromise AND Exfiltration) --
    # (High system activity is a precursor to exfiltration)
    ebpf_anomaly = any(item['normalized_score'] > 3.0 for item in ebpf_scores)
    threat_compromise.add_evidence(ebpf_anomaly, true_positive_rate=0.85, false_positive_rate=0.10)
    threat_exfil.add_evidence(ebpf_anomaly, true_positive_rate=0.60, false_positive_rate=0.10) # Weaker link
    
    # 4. Calculate Final Situational Awareness Score
    psi_t = calculate_situational_awareness([threat_exfil, threat_compromise])
    
    print("-" * 60)
    print(f"Situational Awareness Score Ψ(t): {psi_t:.4f}")
    
    # Alert Logic
    if psi_t > 0.5:
        print("\n🚨 CRITICAL ALERT: High Threat Probability Detected!")

if __name__ == "__main__":
    main()