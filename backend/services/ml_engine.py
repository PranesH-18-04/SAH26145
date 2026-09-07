import os
import time
import joblib
import numpy as np
from typing import Dict, Tuple

class MLEngine:
    def __init__(self):
        # Load trained models
        models_dir = os.path.join(os.path.dirname(__file__), '../models/trained')
        rf_path = os.path.join(models_dir, 'rf_classifier.pkl')
        iso_path = os.path.join(models_dir, 'isolation_forest.pkl')
        
        try:
            self.rf_clf = joblib.load(rf_path)
            self.iso_forest = joblib.load(iso_path)
            print("Successfully loaded ML models.")
        except FileNotFoundError:
            print("WARNING: Models not found. Run train_model.py first.")
            self.rf_clf = None
            self.iso_forest = None
            
        # Label mapping matching train_model.py
        self.label_map = {
            0: "Safe",
            1: "DDoS",
            2: "Data Exfiltration",
            3: "Unauthorized Tunneling"
        }

        # Confidence-Decay Mechanism State
        self.anomaly_history: Dict[str, list] = {}
        self.decay_lambda = 0.25 # Exponential decay rate

    def _get_signature(self, packet_dict: dict, threat_type: str) -> str:
        source_ip = packet_dict.get('source_ip', 'unknown')
        dest_port = packet_dict.get('dest_port', 0)
        return f"{source_ip}:{dest_port}:{threat_type}"

    def _update_and_get_occurrence(self, signature: str, timestamp: float) -> int:
        if signature not in self.anomaly_history:
            self.anomaly_history[signature] = []
        
        # Keep anomalies from the last 10 minutes (600 seconds)
        current_time = time.time()
        self.anomaly_history[signature] = [
            t for t in self.anomaly_history[signature] 
            if current_time - t < 600
        ]
        
        self.anomaly_history[signature].append(timestamp)
        return len(self.anomaly_history[signature])

    def _calculate_confidence_decay(self, base_confidence: float, occurrence_count: int) -> float:
        """
        Calculates exponential frequency decay: C_n = C_0 * exp(-lambda * max(0, n-1))
        """
        if occurrence_count <= 1:
            return base_confidence
            
        import math
        # Decay applies to repeated occurrences (n-1)
        decay_factor = math.exp(-self.decay_lambda * (occurrence_count - 1))
        return base_confidence * decay_factor
    # Explanation generation is deterministic and rule-based (feature-threshold driven), not an LLM call.
    # This is intentional: it's auditable, has zero external API dependency/cost, and every explanation
    # traces directly to the triggering feature — important for a security tool where analysts need to trust *why* something was flagged.
    def _generate_explanation(self, category: str, threat_type: str, packet: dict) -> str:
        if category == "Safe":
            return "Traffic aligns with historical baseline. Model confirms normal behavior."
            
        explanations = []
        if threat_type == "DDoS":
            if packet.get('handshake_stub_flag', 0) == 1:
                explanations.append("Detected SYN-only storm. Over a data-diode, SYN packets are never acknowledged, but this volume exceeds normal unidirectional telemetry.")
            if packet['packet_size'] < 100:
                explanations.append(f"Model detected high volume of small packets ({packet['packet_size']} bytes) without protocol backoff.")
            
        elif threat_type == "Data Exfiltration":
            if packet.get('ack_completeness_ratio', 0) > 0.8:
                explanations.append("Sustained one-directional burst with no protocol backoff (Ack Completeness ~100% absent). Normal bidirectional flows would throttle after packet loss, but this sender shows no adaptive behavior, consistent with covert exfiltration over a diode.")
            if packet.get('retransmission_blindness_index', 0) > 5.0:
                explanations.append("High Retransmission Blindness Index: Sender is transmitting identical payload signatures rapidly without waiting for ACKs, a strong indicator of blind exfiltration.")
            
        elif threat_type == "Unauthorized Tunneling":
            if packet.get('half_duplex_burst_score', 0) > 10.0:
                explanations.append(f"Unnaturally sustained one-directional throughput (Half-Duplex Burst Score: {packet.get('half_duplex_burst_score'):.1f}) matching known tunneling profiles.")
            explanations.append(f"Encrypted traffic characteristics found on unexpected port ({packet.get('dest_port')}).")
            
        else:
            explanations.append(f"Random Forest and Isolation Forest detected a severe statistical deviation across unidirectional features.")

        return " ".join(explanations)

    def analyze_packet(self, packet_dict: dict) -> dict:
        """
        Runs ML Inference using the real trained RandomForest and IsolationForest.
        Returns a dict matching the new schema fields for ThreatAnalysis.
        """
        # Feature extraction
        port = packet_dict.get('dest_port', 80)
        protocol_str = packet_dict.get('protocol', 'TCP')
        # Encode protocol
        proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
        proto_encoded = proto_map.get(protocol_str, 0)
        
        size = packet_dict.get('packet_size', 500)
        duration = packet_dict.get('flow_duration', 1.0)
        ack_ratio = packet_dict.get('ack_completeness_ratio', 0.0)
        burst_score = packet_dict.get('half_duplex_burst_score', 0.0)
        handshake_stub = packet_dict.get('handshake_stub_flag', 0)
        retrans_index = packet_dict.get('retransmission_blindness_index', 0.0)
        
        import pandas as pd
        
        # Prepare feature vector as DataFrame to avoid sklearn UserWarning
        X_df = pd.DataFrame(
            [[port, proto_encoded, size, duration, ack_ratio, burst_score, handshake_stub, retrans_index]], 
            columns=[
                'dest_port', 'protocol_encoded', 'packet_size', 'flow_duration',
                'ack_completeness_ratio', 'half_duplex_burst_score',
                'handshake_stub_flag', 'retransmission_blindness_index'
            ]
        )
        
        # Base safe defaults in case models aren't loaded
        if self.rf_clf is None:
            return {
                "threat_score": 0.1,
                "raw_threat_score": 0.1,
                "decay_factor": 1.0,
                "occurrence_count": 1,
                "signature": "unknown",
                "severity": "LOG_ONLY",
                "category": "Safe",
                "threat_type": None,
                "explanation": "Model not loaded. Defaulting to safe.",
                "feature_contributions": []
            }
            
        # Predict Probabilities
        probas = self.rf_clf.predict_proba(X_df)[0]
        predicted_class_idx = np.argmax(probas)
        base_confidence = float(probas[predicted_class_idx])
        
        # Unsupervised Anomaly Score (-1 for anomaly, 1 for normal)
        iso_pred = self.iso_forest.predict(X_df)[0]
        
        threat_type_str = self.label_map[predicted_class_idx]
        
        if threat_type_str == "Safe":
            if iso_pred == -1:
                base_threat_score = 0.55
                threat_type_str = "Unknown Anomaly"
            else:
                base_threat_score = 1.0 - base_confidence
                threat_type_str = None
        else:
            base_threat_score = base_confidence
        
        # Determine Signature and Update History (Only for non-safe bases)
        signature = self._get_signature(packet_dict, str(threat_type_str))
        occurrence_count = 1
        final_confidence = base_threat_score
        
        if threat_type_str is not None:
            occurrence_count = self._update_and_get_occurrence(signature, time.time())
            final_confidence = self._calculate_confidence_decay(base_threat_score, occurrence_count)
        
        decay_factor = final_confidence / base_threat_score if base_threat_score > 0 else 1.0
        
        # Strict Threshold Enforcement
        if final_confidence < 0.50:
            severity = "LOG_ONLY"
            category = "Safe"
            threat_type_str = None
        elif final_confidence < 0.75:
            severity = "LOW"
            category = "Suspicious"
        elif final_confidence < 0.90:
            severity = "MEDIUM"
            category = "Suspicious"
        else:
            severity = "CRITICAL"
            category = "Malicious"
            
        # Generate Explanation
        explanation = self._generate_explanation(category, threat_type_str, packet_dict)
        
        if final_confidence < base_threat_score:
            explanation += f"\n\n[Confidence Decay Triggered] Alert suppressed: repeated anomalies detected for signature {signature}. Confidence decayed from {base_threat_score*100:.1f}% to {final_confidence*100:.1f}%."

        # Calculate Feature Contributions (SHAP proxy)
        feature_contributions = []
        if category != "Safe":
            if threat_type_str == "DDoS":
                feature_contributions.append({"feature_name": "Handshake Stub Flag", "contribution_score": 0.45, "description": "Unanswered SYN packet burst"})
                feature_contributions.append({"feature_name": "Packet Size", "contribution_score": 0.35, "description": f"Unusually small packet ({size}B)"})
            elif threat_type_str == "Data Exfiltration":
                feature_contributions.append({"feature_name": "Ack Completeness Ratio", "contribution_score": 0.55, "description": f"Missing expected ACKs (Ratio: {ack_ratio:.2f})"})
                feature_contributions.append({"feature_name": "Retransmission Blindness", "contribution_score": 0.25, "description": f"No adaptive backoff detected (Idx: {retrans_index:.1f})"})
            elif threat_type_str == "Unauthorized Tunneling":
                feature_contributions.append({"feature_name": "Half-Duplex Burst Score", "contribution_score": 0.50, "description": f"Sustained unidirectional throughput (Score: {burst_score:.1f})"})
                feature_contributions.append({"feature_name": "Dest Port", "contribution_score": 0.25, "description": f"Mismatch between traffic pattern and Port {port}"})
            else:
                feature_contributions.append({"feature_name": "Statistical Deviation", "contribution_score": 0.60, "description": "Isolation Forest vector distance across unidirectional features"})
                feature_contributions.append({"feature_name": "Protocol Pattern", "contribution_score": 0.20, "description": f"Unusual {protocol_str} flow"})

        return {
            "threat_score": final_confidence,
            "raw_threat_score": base_threat_score,
            "decay_factor": decay_factor,
            "occurrence_count": occurrence_count,
            "signature": signature,
            "severity": severity,
            "category": category,
            "threat_type": threat_type_str,
            "explanation": explanation,
            "feature_contributions": feature_contributions
        }

ml_engine = MLEngine()
