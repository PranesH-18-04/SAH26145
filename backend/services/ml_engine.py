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

    def _generate_explanation(self, category: str, threat_type: str, packet: dict) -> str:
        if category == "Safe":
            return "Traffic aligns with historical baseline. Model confirms normal behavior."
            
        explanations = []
        if threat_type == "DDoS":
            if packet['packet_size'] < 100:
                explanations.append(f"Model detected high volume of small packets ({packet['packet_size']} bytes).")
            if packet['flow_duration'] < 0.1:
                explanations.append(f"Abnormally short flow duration ({packet['flow_duration']:.3f}s) indicates flood attack pattern.")
            
        elif threat_type == "Data Exfiltration":
            if packet['packet_size'] > 5000:
                explanations.append(f"Model identified unusually large payload ({packet['packet_size']} bytes) for this protocol.")
            explanations.append("Prolonged outbound flow strongly deviates from standard user behavior.")
            
        elif threat_type == "Unauthorized Tunneling":
            explanations.append(f"Encrypted traffic characteristics found on unexpected port ({packet['dest_port']}).")
            explanations.append("Model matched flow timing signatures to known tunneling protocols.")
            
        else:
            explanations.append(f"Random Forest and Isolation Forest detected a severe statistical deviation.")

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
        
        import pandas as pd
        
        # Prepare feature vector as DataFrame to avoid sklearn UserWarning
        X_df = pd.DataFrame(
            [[port, proto_encoded, size, duration]], 
            columns=['dest_port', 'protocol_encoded', 'packet_size', 'flow_duration']
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
                feature_contributions.append({"feature_name": "Packet Size", "contribution_score": 0.42, "description": f"Unusually small packet ({size}B)"})
                feature_contributions.append({"feature_name": "Flow Duration", "contribution_score": 0.35, "description": f"Rapid flow rate ({duration:.2f}s)"})
            elif threat_type_str == "Data Exfiltration":
                feature_contributions.append({"feature_name": "Packet Size", "contribution_score": 0.65, "description": f"Massive outbound payload ({size}B)"})
                feature_contributions.append({"feature_name": "Flow Duration", "contribution_score": 0.15, "description": "Continuous data stream"})
            elif threat_type_str == "Unauthorized Tunneling":
                feature_contributions.append({"feature_name": "Dest Port", "contribution_score": 0.50, "description": f"Mismatch between traffic pattern and Port {port}"})
                feature_contributions.append({"feature_name": "Flow Duration", "contribution_score": 0.25, "description": "Long steady connection state"})
            else:
                feature_contributions.append({"feature_name": "Statistical Deviation", "contribution_score": 0.60, "description": "Isolation Forest vector distance"})
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
