import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from services.ml_engine import ml_engine
import time

def run_decay_test():
    print("--- Testing Exponential Frequency Confidence Decay ---")
    print("Formula: C_n = C_0 * exp(-lambda * (n-1))  [where lambda = 0.25]")
    print("Simulating 10 identical Exfiltration packets in rapid succession...\n")
    
    packet_dict = {
        "source_ip": "10.0.5.55",
        "dest_port": 443,
        "protocol": "TCP",
        "packet_size": 45000, 
        "flow_duration": 15.0
    }
    
    for i in range(1, 11):
        result = ml_engine.analyze_packet(packet_dict)
        print(f"Occurrence {result['occurrence_count']:2d} | "
              f"Raw Score: {result['raw_threat_score']:.4f} | "
              f"Decay Factor: {result['decay_factor']:.4f} | "
              f"Final Confidence: {result['threat_score']:.4f} | "
              f"Severity: {result['severity']}")
        time.sleep(0.1)

if __name__ == "__main__":
    run_decay_test()
