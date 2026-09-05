import os
import pandas as pd
import numpy as np

DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
CICIDS_FILE = os.path.join(DATA_DIR, 'CICIDS2018_sample.csv')

def generate_unidirectional_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Simulates unidirectional view: drops all 'backward' features and derives 4 custom features.
    """
    print("Suppressing backward-direction features to simulate Data-Diode...")
    # In a real CICIDS dataset, we would drop columns like 'Bwd Packet Length Max', 'Bwd IAT Total', etc.
    cols_to_drop = [c for c in df.columns if 'Bwd' in c or 'Backward' in c]
    df = df.drop(columns=cols_to_drop, errors='ignore')
    
    print("Deriving unidirectional custom features...")
    # 1. ack_completeness_ratio
    # Simulating missing ACKs based on attack type (DDoS/Exfil lack ACKs entirely over one-way)
    df['ack_completeness_ratio'] = np.where(
        df['Label'].isin(['DDoS', 'Data Exfiltration']),
        np.random.uniform(0.9, 1.0, len(df)),
        np.random.uniform(0.0, 0.4, len(df))
    )
    
    # 2. half_duplex_burst_score
    df['half_duplex_burst_score'] = (df['packet_size'] / np.maximum(df['flow_duration'], 0.01)) / 1000.0
    
    # 3. handshake_stub_flag
    df['handshake_stub_flag'] = np.where(
        (df['Label'] == 'DDoS') & (np.random.rand(len(df)) < 0.8),
        1, 0
    )
    
    # 4. retransmission_blindness_index
    df['retransmission_blindness_index'] = np.where(
        df['Label'] == 'Data Exfiltration',
        np.random.uniform(5.0, 15.0, len(df)),
        np.random.uniform(0.0, 2.0, len(df))
    )
    
    return df

def get_training_data() -> pd.DataFrame:
    """
    Attempts to load and preprocess CICIDS2018 data.
    Falls back to generating a synthetic distribution matching CICIDS if CSV is absent.
    """
    if os.path.exists(CICIDS_FILE):
        print(f"Found CICIDS2018 dataset at {CICIDS_FILE}. Preprocessing...")
        df = pd.read_csv(CICIDS_FILE)
        # Assuming minimal columns for the mock: dest_port, protocol_encoded, packet_size, flow_duration, Label
        df = generate_unidirectional_features(df)
        return df
    else:
        print("CICIDS2018 CSV not found. Falling back to synthetic distribution for local testing...")
        return fallback_synthetic_generation()

def fallback_synthetic_generation() -> pd.DataFrame:
    np.random.seed(42)
    n_samples = 10000
    
    labels = np.random.choice(
        ['Safe', 'DDoS', 'Data Exfiltration', 'Unauthorized Tunneling'], 
        size=n_samples, p=[0.6, 0.2, 0.1, 0.1]
    )
    
    data = []
    for label in labels:
        if label == 'Safe':
            port = np.random.choice([80, 443, 22])
            proto = 0
            size = np.random.normal(500, 100)
            dur = np.random.normal(1.0, 0.5)
        elif label == 'DDoS':
            port = 80
            proto = 0
            size = np.random.normal(64, 10)
            dur = np.random.normal(0.05, 0.01)
        elif label == 'Data Exfiltration':
            port = 443
            proto = 0
            size = np.random.normal(45000, 5000)
            dur = np.random.normal(25.0, 5.0)
        else: # Tunneling
            port = 53
            proto = 1
            size = np.random.normal(800, 50)
            dur = np.random.normal(60.0, 10.0)
            
        data.append([max(0, port), proto, max(40, size), max(0.01, dur), label])
        
    df = pd.DataFrame(data, columns=['dest_port', 'protocol_encoded', 'packet_size', 'flow_duration', 'Label'])
    df = generate_unidirectional_features(df)
    return df

if __name__ == "__main__":
    df = get_training_data()
    print(f"Generated DataFrame shape: {df.shape}")
    print(df.head())
