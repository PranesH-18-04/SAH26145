import os
import pandas as pd
import numpy as np

DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
CICIDS_FILE = os.path.join(DATA_DIR, 'cicids_combined_ddos_exfil_tunnel.csv')

def get_training_data() -> pd.DataFrame:
    """
    Loads REAL CICIDS2018 dataset, simulates data-diode by dropping backward columns,
    and derives unidirectional features mathematically.
    """
    print(f"Loading actual dataset from {CICIDS_FILE}...")
    df = pd.read_csv(CICIDS_FILE)
    
    # Clean infinities and NaNs from the original dataset
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    print("Dropping non-feature columns (Timestamp, etc)...")
    non_features = ['Timestamp']
    # Drop them if they exist
    df.drop(columns=[c for c in non_features if c in df.columns], inplace=True)
    
    # The user specifically requested zeroing out / dropping exactly these backward columns:
    bwd_cols = [
        'Tot Bwd Pkts', 'TotLen Bwd Pkts', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 
        'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Bwd IAT Tot', 'Bwd IAT Mean', 
        'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Bwd PSH Flags', 'Bwd URG Flags', 
        'Bwd Header Len', 'Bwd Pkts/s', 'Bwd Seg Size Avg', 'Init Bwd Win Byts', 
        'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 
        'Bwd Blk Rate Avg'
    ]
    
    print("Suppressing backward-direction features to simulate Data-Diode...")
    df.drop(columns=[c for c in bwd_cols if c in df.columns], inplace=True)
    
    print("Deriving real unidirectional custom features from forward/flow columns...")
    
    # 1. ack_completeness_ratio
    # Formula: 1.0 - (ACK Flag Cnt / max(Tot Fwd Pkts, 1)). Clamped between 0 and 1.
    # Logic: In a normal TCP flow, forward packets are acknowledged. Over a diode, 
    # the sender might never see ACKs, so the ACK count relative to forward packets drops.
    # Note: If protocol is UDP (17), this metric is less relevant, but still computable.
    df['ack_completeness_ratio'] = np.clip(
        1.0 - (df['ACK Flag Cnt'] / np.maximum(df['Tot Fwd Pkts'], 1.0)),
        0.0, 1.0
    )
    
    # 2. half_duplex_burst_score
    # Formula: (Active Mean + 1.0) / (Idle Mean + 1.0)
    # Logic: Sustained activity vs rest periods. A high ratio indicates a lack of idle backoff,
    # typical of covert tunneling or blind exfiltration over a diode.
    df['half_duplex_burst_score'] = (df['Active Mean'] + 1.0) / (df['Idle Mean'] + 1.0)
    
    # 3. handshake_stub_flag
    # Formula: 1 if (SYN Flag Cnt > 0 and ACK Flag Cnt == 0) else 0
    # Logic: A SYN sent over a diode will never complete a 3-way handshake.
    df['handshake_stub_flag'] = np.where(
        (df['SYN Flag Cnt'] > 0) & (df['ACK Flag Cnt'] == 0),
        1, 0
    )
    
    # 4. retransmission_blindness_index
    # Formula: (1.0 / (1.0 + (Fwd IAT Std / max(Fwd IAT Mean, 1e-5)))) * (1.0 / (1.0 + Fwd Pkt Len Std))
    # Logic: Blind retransmission (or tunneling) over a diode often happens with identical payload sizes
    # (low Fwd Pkt Len Std) and fixed robotic timing (low Fwd IAT Std relative to Mean) because there is 
    # no adaptive flow control backoff. Low variance = High Index.
    iat_cov = df['Fwd IAT Std'] / np.maximum(df['Fwd IAT Mean'], 1e-5)
    df['retransmission_blindness_index'] = (
        (1.0 / (1.0 + iat_cov)) * 
        (1.0 / (1.0 + df['Fwd Pkt Len Std']))
    )

    # Standardize our base required columns to match inference engine exactly
    # (rename them to match what ml_engine expects or extract them)
    df.rename(columns={
        'Dst Port': 'dest_port',
        'Protocol': 'protocol_encoded',
        'Fwd Pkt Len Mean': 'packet_size',
        'Flow Duration': 'flow_duration'
    }, inplace=True)
    
    # We will use exactly our 4 base features + 4 novel features for training to keep the model lightweight and defensible
    final_features = [
        'dest_port', 'protocol_encoded', 'packet_size', 'flow_duration',
        'ack_completeness_ratio', 'half_duplex_burst_score', 
        'handshake_stub_flag', 'retransmission_blindness_index',
        'Label'
    ]
    df = df[final_features]
    
    return df

if __name__ == "__main__":
    df = get_training_data()
    print(f"\nGenerated DataFrame shape: {df.shape}")
    print("\nFeature describe() to prove real variance:")
    print(df.describe())
