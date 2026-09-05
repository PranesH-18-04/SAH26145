import pandas as pd
import sys
sys.path.append('backend/scripts')
from preprocess_cicids import get_training_data

df = get_training_data()

print("--- Handshake Stub Flag ---")
print(df['handshake_stub_flag'].value_counts())

print("\n--- Half Duplex Burst Score ---")
print(df['half_duplex_burst_score'].describe())
print(df['half_duplex_burst_score'].value_counts(bins=10))

# Check SYN and ACK counts in raw data
raw_df = pd.read_csv('backend/data/cicids_combined_ddos_exfil_tunnel.csv')
print("\n--- Raw SYN Flag Cnt ---")
print(raw_df['SYN Flag Cnt'].value_counts())
print("\n--- Raw ACK Flag Cnt ---")
print(raw_df['ACK Flag Cnt'].value_counts())

print("\n--- Active vs Idle Mean ---")
print(raw_df[['Active Mean', 'Idle Mean']].describe())
