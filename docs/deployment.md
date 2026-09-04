# NTRO ThreatSense - Deployment Architecture

## Unidirectional Gateway / Data Diode Integration

ThreatSense is strictly designed to operate on the "high-side" (secure enclave) of a Unidirectional Gateway. 

### Architecture Diagram

```mermaid
graph TD
    subgraph "Low Side (Untrusted Network)"
        A[Network Switch / Span Port] --> B[Hardware TAP]
    end

    B -.->|Unidirectional Optical Link| C[Data Diode / Unidirectional Gateway]
    
    subgraph "High Side (Secure SOC Enclave)"
        C --> D[Packet Broker / Kafka Ingestion]
        D --> E[ThreatSense Feature Extractor]
        E --> F[ThreatSense ML Engine (FastAPI)]
        F --> G[Analyst Dashboard (React)]
        F --> H[PostgreSQL Persistence]
    end

    style C fill:#f9f,stroke:#333,stroke-width:2px
    style F fill:#69b3a2,stroke:#333,stroke-width:2px
```

### Flow of Data
1. **Network Tap:** Raw traffic is mirrored from a core switch on the untrusted network.
2. **Data Diode:** The traffic physically passes through a one-way fiber optic link. No TCP acknowledgments or control signals can traverse back.
3. **Ingestion & Feature Extraction:** Our pipeline captures the raw PCAP stream (e.g., using `libpcap`/`scapy`), extracting metadata: `dest_port`, `protocol_encoded`, `packet_size`, `flow_duration`.
4. **ML Inference:** The `MLEngine` (RandomForest + IsolationForest) scores the flows for DDoS, Exfiltration, or Tunneling without relying on bidirectional state tracking.
5. **Dashboard:** The React frontend consumes the live WebSocket stream for SOC analysts.
