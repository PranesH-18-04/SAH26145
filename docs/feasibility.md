# Deployment Feasibility & Scalability

This document outlines the deployment feasibility of the AI Threat Detection System within real-world data-diode (unidirectional gateway) or mirrored-tap infrastructure.

## Unidirectional Infrastructure Integration
The system architecture strictly adheres to a unidirectional data flow requirement:
- **Ingestion Mechanisms:** Network traffic from a mirrored TAP or SPAN port is passed through a hardware data diode (e.g., Fox-IT, Owl Cyber Defense). 
- **Protocol Agnostic Intake:** The backend ingests unidirectional flows extracting our custom one-way features.

## Why Generic IDS Features Fail Here (The Unidirectional Edge)
Most generic IDS models rely on bidirectional features (e.g., full TCP handshake states, backward packet lengths, bidirectional flow duration). In a data-diode deployment, the sensor only sees one side of the conversation. Our model actively exploits this constraint rather than ignoring it by computing novel unidirectional features.

**Validated Signals:**
Our tests on a unidirectional-simulated subset of CICIDS2018 prove that two of our derivations hold strong discriminative power even when traditional artifacts like destination port are removed:
- `ack_completeness_ratio`: Exploits the missing return ACKs in a blind one-way tunnel.
- `retransmission_blindness_index`: Identifies identical payloads sent with robotic timing (lack of adaptive flow control).

**Promising but Unproven Signals:**
- `half_duplex_burst_score` and `handshake_stub_flag` showed weak discriminative power (<2% importance) in the CICIDS2018 synthetic diode environment. These features theoretically identify sustained bursts and unanswered handshakes, but further validation on true physical data-diode captures is needed to prove their efficacy.

*Note on Port Bias:* The model leverages `dest_port` to achieve ~87% accuracy. However, leakage analysis (documented in `model_performance.md`) shows that even when `dest_port` is completely removed, the model sustains ~86% accuracy by shifting weight directly onto our custom `ack_completeness_ratio` and `retransmission_blindness_index`.

## Quantified Throughput Limits
The current Python-based FastAPI architecture uses an asynchronous event loop combined with extremely fast `scikit-learn` model inference (Random Forest and Isolation Forest).
- **Inference Latency:** `model.predict_proba()` on a single vector evaluates in under **2 milliseconds**.
- **System Throughput:** The single-threaded `asyncio` loop comfortably handles approximately **3,000 - 5,000 flows per second** on a standard CPU thread.
- **WebSocket Streaming:** The backend broadcasts evaluated alerts instantaneously to the React client with sub-10ms overhead.

## Production Scalability Path (National Scale)
To support national-scale traffic volumes (NTRO scale) without a complete redesign, we propose the following scaling path:

1. **Kafka Buffering Layer:**
   - Place an Apache Kafka message queue immediately after the data diode.
   - **Why Kafka?** It acts as an unshakeable shock absorber. If traffic spikes abruptly (e.g., during a volumetric DDoS attack), Kafka buffers the flows, preventing dropped packets and decoupling the ingestion rate from the ML inference rate.
   
2. **Horizontal Scaling of ML Workers:**
   - Multiple instances of `ml_engine.py` can act as Kafka consumer groups, processing flows in parallel.
   - The in-memory `anomaly_history` (used for the Confidence-Decay Mechanism) can be trivially migrated to a distributed **Redis cache**. This ensures that all parallel workers share the exact same historical state when decaying the confidence of repeated false positives.

3. **Compiled Inference (Edge Cases):**
   - For ultra-high bandwidth links (40Gbps+), the Random Forest model can be exported to ONNX runtime or compiled via TensorRT for GPU-accelerated inference.
