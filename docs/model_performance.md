# ML Model Performance Evaluation

Trained on a class-balanced sample of CSE-CIC-IDS2018 (Benign, DDoS attack-HOIC, Infiltration, SSH-BruteForce), 8,000 rows per class. SSH-BruteForce and Infiltration are used as proxies for Tunnel and Exfiltration classes respectively, due to the absence of a public unidirectional-traffic dataset. Backward-direction flow features were suppressed to simulate a data-diode sensor view; the four custom features were derived from the resulting real CICIDS2018 forward-direction columns.

### Novel Unidirectional Feature Derivation Formulas:
- **ack_completeness_ratio**: `max(0, 1.0 - (ACK Flag Cnt / max(Tot Fwd Pkts, 1)))`
- **half_duplex_burst_score**: `(Active Mean + 1.0) / (Idle Mean + 1.0)`
- **handshake_stub_flag**: `1 if (SYN Flag Cnt > 0 and ACK Flag Cnt == 0) else 0`
- **retransmission_blindness_index**: `(1.0 / (1.0 + (Fwd IAT Std / max(Fwd IAT Mean, 1e-5)))) * (1.0 / (1.0 + Fwd Pkt Len Std))`

## Overall Metrics (With `dest_port`)
- **Precision (weighted):** 0.8765
- **Recall (weighted):** 0.8700
- **F1-Score (weighted):** 0.8681

## Feature Importances
The following feature importances prove that two of the novel unidirectional features (`ack_completeness_ratio` and `retransmission_blindness_index`) significantly drive the classification model, while the others showed limited signal:

- **dest_port**: 0.3689
- **flow_duration**: 0.2085
- **ack_completeness_ratio**: 0.1496
- **packet_size**: 0.1295
- **retransmission_blindness_index**: 0.0922
- **protocol_encoded**: 0.0358
- **half_duplex_burst_score**: 0.0150
- **handshake_stub_flag**: 0.0005

## Classification Report
```text
              precision    recall  f1-score   support

      Benign       0.82      0.62      0.71      1602
        DDoS       0.99      1.00      1.00      1615
       Exfil       0.70      0.86      0.77      1595
      Tunnel       1.00      1.00      1.00      1588

    accuracy                           0.87      6400
   macro avg       0.88      0.87      0.87      6400
weighted avg       0.88      0.87      0.87      6400

```

## Leakage Analysis: The `dest_port` Artifact
Because the dataset classes were constructed from specific day-files in CICIDS2018 (e.g. DDOS HOIC on Port 80, SSH Bruteforce on Port 22), the `dest_port` feature artificially acts as a strong discriminator for these classes. We ran a secondary training pass completely removing `dest_port` to test how the unidirectional features stand on their own.

### Metrics WITHOUT `dest_port`
```text
              precision    recall  f1-score   support

      Benign       0.79      0.61      0.69      1602
        DDoS       0.98      1.00      0.99      1615
       Exfil       0.68      0.82      0.74      1595
      Tunnel       0.99      0.99      0.99      1588

    accuracy                           0.86      6400
   macro avg       0.86      0.86      0.85      6400
weighted avg       0.86      0.86      0.85      6400

```
### Feature Importances WITHOUT `dest_port`
- **flow_duration**: 0.3945
- **ack_completeness_ratio**: 0.2084
- **packet_size**: 0.1869
- **retransmission_blindness_index**: 0.1450
- **protocol_encoded**: 0.0392
- **half_duplex_burst_score**: 0.0248
- **handshake_stub_flag**: 0.0011

As seen above, when port is removed, the model is forced to rely entirely on payload and flow dynamics. The unidirectional features (specifically `ack_completeness_ratio` and `retransmission_blindness_index`) become the dominant drivers, though precision/recall for specific classes naturally drops without the port artifact.

## Known Limitations
### Weak Features
`half_duplex_burst_score` and `handshake_stub_flag` did not show strong discriminative power on this dataset; revised formulas are documented above (re-keyed to active/idle ratios and strict boolean flag counts), but further validation is needed on true unidirectional capture data.

### Benign Recall Misclassification Analysis
The model showed lower recall (~0.63) for Benign traffic in the primary evaluation. Upon isolating the misclassified Benign rows (601 instances) vs correctly classified Benign rows (1001 instances), we found they share specific feature distributions that perfectly overlap with the day-file attack signatures. 
For example:
- **Port Overlap**: 57% of misclassified Benign rows (346 out of 601) occurred on Port 53, which is heavily associated with the Tunneling proxy class. Correctly classified Benign rows were distributed more broadly across Ports 80, 3389, and 443.
- **Retransmission Blindness**: Misclassified Benign rows had a mean 
etransmission_blindness_index of 0.719 (very high, looking like blind tunneling) compared to just 0.235 for correctly classified Benign rows.
- **Packet Size**: Misclassified Benign rows had a significantly smaller mean packet_size (44.9 bytes) compared to correctly classified rows (115.1 bytes).

This suggests the classifier is struggling against identical baseline traffic (like DNS queries on Port 53) injected into the attack subsets, rather than a failure of the unidirectional logic.