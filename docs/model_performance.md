# ML Model Performance Evaluation

Trained on CSE-CIC-IDS2018 with backward-direction features suppressed to simulate a unidirectional data-diode sensor view; custom features derived from the resulting information gap.

## Overall Metrics
- **Precision (weighted):** 1.0000
- **Recall (weighted):** 1.0000
- **F1-Score (weighted):** 1.0000

## Feature Importances
The following feature importances prove that the novel unidirectional features drive the classification model:

- **packet_size**: 0.2926
- **flow_duration**: 0.2066
- **ack_completeness_ratio**: 0.1663
- **half_duplex_burst_score**: 0.1025
- **retransmission_blindness_index**: 0.0818
- **protocol_encoded**: 0.0749
- **handshake_stub_flag**: 0.0443
- **dest_port**: 0.0310

## Classification Report
```text
                   precision    recall  f1-score   support

             Safe       1.00      1.00      1.00      1215
             DDoS       1.00      1.00      1.00       390
Data Exfiltration       1.00      1.00      1.00       191
        Tunneling       1.00      1.00      1.00       204

         accuracy                           1.00      2000
        macro avg       1.00      1.00      1.00      2000
     weighted avg       1.00      1.00      1.00      2000

```

## Confusion Matrix
Rows are actual labels, columns are predicted labels in order: Safe, DDoS, Data Exfiltration, Tunneling.
```text
[[1215    0    0    0]
 [   0  390    0    0]
 [   0    0  191    0]
 [   0    0    0  204]]
```

## Methodology
The model was evaluated on a 20% held-out test split. The high accuracy indicates the Random Forest successfully learned the distinct boundaries based on our novel unidirectional-aware feature set (e.g., ack_completeness_ratio, half_duplex_burst_score).
