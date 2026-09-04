# Confidence Decay Mechanism

## Overview
A critical challenge in Security Operations Centers (SOCs) is **alert fatigue**. When a benign but statistically anomalous traffic pattern occurs (e.g., a misconfigured internal backup script triggering an ML anomaly detector), standard systems will bombard the analyst with hundreds of identical "High Severity" alerts until the script is shut down.

To solve this, ThreatSense implements a rigorous, mathematically-grounded **Exponential Frequency-based Confidence Decay**. 

Instead of treating every packet in isolation, ThreatSense keys anomalies by a unique signature (`source_ip : dest_port : threat_type`) and applies a Bayesian-inspired exponential penalty to the model's confidence for every repeated occurrence within a rolling time window.

## The Mathematical Model

We chose an explicit **exponential frequency decay** because it provides a smooth, predictable reduction in confidence that rapidly suppresses alert storms without instantly silencing legitimate bursts.

The formula applied is:

$$ C_n = C_0 \times e^{-\lambda \cdot \max(0, n-1)} $$

Where:
* $C_n$ = The final decayed confidence score for the current packet.
* $C_0$ = The raw, base prediction probability from the ML Model (e.g., Random Forest).
* $\lambda$ = The decay rate coefficient (we use `0.25`).
* $n$ = The occurrence count of this exact anomaly signature within the rolling 10-minute state window.

### Why not a moving average or fixed threshold?
A moving average dilutes genuine threats if mixed with normal traffic. A fixed threshold is a cliff (e.g., "ignore after 5 times"), which is easily exploitable by attackers who hide within the ignored window. 
Exponential decay smoothly reduces the priority of a repeated event. If the event is truly malicious, the SOC analyst will still see the initial high-severity alerts. If it's a false positive, it gracefully degrades to a low-severity background log.

## Numerical Walkthrough

Assume a backup script triggers the anomaly detector with a base confidence ($C_0$) of **0.95 (95%)**.

**Occurrence 1 ($n=1$):**
* Penalty: $e^{-0.25 \times 0} = e^0 = 1.0$
* Final Score: $0.95 \times 1.0 = 0.95$ (95% - CRITICAL)

**Occurrence 2 ($n=2$):**
* Penalty: $e^{-0.25 \times 1} \approx 0.7788$
* Final Score: $0.95 \times 0.7788 \approx 0.739$ (74% - MEDIUM)

**Occurrence 3 ($n=3$):**
* Penalty: $e^{-0.25 \times 2} = e^{-0.5} \approx 0.6065$
* Final Score: $0.95 \times 0.6065 \approx 0.576$ (58% - LOW)

**Occurrence 4 ($n=4$):**
* Penalty: $e^{-0.25 \times 3} = e^{-0.75} \approx 0.4724$
* Final Score: $0.95 \times 0.4724 \approx 0.448$ (45% - LOG ONLY)

By the 4th occurrence, the identical anomaly has been suppressed below the analyst's active attention threshold, entirely autonomously.

## Verification
You can mathematically verify this logic by running the included backend test script:
```bash
cd backend
python scripts/test_decay.py
```
