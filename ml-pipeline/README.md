# ML Threat Detection Pipeline

Machine learning pipeline for behavioral threat detection in SOC alert data. The XGBoost binary classifier achieves **PR-AUC 0.9998** on temporal test splits and is deployed as a real-time scoring API on brisket.

> Full source code, training notebooks, and attack framework are in the separate [soc-ml repository](https://github.com/brianchaplow/soc-ml).

## Architecture

```
OpenSearch (wazuh-alerts-4.x-* + zeek-conn)
  --> SOCOpenSearchClient        # Query and field mapping (data.* --> flat names)
  --> ZeekEnricher               # 5-tuple + timestamp join of Zeek conn.log onto alerts
  --> DataExtractor              # Enriched alerts + Zeek baseline export
  --> GroundTruthExtractor       # Labels from Caldera API or attack_log.csv
  --> FeatureEngineer            # 31 behavioral features (no IP-based features)
  --> ModelTrainer               # XGBoost, LightGBM, RandomForest, LogReg
  --> HybridScorer               # IsolationForest anomaly + XGBoost supervised
  --> ml-scorer container        # FastAPI on brisket:5002
  --> Shuffle WF1                # Combined scoring --> TheHive / Discord
```

## Feature Engineering

The pipeline computes **31 behavioral features** from Wazuh alerts and Zeek conn.log data. IP addresses and signature IDs are deliberately excluded to avoid encoding network-specific biases or leaking labels.

Feature categories include:

- **Temporal** -- alert frequency, inter-arrival time, burst detection
- **Zeek connection** -- conn_state distribution, history flags, service DPI, duration statistics, byte/packet ratios, connection overhead metrics
- **Alert context** -- rule severity patterns, agent diversity, rule group distributions

## Training Methodology

- **Temporal train/test split** -- data is split by time, never randomly, to prevent future information from leaking into training
- **Ground truth** -- labeled via Caldera campaign telemetry and the `run_attack.sh` logging wrapper
- **Primary metric** -- PR-AUC (Precision-Recall Area Under Curve), chosen because the dataset is heavily imbalanced toward benign traffic
- **Hybrid scoring** -- `(1-w) * xgboost_prob + w * isolation_forest_score` provides zero-day coverage by blending supervised classification with unsupervised anomaly detection

## Deployment

The trained XGBoost model runs inside a Docker container on **brisket** (port 5002) as a FastAPI service. It accepts alert feature vectors and returns threat probability scores.

Integration points:

- **Shuffle WF1** sends alerts to the scorer in real time; the combined score (ML + AbuseIPDB) determines the response action
- **Shuffle WF6** runs daily model drift detection by sampling 150 recent alerts, scoring them, and comparing the score distribution against a stored baseline in ELK

## Model Card

A detailed model card documenting training data, evaluation metrics, intended use, limitations, and ethical considerations is located at [`model-cards/xgboost-threat-scorer.md`](model-cards/xgboost-threat-scorer.md).

## Directory Structure

```
ml-pipeline/
  model-cards/
    xgboost-threat-scorer.md    # Model card with evaluation metrics and limitations
```

## Related Resources

- [soc-ml repository](https://github.com/brianchaplow/soc-ml) -- full training source code, notebooks, and attack framework
- [Shuffle WF1](../shuffle/workflows/wf1-threat-enrichment.json) -- real-time scoring integration
- [Shuffle WF6](../shuffle/workflows/wf6-model-drift.json) -- drift monitoring workflow
