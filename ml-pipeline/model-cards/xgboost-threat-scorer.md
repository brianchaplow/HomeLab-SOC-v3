# Model Card: XGBoost Threat Scorer

**Author:** Brian Chaplow
**Version:** v3 (deployed 2026-02-12, patch 2026-02-18)
**Format:** [Model Cards for Model Reporting](https://arxiv.org/abs/1810.03993) (Mitchell et al., 2019)
**Last Updated:** 2026-02-19

---

## 1. Model Details

| Field | Value |
|-------|-------|
| **Name** | XGBoost Threat Scorer |
| **Type** | Binary classifier (gradient-boosted decision trees) |
| **Framework** | XGBoost via scikit-learn API |
| **Training Hardware** | NVIDIA GTX 1650 Ti (4 GB VRAM) on sear (Kali Linux) |
| **Inference Hardware** | NVIDIA RTX A1000 (8 GB VRAM) on brisket (Ubuntu 24.04) |
| **Serving** | FastAPI REST API in Docker container (port 5002) |
| **Model Artifact** | `soc-ml/models/v3_20260213_173915/` |
| **Input** | Wazuh SIEM alert enriched with Zeek network connection data |
| **Output** | Threat probability score in the range [0.0, 1.0] |
| **Features** | 102 engineered features (31 from Zeek conn enrichment); behavioral only, no IP-based features |
| **Training Records** | 1.28 million alerts |
| **License** | MIT |

### Model Architecture

The scorer uses XGBoost's `XGBClassifier` in binary logistic mode. The model was selected after a comparative evaluation of six candidate algorithms (see Section 5). It is deployed inside a lightweight Docker container running a FastAPI application that accepts JSON alert payloads and returns a threat probability.

### Hybrid Scoring

The deployed system combines two complementary scores:

- **Supervised score** -- XGBoost threat probability trained on labeled attack data.
- **Anomaly score** -- IsolationForest trained on normal traffic patterns to detect novel behavior.
- **Combined score** -- Weighted blend: `(1 - w) * supervised_prob + w * anomaly_score`, providing both known-threat detection and zero-day coverage.

A semi-supervised component (`SelfTrainingClassifier`) was also trained during the pipeline to leverage unlabeled data, contributing to the hybrid ensemble's robustness.

In the production SOAR workflow (WF1), the final alert score is computed as `max(abuseipdb_normalized, ml_score)`, integrating external threat intelligence with the ML prediction.

---

## 2. Intended Use

### Primary Use Case

Real-time threat scoring of SIEM alerts within a SOC triage workflow. The model is integrated into Shuffle SOAR Workflow 1 (Threat Enrichment and Auto-Block), where it scores every incoming Wazuh alert before human review.

### Supported Workflows

| Workflow | Integration |
|----------|-------------|
| **WF1** (Threat Enrichment and Auto-Block) | Scores alerts via REST API; combined score drives routing to TheHive case creation and Discord notification |
| **WF6** (Model Drift Detector) | Samples 150 recent alerts daily, scores them, and compares the score distribution against the training baseline |

### Intended Users

- SOC analysts performing alert triage
- Automated SOAR workflows prioritizing alerts for human review

### Out-of-Scope Uses

- **Autonomous blocking without human review.** The model's output is advisory. In the current deployment, auto-blocking via Cloudflare is disabled (honeypot mode, `HONEYPOT_DISABLED` branch condition in WF1).
- **Production enterprise environments.** The model was trained exclusively on home-lab network data and is not validated for enterprise-scale or enterprise-diversity traffic.
- **Standalone deployment.** The model depends on Zeek enrichment and Wazuh alert structure; it cannot score raw network packets or non-Wazuh log formats.

---

## 3. Factors

### Relevant Factors

- **Alert source diversity:** The model was trained on alerts from 10 Wazuh agents spanning 5 VLANs (Management, SOC, Lab, Targets, IoT), including OPNsense syslog, Suricata IDS, Windows Security/Sysmon, and Linux journald events.
- **Attack diversity:** Ground truth labels come from 13 Caldera adversary simulation campaigns (4,874 links executed, 3,868 attack-labeled alerts) plus manual red-team exercises logged via `run_attack.sh` (50+ attack types across 14 scripts).
- **Temporal variation:** Training data covers multiple days of continuous operation, capturing diurnal traffic patterns and varying attack densities.
- **Network topology:** All training data originates from a segmented home-lab network with RFC 1918 addressing. The model has no exposure to cloud-native, SaaS, or large enterprise network patterns.

### Evaluation Factors

The model is evaluated across the full alert population without disaggregation by agent, VLAN, or alert type. Future work could stratify evaluation by these factors to identify per-segment performance variation.

---

## 4. Training Data

### Source

Production Wazuh alerts from HomeLab SOC v3, indexed in OpenSearch (`wazuh-alerts-4.x-*` on brisket:9200), enriched with Zeek network connection metadata from the `zeek-conn` index.

### Ground Truth Labeling

| Method | Description |
|--------|-------------|
| **Caldera campaigns** | 13 adversary simulation campaigns using 4 Sandcat agents on VLAN 30/40 targets. Caldera's operation API provides technique-level execution timestamps, correlated to Wazuh alerts by time window and target IP. |
| **Manual attack logging** | `run_attack.sh` wrapper logs every manual red-team exercise to `attack_log.csv` with timestamp, attack type, source IP, target IP, and MITRE ATT&CK technique. |
| **Negative class** | All alerts not correlated to a known attack event within the temporal correlation window are labeled as benign. |

### Data Pipeline

```
OpenSearch (wazuh-alerts-4.x-*)
  --> SOCOpenSearchClient (field mapping: data.* --> flat v2 names)
  --> ZeekEnricher (5-tuple + timestamp join with zeek-conn index)
  --> DataExtractor (enriched alerts + Zeek baseline)
  --> GroundTruthExtractor (Caldera API + attack_log.csv labels)
  --> FeatureEngineer (102 behavioral features)
  --> ModelTrainer (temporal split --> train/test)
```

### Splitting Strategy

**Temporal train/test split** -- the dataset is split by timestamp, not randomly. All training samples precede all test samples in time. This prevents data leakage from future information and provides a realistic evaluation of how the model performs on genuinely unseen data.

### Dataset Statistics

| Metric | Value |
|--------|-------|
| Total records | 1.28 million |
| Engineered features | 102 (including 31 Zeek conn features) |
| Attack-labeled alerts | 3,868 (from Caldera campaigns) |
| Class ratio | Highly imbalanced (attacks are rare events) |

---

## 5. Feature Engineering

All features are behavioral -- the pipeline deliberately excludes IP addresses and other network-specific identifiers to avoid encoding topology biases that would not generalize to other environments.

### Feature Categories

| Category | Count | Description |
|----------|-------|-------------|
| **Alert metadata** | ~15 | Rule level (severity), rule group, MITRE ATT&CK technique/tactic counts, decoder name |
| **Temporal** | ~10 | Hour of day, day of week, time since last alert, alert frequency (rolling windows), burst detection |
| **Agent behavioral** | ~15 | Alert rate per agent, deviation from per-agent baseline, agent alert diversity |
| **Zeek network connection** | 31 | Connection state (`conn_state`), history flags, service (DPI), duration, originated/responded bytes, byte overhead ratio, protocol distribution |
| **Anomaly meta-features** | ~5 | IsolationForest anomaly scores computed on the feature space, used as additional input features |
| **Interaction and derived** | ~26 | Cross-category combinations, rolling statistics, ratio features |

**Total:** 102 features

### Key Design Decisions

- **No IP-based features.** Source and destination IPs are used only for Zeek enrichment joins, never as model inputs. This prevents the model from memorizing lab-specific addressing.
- **No severity/signature_id features.** These fields directly encode the label (high severity correlates with attacks by definition) and were excluded to prevent label leakage.
- **Zeek conn.log enrichment.** Each Wazuh alert is joined to the nearest Zeek connection record by 5-tuple (source IP, destination IP, source port, destination port, protocol) and timestamp proximity. This adds 31 features describing the underlying network session (duration, bytes, connection state, service identification via DPI). The enrichment hit rate is approximately 20%.
- **`_safe_col()` robustness fix (2026-02-18).** The `FeatureEngineer` class had 14 instances of `df.get('col', 0)` that returned a scalar `0` when a column was absent, causing downstream `pd.to_numeric().fillna()` to fail. A `_safe_col()` static method was added to always return a `pd.Series`, deployed to both the training environment and the production container.

---

## 6. Evaluation Results

### Candidate Models

Six supervised classifiers were trained and compared on the same temporal train/test split. KNN was excluded due to computational infeasibility at 1.28 million samples.

| Model | PR-AUC | Notes |
|-------|--------|-------|
| **XGBoost** | **0.9998** | Selected for deployment |
| LightGBM | -- | Competitive; lighter memory footprint |
| RandomForest | -- | Baseline ensemble |
| Logistic Regression | -- | Linear baseline |
| IsolationForest | -- | Unsupervised anomaly detection (no labels required) |
| SelfTrainingClassifier | -- | Semi-supervised; leverages unlabeled data |

> PR-AUC values for non-deployed models are available in training logs but omitted here to focus on the deployed model.

### Primary Metric: PR-AUC

**Precision-Recall Area Under Curve = 0.9998**

PR-AUC was chosen over ROC-AUC because the dataset is heavily class-imbalanced (attacks are rare events in production SIEM data). ROC-AUC can be misleadingly high when the negative class dominates, because it credits the model for correctly classifying the abundant negatives. PR-AUC focuses exclusively on the model's ability to identify the rare positive (attack) class, making it a more informative metric for threat detection.

### Hybrid Scoring Performance

The production system uses a hybrid scoring architecture that combines the XGBoost supervised score with an IsolationForest anomaly score:

- **Known threats:** The XGBoost component achieves near-perfect detection of attack patterns present in the training distribution.
- **Novel threats:** The IsolationForest component flags statistically anomalous behavior regardless of whether it matches known attack signatures, providing coverage for zero-day and previously unseen attack techniques.

### Operational Metrics

| Metric | Value |
|--------|-------|
| Alerts scored by ML (cumulative) | 1.6M+ |
| High-confidence threats flagged | 36,900+ |
| IPs auto-blocked (via downstream Cloudflare action) | 1,981+ |
| Target PR-AUC (design goal) | >= 0.70 |
| Achieved PR-AUC | 0.9998 |

---

## 7. Monitoring and Drift Detection

### WF6: Model Drift Detector

A dedicated Shuffle SOAR workflow (WF6) runs daily via system cron to monitor for distribution shift between training-time and production-time feature distributions.

| Parameter | Value |
|-----------|-------|
| **Schedule** | Daily at 09:00 EST (`0 14 * * *` UTC) |
| **Sample size** | 150 recent alerts per run |
| **Method** | Score sampled alerts via ml-scorer API, compare score distribution statistics against training baseline |
| **Storage** | Results indexed to ELK `ml-drift` index (daily metrics + baseline documents) |
| **Alerting** | Discord notification when drift exceeds configured thresholds |
| **LLM augmentation** | Ollama (qwen3:8b) generates a plain-language drift interpretation for each run |

### Retraining Triggers

The model should be retrained when:

1. WF6 detects sustained distribution drift over multiple consecutive days.
2. Network topology changes significantly (new VLANs, new host types, new agent deployments).
3. New attack campaigns provide additional ground-truth labels.
4. The Zeek enrichment hit rate changes substantially (currently approximately 20%).

---

## 8. Ethical Considerations

### Data Privacy

- **No PII in features.** The model operates on behavioral metadata (alert patterns, connection statistics, temporal distributions). No usernames, email addresses, file contents, or other personally identifiable information are used as features.
- **IP addresses excluded from model input.** Source and destination IPs are used only for Zeek enrichment joins and ground-truth correlation, never as model features.
- **Lab-only training data.** All training data originates from a private home-lab network. No production enterprise data, customer data, or third-party data was used.

### Bias Mitigation

- **Behavioral features avoid network-specific biases.** By excluding IP addresses and network identifiers, the model does not learn to associate specific hosts or subnets with threat status. This reduces the risk of false positives driven by topology artifacts rather than genuine threat behavior.
- **Temporal split prevents temporal leakage.** The strict temporal train/test split ensures the model is evaluated on genuinely future data, preventing inflated metrics from data leakage.

### Human Oversight

- **Advisory, not autonomous.** The model's threat score is one input among several in the analyst's triage decision. The SOAR workflow routes high-scoring alerts to TheHive for human case management and sends Discord notifications for analyst attention.
- **Auto-blocking is disabled.** The Cloudflare auto-block branch in WF1 is currently disabled (`HONEYPOT_DISABLED`), ensuring no automated enforcement actions are taken based on model output alone.

### Transparency

- **LLM explainability.** When the ML score exceeds 0.7, Shuffle WF1 uses Ollama (qwen3:8b) to generate a plain-language explanation of the top contributing features. This explanation is included in the TheHive case description and the Discord alert, making the model's reasoning accessible to analysts.
- **Open source.** The training pipeline, feature engineering code, and model artifacts are available in the [soc-ml repository](https://github.com/brianchaplow/soc-ml).

---

## 9. Caveats and Recommendations

### Known Limitations

1. **Lab-environment performance.** The PR-AUC of 0.9998 reflects performance on home-lab network traffic with Caldera-generated attack campaigns. Production enterprise environments with greater traffic diversity, more varied attack patterns, and different alert distributions should expect lower performance. The metric should be interpreted as an upper bound.

2. **Class imbalance.** Attacks constitute a small fraction of the total alert volume. While PR-AUC accounts for this imbalance in evaluation, the model's calibration (the degree to which predicted probabilities match true attack rates) has not been independently validated.

3. **Zeek enrichment dependency.** Approximately 20% of alerts successfully join to Zeek connection records. The remaining 80% receive zero-valued Zeek features. Model performance may differ between Zeek-enriched and non-enriched alerts.

4. **Ground truth coverage.** Labels come from Caldera adversary simulation and manual red-team exercises. Attack types not represented in these exercises (insider threats, supply chain attacks, novel zero-days) are not present in the positive class. The IsolationForest anomaly component partially mitigates this gap.

5. **Single-environment training.** The model has only been trained on data from one network topology. Transfer to networks with different VLAN structures, agent configurations, or alert volume profiles may require retraining.

### Recommendations

- **Retrain periodically.** Use WF6 drift detection as the trigger. At minimum, retrain quarterly or after significant infrastructure changes.
- **Expand ground truth.** Additional Caldera campaigns covering new MITRE ATT&CK techniques will improve positive class coverage.
- **Stratify evaluation.** Future evaluation should disaggregate performance by agent type, VLAN, alert source (Suricata vs. Sysmon vs. journald), and Zeek enrichment status to identify weak spots.
- **Calibrate probabilities.** Apply Platt scaling or isotonic regression to improve probability calibration if the score is used for threshold-based decisions beyond ranking.
- **Monitor Zeek enrichment rate.** Changes in the Zeek join hit rate (currently approximately 20%) may indicate pipeline issues or topology changes that affect model performance.

---

## 10. Quantitative Analyses

### Training Configuration

| Parameter | Value |
|-----------|-------|
| Training set | Temporal prefix of 1.28M records |
| Test set | Temporal suffix of 1.28M records |
| Feature count | 102 |
| Zeek connection features | 31 |
| GPU | GTX 1650 Ti (training), RTX A1000 (inference) |
| Frameworks | XGBoost, LightGBM, scikit-learn |
| Artifact directory | `soc-ml/models/v3_20260213_173915/` |

### Production Deployment

| Component | Detail |
|-----------|--------|
| Container | `ml-scorer` (Docker on brisket, port 5002) |
| API framework | FastAPI |
| GPU sharing | RTX A1000 shared with Ollama; `OLLAMA_KEEP_ALIVE=5m` releases VRAM when idle; XGBoost falls back to CPU (Ultra 9 285) if GPU is occupied |
| SOAR integration | Shuffle WF1 calls `POST /score` with alert JSON |
| Drift monitoring | Shuffle WF6 calls `/score` with sampled alerts daily |

---

## References

- Mitchell, M., Wu, S., Zaldivar, A., et al. (2019). *Model Cards for Model Reporting.* Proceedings of the Conference on Fairness, Accountability, and Transparency. [arXiv:1810.03993](https://arxiv.org/abs/1810.03993)
- Chen, T., & Guestrin, C. (2016). *XGBoost: A Scalable Tree Boosting System.* Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining.
- Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). *Isolation Forest.* Proceedings of the 2008 Eighth IEEE International Conference on Data Mining.
- Saito, T., & Rehmsmeier, M. (2015). *The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets.* PLOS ONE, 10(3).
