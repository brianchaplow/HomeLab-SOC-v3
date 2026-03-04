# ML Models Directory

This directory contains trained ML models for threat detection.

## Current Production Model

- **Path on QNAP:** /share/Container/soc-automation/models/
- **Active model:** ground_truth_v2_xgb_20260127_171501/

## Model Files (not synced to repo)

| File | Purpose |
|------|---------|
| model.json | XGBoost model (native format) |
| eature_engineer.pkl | Scikit-learn feature engineering pipeline |
| metadata.json | Training metadata, thresholds, feature list |

## Training Location

Models are trained on the Kali system (sear) at:
- /home/butcher/soc-ml/

## Why Models Aren't in Repo

1. **Size:** Models can be large (10MB+)
2. **Sensitive:** Trained on production network patterns
3. **Versioned separately:** Model versions tracked in metadata.json

## Retraining

See docs/ml-detection.md for training procedures.
