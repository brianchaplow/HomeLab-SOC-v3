# Adversary Simulation

MITRE Caldera v5.3.0 adversary emulation platform and ground-truth attack logging for purple team validation and ML training data generation.

## Caldera Deployment

Caldera runs on **smoker** (10.10.30.21) and manages four Sandcat agents deployed to targets on the isolated VLAN 40 network and the AD lab on VLAN 30.

### Enrolled Agents

| Agent | Host | VLAN | OS |
|-------|------|------|----|
| Sandcat | DC01 | 30 | Windows Server 2022 |
| Sandcat | WS01 | 30 | Windows 10 |
| Sandcat | DVWA | 40 | Debian |
| Sandcat | Metasploitable | 40 | Ubuntu |

### Adversary Profiles

The deployment includes **29 MITRE ATT&CK adversary profiles** exported as JSON. These profiles map to real-world threat actor TTPs and are used for:

- Validating Wazuh detection rule coverage across ATT&CK tactics
- Generating labeled attack traffic for ML model training
- Identifying detection gaps via Shuffle WF3 (Detection Gap Analyzer)

### Campaign Settings

Campaigns must be configured with:

- `auto_close: false` -- prevents premature campaign termination
- `source: basic` -- references the default fact source
- `group: "targets"` -- targets the correct agent group
- Full adversary UUIDs (truncated UUIDs cause 0-link failures)

## Ground-Truth Logging

### run_attack.sh

The [`attack-scripts/run_attack.sh`](attack-scripts/run_attack.sh) wrapper script is used for **all** manual attack execution. It logs every attack to a CSV file with timestamps, attack type, target, and parameters. This ground-truth log feeds the ML pipeline's `GroundTruthExtractor` for temporal labeling of Wazuh alerts.

Usage:
```bash
./run_attack.sh <attack_type> <target_ip> [additional_args]
```

All attacks must target VLAN 40 (10.10.40.0/24) exclusively.

## Purple Team Validation

The adversary simulation workflow follows a closed loop:

1. **Execute** -- run Caldera campaigns or manual attacks via `run_attack.sh`
2. **Detect** -- verify Wazuh alerts fire for each technique executed
3. **Measure** -- correlate attack logs with detections to quantify coverage
4. **Improve** -- write new Wazuh rules or tune existing ones to close gaps
5. **Retrain** -- feed labeled data into the ML pipeline for model updates

Shuffle WF3 (Detection Gap Analyzer) automates step 3 by comparing Caldera campaign telemetry against Wazuh alert data.

## Directory Structure

| Path | Description |
|------|-------------|
| [`caldera/default.yml`](caldera/default.yml) | Caldera server default configuration |
| [`caldera/local.yml`](caldera/local.yml) | Local configuration overrides |
| [`caldera/agents.yml`](caldera/agents.yml) | Sandcat agent deployment definitions |
| [`caldera/adversary-profiles.json`](caldera/adversary-profiles.json) | 29 MITRE ATT&CK adversary profile exports |
| [`attack-scripts/run_attack.sh`](attack-scripts/run_attack.sh) | Ground-truth logging wrapper for manual attacks |
