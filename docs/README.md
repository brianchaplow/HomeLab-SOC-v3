# Documentation

Architecture documentation, network topology, migration narrative, and visual assets for the HomeLab SOC v3 portfolio.

## Contents

| Document | Description |
|----------|-------------|
| `architecture.md` | High-level SOC v3 architecture -- component relationships, data flows, and design rationale |
| `phases.md` | 11-phase migration narrative covering the build-out from bare metal to fully operational SOC |
| `network-topology.md` | VLAN design, firewall rules, switch ACLs, and inter-host connectivity map |

## Visual Assets

### Screenshots

The [`screenshots/`](screenshots/) directory contains annotated screenshots of the SOC platform in operation:

| File | Description |
|------|-------------|
| [`screenshots/ml-dashboard.jpg`](screenshots/ml-dashboard.jpg) | ML pipeline performance dashboard showing model metrics |

### Diagrams

The [`diagrams/`](diagrams/) directory is reserved for architecture and data flow diagrams (Mermaid source files, exported PNGs).

## Related Documentation

- [Shuffle WF6/WF7/WF8 Design](../shuffle/docs/wf6-wf7-wf8-design.md) -- AI/ML workflow suite design document
- [Wazuh Detection Examples](../wazuh/detection-examples/) -- sample alerts and detection write-ups
- [ML Model Card](../ml-pipeline/model-cards/xgboost-threat-scorer.md) -- XGBoost threat scorer evaluation and limitations
