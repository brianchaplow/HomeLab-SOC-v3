# Documentation

Architecture documentation, network topology, migration narrative, and visual assets for the HomeLab SOC v3 portfolio.

## Contents

| Document | Description |
|----------|-------------|
| `architecture.md` | High-level SOC v3 architecture -- component relationships, data flows, and design rationale |
| `phases.md` | Phase-by-phase migration narrative (phases 1-12) covering the build-out from bare metal to fully operational SOC |
| `network-topology.md` | VLAN design, firewall rules, switch ACLs, and inter-host connectivity map |
| [`guides/portfolio-overview.md`](guides/portfolio-overview.md) | Narrative guide for portfolio reviewers -- architecture, detection engineering, ML, IR, and more |
| [`guides/soc-playbook.md`](guides/soc-playbook.md) | Operational SOC handbook -- daily checklists, alert triage, runbooks, API reference, troubleshooting |

## Visual Assets

### Screenshots

The [`screenshots/`](screenshots/) directory contains annotated screenshots of the SOC platform in operation:

| File | Description |
|------|-------------|
| [`screenshots/ml-dashboard.jpg`](screenshots/ml-dashboard.jpg) | ML pipeline performance dashboard showing model metrics |

### Diagrams

Architecture and data-flow diagrams are written inline as Mermaid in the Markdown files (see the top-level README, `architecture.md` and `network-topology.md`), so GitHub renders them directly.

## Related Documentation

- [Shuffle WF6/WF7/WF8 Design](../shuffle/docs/wf6-wf7-wf8-design.md) -- AI/ML workflow suite design document
- [Wazuh Detection Examples](../wazuh/detection-examples/) -- sample alerts and detection write-ups
- [ML Model Card](../ml-pipeline/model-cards/xgboost-threat-scorer.md) -- XGBoost threat scorer evaluation and limitations
