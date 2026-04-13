# Elastic Stack

Elasticsearch 8.17, Kibana, Fleet Server, and Logstash deployed as a Docker stack on **haccp** bare metal (10.10.30.25). Migrated from pitcrew LXC 201 in March 2026. Serves as the detection engine, honeypot research archive, and packet capture platform for the HomeLab SOC. Arkime v6.0.1 runs on the same host for full packet capture and session analysis.

## Deployment

The stack runs on haccp bare metal (32 GB RAM, 12 GB ES heap) using Docker Compose at `/opt/elk/docker-compose.yml`. Tailscale provides overlay connectivity for log ingestion from the GCP VM. ELK containers on haccp do not auto-start on reboot and must be brought up manually:

```bash
ssh bchaplow@10.10.30.25 'cd /opt/elk && docker compose up -d'
```

## Detection Rules

The deployment includes **1,345 detection rules** (migrated and expanded from the original 214 enabled on LXC 201). Rules are exported as a single NDJSON file for version control and reproducibility.

| File | Description |
|------|-------------|
| [`detection-rules/all-rules.ndjson`](detection-rules/all-rules.ndjson) | Full rule export (enabled + disabled) for Kibana import |

Rule categories span MITRE ATT&CK tactics including Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, and Command and Control.

## Fleet Agent Policies

Four Fleet agent policies manage endpoint telemetry collection across the SOC. Fleet Server and all agents connect to haccp (10.10.30.25):

| Policy | Purpose |
|--------|---------|
| SOC Endpoints | Core SOC infrastructure (brisket, sear) |
| Windows Endpoints | Active Directory lab machines (DC01, WS01, WS02) |
| Sensors | Network sensors (smokehouse) |
| Fleet Server | Self-monitoring policy for the Fleet Server |

Policy definitions are exported in [`fleet-policies/agent-policies.json`](fleet-policies/agent-policies.json).

## Dashboards

| File | Dashboard | Panels |
|------|-----------|--------|
| [`dashboards/soc-overview-v3.ndjson`](dashboards/soc-overview-v3.ndjson) | SOC v3 Overview | Alert trends, top rules, agent status |
| [`dashboards/honeypot-research-dashboard.ndjson`](dashboards/honeypot-research-dashboard.ndjson) | Honeypot Research -- INST 570 | 15 panels covering credential capture, geo-IP, attack patterns |

## Honeypot Research Indices

These indices support the INST 570 honeypot research project. The honeypot campaign ended in March 2026; data is historical and preserved for reference. Data was collected from the GCP VM via Fluent Bit (Tailscale) and from Wazuh via a cron-based sync script.

| Index | Source | Description |
|-------|--------|-------------|
| `honeypot-credentials` | Fluent Bit | Credential capture events from the PHP WordPress honeypot |
| `honeypot-access` | Fluent Bit | Apache access logs for the honeypot vhost |
| `honeypot-wazuh` | Cron sync | Wazuh agent 009 alerts for the GCP VM |
| `apache-parsed-v2` | Fluent Bit | Portfolio and blog site access logs with Cloudflare geo fields |

## AI/ML Workflow Indices

| Index | Source | Description |
|-------|--------|-------------|
| `ml-drift` | WF6 | Daily model drift detection metrics and baseline comparisons |
| `honeypot-intel` | WF7 | Weekly honeypot intelligence reports with LLM analysis (decommissioned March 2026) |
| `log-anomalies` | WF8 | Rare alert pattern classifications and daily summaries |
| `auth-anomaly-ml` | Elastic ML | Authentication anomaly detection job (unusual login patterns) |

## Directory Structure

```
elastic/
  detection-rules/
    all-rules.ndjson        # Full Kibana detection rule export
  dashboards/
    soc-overview-v3.ndjson
    honeypot-research-dashboard.ndjson
  fleet-policies/
    agent-policies.json     # Fleet agent policy definitions
```
