# Elastic Stack

Elasticsearch 8.17, Kibana, Fleet Server, and Logstash deployed as a Docker stack on **ELK LXC 201** (10.10.30.23), hosted on the pitcrew Proxmox node. Serves as the detection engine and honeypot research platform for the HomeLab SOC.

## Deployment

The entire stack runs inside a Proxmox LXC container (6 CPU cores, 10 GB RAM) using Docker Compose at `/opt/elk/docker-compose.yml`. Tailscale provides overlay connectivity for log ingestion from the GCP VM. Containers do not auto-start on LXC reboot and must be brought up manually.

## Detection Rules

The deployment includes approximately **1,419 total detection rules**, of which **214 are actively enabled**. Rules are exported as a single NDJSON file for version control and reproducibility.

| File | Description |
|------|-------------|
| [`detection-rules/all-rules.ndjson`](detection-rules/all-rules.ndjson) | Full rule export (enabled + disabled) for Kibana import |

Rule categories span MITRE ATT&CK tactics including Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, and Command and Control.

## Fleet Agent Policies

Four Fleet agent policies manage endpoint telemetry collection across the SOC:

| Policy | Purpose |
|--------|---------|
| SOC Endpoints | Core SOC infrastructure (brisket, sear) |
| Windows Endpoints | Active Directory lab machines (DC01, WS01) |
| Sensors | Network sensors (smokehouse) |
| Fleet Server | Self-monitoring policy for the Fleet Server |

Policy definitions are exported in [`fleet-policies/agent-policies.json`](fleet-policies/agent-policies.json).

## Dashboards

| File | Dashboard | Panels |
|------|-----------|--------|
| [`dashboards/soc-overview-v3.ndjson`](dashboards/soc-overview-v3.ndjson) | SOC v3 Overview | Alert trends, top rules, agent status |
| [`dashboards/honeypot-research-dashboard.ndjson`](dashboards/honeypot-research-dashboard.ndjson) | Honeypot Research -- INST 570 | 15 panels covering credential capture, geo-IP, attack patterns |

## Honeypot Research Indices

These indices support the INST 570 honeypot research project. Data flows from the GCP VM via Fluent Bit (Tailscale) and from Wazuh via a cron-based sync script.

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
| `honeypot-intel` | WF7 | Weekly honeypot intelligence reports with LLM analysis |
| `log-anomalies` | WF8 | Rare alert pattern classifications and daily summaries |

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
