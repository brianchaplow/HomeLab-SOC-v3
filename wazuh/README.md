# Wazuh SIEM

Wazuh 4.14.2 deployment serving as the primary SIEM for the HomeLab SOC v3 platform. Runs as a Docker stack on **brisket** (10.10.20.30) with 12 enrolled agents spanning all network VLANs, plus OPNsense syslog ingestion.

## Architecture

The Wazuh stack consists of three containers (Manager, Indexer, Dashboard) deployed via Docker Compose. The Manager receives agent events on ports 1514/1515, syslog on 514/UDP, and exposes the API on port 55000. The Indexer (OpenSearch-based) stores alerts in `wazuh-alerts-4.x-*` indices alongside seven Zeek indices enriched via the Fluent Bit pipeline on smokehouse.

### Agent Inventory

| Agent | Host | VLAN | OS |
|-------|------|------|----|
| 001 | smoker | 30 | Proxmox VE |
| 002 | sear | 20 | Kali Linux |
| 003 | pitcrew | 30 | Proxmox VE |
| 005 | PITBOSS | 10 | Windows 11 |
| 006 | smokehouse | 20 | QTS (QNAP) |
| 007 | DC01 | 30 | Windows Server 2022 |
| 009 | GCP VM | External | Ubuntu (GCP) |
| 010 | thehive | 30 | TheHive LXC 200 |
| 012 | WS01 | 30 | Windows 10 |
| 013 | pbs | 30 | PBS LXC 300 |
| 014 | haccp | 30 | Ubuntu 24.04 |
| -- | OPNsense | 10 | Syslog (514/UDP) |

### Zeek Pipeline

Smokehouse runs Zeek on a SPAN port (eth4), and Fluent Bit ships parsed logs to the Wazuh Indexer on brisket. Seven dedicated indices hold the Zeek data:

`zeek-conn`, `zeek-dns`, `zeek-http`, `zeek-ssl`, `zeek-files`, `zeek-notice`, `zeek-weird`

These indices feed the ML pipeline's feature engineering stage, providing 31 network-level behavioral features (conn_state, history, service DPI, duration, byte ratios) for threat scoring.

## Directory Contents

| Path | Description |
|------|-------------|
| [`configs/ossec.conf`](configs/ossec.conf) | Manager configuration -- agent enrollment, syslog input, ruleset loading, remote commands |
| [`rules/local_rules.xml`](rules/local_rules.xml) | Custom detection rules layered on top of the default Wazuh ruleset |
| [`decoders/local_decoder.xml`](decoders/local_decoder.xml) | Custom decoders for non-standard log formats |
| [`detection-examples/`](detection-examples/) | Sample alerts and detection write-ups demonstrating rule triggering |

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 1514 | TCP | Agent event transport |
| 1515 | TCP | Agent enrollment |
| 514 | UDP | Syslog (OPNsense) |
| 55000 | TCP | Wazuh REST API (JWT auth) |

## Detection Examples

The [`detection-examples/`](detection-examples/) directory contains sample alert JSON and narrative write-ups showing how custom rules fire against real attack traffic. See [`sqlmap-detection.md`](detection-examples/sqlmap-detection.md) for a worked example of SQL injection detection via Wazuh + Zeek correlation.

## Integration Points

- **Shuffle SOAR** -- WF1 webhook receives Wazuh alerts for automated enrichment and response
- **ML Scorer** -- the XGBoost model on brisket:5002 scores alerts using features derived from Wazuh + Zeek data
- **TheHive** -- high-severity alerts are escalated to case management via Shuffle
- **ELK Stack** -- Fleet agents on haccp collect endpoint telemetry; honeypot sync (agent 009 → ELK) is decommissioned
- **OpenCTI** -- IOC indicators are exported from OpenCTI to a Wazuh CDB list and matched by custom rule 100200 for real-time threat intelligence alerting
