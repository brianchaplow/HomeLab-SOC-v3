# Infrastructure

Core infrastructure configurations for the HomeLab SOC v3 platform, including Docker Compose stacks, monitoring, and network sensor configs across four physical hosts.

## Host Overview

### brisket (10.10.20.30) -- SOC Platform

Primary SOC server (Intel Ultra 9 285, 64 GB RAM, NVIDIA RTX A1000). Runs the following Docker stacks:

| Stack | Containers | Compose File |
|-------|-----------|--------------|
| Wazuh | Manager, Indexer (OpenSearch), Dashboard | [`docker/brisket-wazuh-compose.yml`](docker/brisket-wazuh-compose.yml) |
| Shuffle | Frontend, Backend, Orborus, OpenSearch | [`docker/brisket-shuffle-compose.yml`](docker/brisket-shuffle-compose.yml) |
| ML Scorer | FastAPI + XGBoost | [`docker/brisket-ml-scorer-compose.yml`](docker/brisket-ml-scorer-compose.yml) |
| Velociraptor | Server (GUI + client comms) | [`docker/brisket-velociraptor-compose.yml`](docker/brisket-velociraptor-compose.yml) |
| Monitoring | Prometheus, Grafana | [`docker/brisket-monitoring-compose.yml`](docker/brisket-monitoring-compose.yml) |

Ollama runs natively on the host (not containerized) to leverage the RTX A1000 GPU directly.

### haccp (10.10.30.25) -- ELK & Packet Capture

Bare metal host running the ELK stack (Elasticsearch 8.17 with 12 GB heap, Kibana, Fleet Server, Logstash) and Arkime v6.0.1 for full packet capture and session analysis. Migrated from pitcrew LXC 201 in March 2026. Docker Compose at `/opt/elk/docker-compose.yml`. Containers do not auto-start on reboot.

### smokehouse (10.10.20.10) -- Sensors

QNAP NAS running Suricata and Zeek on a SPAN mirror port (eth4). Fluent Bit ships parsed Zeek logs (conn, dns, http, ssl, files, notice, weird) to the Wazuh Indexer on brisket. Legacy Telegraf, InfluxDB, and Grafana instance decommissioned in March 2026 (monitoring consolidated to Prometheus/Grafana on brisket).

### smoker (10.10.30.21) -- Targets and Adversary Simulation

Proxmox host running Caldera v5.3.0 and multiple target containers on VLAN 40 via ipvlan L2 networking (WordPress, crAPI, vsftpd, SMTP relay, SNMPd, Honeypot WAF). Also hosts PBS LXC 300 for Proxmox Backup Server (NFS mount to smokehouse 17 TB storage).

### pitcrew (10.10.30.20) -- Proxmox & Threat Intel

Proxmox host running AD lab VMs (DC01, WS01) and TheHive LXC 200. WS01 is a Windows 10 Eval (EOL Oct 2025, unpatched attack surface). Also hosts **OpenCTI LXC 202** (10.10.30.26) for threat intelligence platform integration with Shuffle WF1 and Wazuh IOC CDB lists.

## Monitoring

Prometheus scrapes 7 targets (added haccp) and feeds the Grafana SOC v3 Overview dashboard. The Proxmox Telegraf dashboard provides VM/LXC resource metrics from both pitcrew and smoker.

| File | Description |
|------|-------------|
| [`prometheus/prometheus.yml`](prometheus/prometheus.yml) | Scrape configuration (7 targets) |
| [`grafana/proxmox-telegraf-dashboard.json`](grafana/proxmox-telegraf-dashboard.json) | Grafana dashboard for Proxmox host and guest metrics |

## Network Sensors

Suricata configuration and custom rules for the smokehouse SPAN port deployment.

| File | Description |
|------|-------------|
| [`configs/suricata/suricata.yaml`](configs/suricata/suricata.yaml) | Main Suricata configuration |
| [`configs/suricata/local.rules`](configs/suricata/local.rules) | Custom Suricata detection rules |
| [`configs/suricata/update.yaml`](configs/suricata/update.yaml) | suricata-update rule source configuration |

## Legacy Stack

| File | Description |
|------|-------------|
| [`docker/v2-soc-compose.yml`](docker/v2-soc-compose.yml) | v2 SOC Docker Compose stack (smokehouse-era, retained for reference) |

## Directory Structure

```
infrastructure/
  docker/
    brisket-wazuh-compose.yml
    brisket-shuffle-compose.yml
    brisket-ml-scorer-compose.yml
    brisket-velociraptor-compose.yml
    brisket-monitoring-compose.yml
    v2-soc-compose.yml
  prometheus/
    prometheus.yml
  grafana/
    proxmox-telegraf-dashboard.json
  configs/
    suricata/
      suricata.yaml
      local.rules
      update.yaml
```
