# Infrastructure

Core infrastructure configurations for the HomeLab SOC v3 platform, including Docker Compose stacks, monitoring, and network sensor configs across three physical hosts.

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

### smokehouse (10.10.20.10) -- Sensors

QNAP NAS running Suricata and Zeek on a SPAN mirror port (eth4). Fluent Bit ships parsed Zeek logs (conn, dns, http, ssl, files, notice, weird) to the Wazuh Indexer on brisket. Also hosts Telegraf, InfluxDB, and a Grafana instance for infrastructure dashboards.

### smoker (10.10.30.21) -- Targets and Adversary Simulation

Proxmox host running Caldera v5.3.0 and multiple target containers on VLAN 40 via ipvlan L2 networking (WordPress, crAPI, vsftpd, SMTP relay, SNMPd, Honeypot WAF). Also hosts PBS LXC 300 for Proxmox Backup Server (NFS mount to smokehouse 17 TB storage).

## Monitoring

Prometheus scrapes 6 targets and feeds the Grafana SOC v3 Overview dashboard. The Proxmox Telegraf dashboard provides VM/LXC resource metrics from both pitcrew and smoker.

| File | Description |
|------|-------------|
| [`prometheus/prometheus.yml`](prometheus/prometheus.yml) | Scrape configuration (6 targets) |
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
