# Infrastructure

Core infrastructure configurations for the HomeLab SOC v3 platform, including Docker Compose stacks, monitoring, and network sensor configs across four physical hosts.

## Host Overview

### soc-01 (172.20.2.14) -- SOC Platform

Primary SOC server (Intel Ultra 9 285, 64 GB RAM, NVIDIA RTX A1000). Runs the following Docker stacks:

| Stack | Containers | Compose File |
|-------|-----------|--------------|
| Wazuh | Manager, Indexer (OpenSearch), Dashboard | [`docker/soc-01-wazuh-compose.yml`](docker/soc-01-wazuh-compose.yml) |
| Shuffle | Frontend, Backend, Orborus, OpenSearch | [`docker/soc-01-shuffle-compose.yml`](docker/soc-01-shuffle-compose.yml) |
| ML Scorer | FastAPI + XGBoost | [`docker/soc-01-ml-scorer-compose.yml`](docker/soc-01-ml-scorer-compose.yml) |
| Velociraptor | Server (GUI + client comms) | [`docker/soc-01-velociraptor-compose.yml`](docker/soc-01-velociraptor-compose.yml) |
| Monitoring | Prometheus, Grafana | [`docker/soc-01-monitoring-compose.yml`](docker/soc-01-monitoring-compose.yml) |

Ollama runs natively on the host (not containerized) to leverage the RTX A1000 GPU directly.

### elk-01 (172.20.3.16) -- ELK & Packet Capture

Bare metal host running the ELK stack (Elasticsearch 8.17 with 12 GB heap, Kibana, Fleet Server, Logstash) and Arkime v6.0.1 for full packet capture and session analysis. Migrated from pve-01 LXC 201 in March 2026. Docker Compose at `/opt/elk/docker-compose.yml`. Containers do not auto-start on reboot.

### sensor-01 (172.20.2.11) -- Sensors

QNAP NAS running Suricata and Zeek on a SPAN mirror port (eth4). Fluent Bit ships parsed Zeek logs (conn, dns, http, ssl, files, notice, weird) to the Wazuh Indexer on soc-01. Legacy Telegraf, InfluxDB, and Grafana instance decommissioned in March 2026 (monitoring consolidated to Prometheus/Grafana on soc-01).

### pve-02 (172.20.3.12) -- Targets and Adversary Simulation

Proxmox host running Caldera v5.3.0 and multiple target containers on VLAN 400 via ipvlan L2 networking (WordPress, crAPI, vsftpd, SMTP relay, SNMPd, Honeypot WAF). Also hosts PBS LXC 300 for Proxmox Backup Server (NFS mount to sensor-01 17 TB storage).

### pve-01 (172.20.3.11) -- Proxmox & Threat Intel

Proxmox host running AD lab VMs (DC01, WS01) and TheHive LXC 200. WS01 is a Windows 10 Eval (EOL Oct 2025, unpatched attack surface). Also hosts **OpenCTI LXC 202** (172.20.3.17) for threat intelligence platform integration with Shuffle WF1 and Wazuh IOC CDB lists.

## Monitoring

Prometheus scrapes 7 targets (added elk-01) and feeds the Grafana SOC v3 Overview dashboard. The Proxmox Telegraf dashboard provides VM/LXC resource metrics from both pve-01 and pve-02.

| File | Description |
|------|-------------|
| [`prometheus/prometheus.yml`](prometheus/prometheus.yml) | Scrape configuration (7 targets) |
| [`grafana/proxmox-telegraf-dashboard.json`](grafana/proxmox-telegraf-dashboard.json) | Grafana dashboard for Proxmox host and guest metrics |

## Network Sensors

Suricata configuration and custom rules for the sensor-01 SPAN port deployment.

| File | Description |
|------|-------------|
| [`configs/suricata/suricata.yaml`](configs/suricata/suricata.yaml) | Main Suricata configuration |
| [`configs/suricata/local.rules`](configs/suricata/local.rules) | Custom Suricata detection rules |
| [`configs/suricata/update.yaml`](configs/suricata/update.yaml) | suricata-update rule source configuration |

## Legacy Stack

| File | Description |
|------|-------------|
| [`docker/v2-soc-compose.yml`](docker/v2-soc-compose.yml) | v2 SOC Docker Compose stack (sensor-01-era, retained for reference) |

## Directory Structure

```
infrastructure/
  docker/
    soc-01-wazuh-compose.yml
    soc-01-shuffle-compose.yml
    soc-01-ml-scorer-compose.yml
    soc-01-velociraptor-compose.yml
    soc-01-monitoring-compose.yml
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
