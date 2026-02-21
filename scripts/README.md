# Scripts

Utility scripts for SOC infrastructure data collection and the v2 automation suite that preceded the Shuffle SOAR workflows.

## Collect-SOC.ps1 -- Infrastructure Collection

[`collection/Collect-SOC.ps1`](collection/Collect-SOC.ps1) is a PowerShell script that gathers configurations and operational state from all SOC hosts via SSH. It collects:

- Docker Compose files and container status from brisket, smokehouse, and smoker
- Wazuh manager configuration, custom rules, and decoders
- Suricata and Zeek sensor configurations from smokehouse
- Prometheus and Grafana configurations
- Velociraptor server/client configs
- Caldera configuration files
- TheHive and Cortex settings
- ELK Stack Docker Compose and Fleet policies
- Shuffle workflow exports

The script was used to populate this portfolio repository with sanitized copies of production configurations.

## v2 Automation Suite

The [`automation/`](automation/) directory contains the **v2 soc-automation scripts** -- Docker-containerized Python tools that handled alert enrichment, auto-blocking, daily digests, and ML scoring before being replaced by the Shuffle SOAR platform in v3.

### Components

| Script | Purpose | v3 Replacement |
|--------|---------|----------------|
| [`scripts/enrichment.py`](automation/scripts/enrichment.py) | AbuseIPDB + WHOIS lookup for alert IPs | Shuffle WF1 |
| [`scripts/autoblock.py`](automation/scripts/autoblock.py) | Automated Cloudflare WAF blocking | Shuffle WF1 |
| [`scripts/digest.py`](automation/scripts/digest.py) | Daily alert digest to Discord | Shuffle WF2 |
| [`scripts/ml_scorer.py`](automation/scripts/ml_scorer.py) | XGBoost model inference utilities | ML Scorer container (brisket:5002) |

### Shared Utilities

| Module | Purpose |
|--------|---------|
| [`scripts/utils/opensearch_client.py`](automation/scripts/utils/opensearch_client.py) | OpenSearch query client |
| [`scripts/utils/discord_notify.py`](automation/scripts/utils/discord_notify.py) | Discord webhook notification helper |

### Configuration

| File | Description |
|------|-------------|
| [`automation/config/config.yaml`](automation/config/config.yaml) | Service endpoints, thresholds, and operational settings |
| [`automation/env.example`](automation/env.example) | Environment variable template for credentials (never commit actual `.env`) |
| [`automation/docker-compose.yml`](automation/docker-compose.yml) | Container deployment for the automation suite |
| [`automation/Dockerfile`](automation/Dockerfile) | Container image build definition |
| [`automation/requirements.txt`](automation/requirements.txt) | Python dependencies |
| [`automation/cron/crontab`](automation/cron/crontab) | Scheduled execution configuration |

### Running

The v2 suite ran as a Docker container with cron-scheduled tasks. While it is no longer in active use (Shuffle handles all automation in v3), it is preserved here as a reference for the evolution of the SOC's automation capabilities.

```bash
# v2 usage (historical reference)
docker compose -f automation/docker-compose.yml up -d
```
