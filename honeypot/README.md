# Honeypot Research

WordPress login honeypot deployed on a **GCP VM** for INST 570 cybersecurity research. The honeypot captures credential stuffing attempts and attack patterns, shipping data to the ELK Stack for analysis via Fluent Bit and a Wazuh alert sync pipeline.

## Architecture

```
Attacker --> GCP VM (34.48.x.x)
               |
               +--> PHP wp-login.php honeypot --> /var/log/honeypot/credentials.json
               +--> Apache access logs         --> /var/log/apache2/honeypot-access.log
               +--> Wazuh Agent 009            --> brisket Wazuh Manager
               |
          Fluent Bit (es output)
               |
               +--> [Tailscale overlay] --> ELK LXC 201
               |                              honeypot-credentials index
               |                              honeypot-access index
               |
          honeypot-wazuh-sync.py (cron */15 on brisket)
               |
               +--> ELK LXC 201 --> honeypot-wazuh index
```

The GCP VM is only reachable from the home network via Tailscale (LAN IPs are not routable). Fluent Bit ships directly to Elasticsearch using the `es` output plugin over the Tailscale overlay.

## Data Collection

| Index | Source | Records | Description |
|-------|--------|---------|-------------|
| `honeypot-credentials` | Fluent Bit | ~3,140 | Username/password pairs captured by the PHP honeypot |
| `honeypot-access` | Fluent Bit | ~737 | Apache access logs for the honeypot virtual host |
| `honeypot-wazuh` | Cron sync | ~5,925 | Wazuh alerts for GCP VM agent 009 (rule triggers, MITRE mappings) |

The sync script (`honeypot-wazuh-sync.py`) uses Wazuh document `_id` as the Elasticsearch `_id`, making it idempotent -- re-runs never create duplicates.

## Kibana Dashboard

The **Honeypot Research Dashboard -- INST 570** contains 15 visualization panels covering:

- Credential capture volume over time
- Top attempted usernames and passwords
- Source IP geolocation (country distribution)
- Wazuh rule trigger frequency and MITRE ATT&CK technique mapping
- HTTP method and user-agent analysis

The dashboard builder script generates the Kibana saved objects programmatically.

## Shuffle Integration

- **WF7 (Honeypot Intel Report)** -- runs weekly on Sundays, queries all three honeypot indices, generates statistics, and produces an LLM-authored intelligence summary delivered to Discord
- **WF8 (LLM Log Anomaly Finder)** -- daily analysis that includes honeypot-wazuh patterns in its rare alert classification

## Directory Structure

| Path | Description |
|------|-------------|
| [`configs/honeypot-wazuh-sync.py`](configs/honeypot-wazuh-sync.py) | Cron script that syncs Wazuh agent 009 alerts to ELK every 15 minutes |
| [`scripts/honeypot-import.py`](scripts/honeypot-import.py) | Bulk import script for loading historic honeypot data into Elasticsearch |
| [`scripts/honeypot-export-powerbi.py`](scripts/honeypot-export-powerbi.py) | Export honeypot data to CSV for Power BI analysis |
| [`dashboards/honeypot-dashboard.py`](dashboards/honeypot-dashboard.py) | Programmatic Kibana dashboard builder (saved objects API) |
