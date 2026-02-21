# Incident Response

Case management and digital forensics tooling for the HomeLab SOC, comprising TheHive 4, Cortex 3, and Velociraptor v0.75.3.

## TheHive 4 -- Case Management

Deployed on **pitcrew LXC 200** (10.10.30.22, 4 CPU cores, 8 GB RAM). TheHive receives automated case creation from Shuffle WF1 when alerts exceed the combined threat score threshold. Cases include enrichment context from AbuseIPDB, ML scorer output, and LLM-generated triage summaries.

Shuffle workflows WF1, WF2, WF3, and WF5 all interact with TheHive via its REST API using a workflow variable for the API key.

## Cortex 3 -- Automated Analysis

Cortex runs alongside TheHive on the same LXC and provides observable enrichment through five configured analyzers:

| Analyzer | Function |
|----------|----------|
| AbuseIPDB_1_0 | IP reputation lookup |
| VirusTotal_GetReport_3_1 | File/URL/hash reputation (requires API key) |
| Shodan_DNSResolve_2_0 | DNS resolution and host exposure (requires API key) |
| Abuse_Finder_3_0 | Abuse contact lookup for IP/domain |
| GoogleDNS_resolve_1_0_0 | DNS resolution via Google public DNS |

AbuseIPDB, Abuse_Finder, and GoogleDNS are fully operational. VirusTotal and Shodan analyzers are configured but require provisioning of production API keys.

Analyzer configuration is exported in [`thehive/cortex-analyzers.json`](thehive/cortex-analyzers.json).

## Velociraptor v0.75.3 -- DFIR

Velociraptor provides endpoint visibility and forensic collection across the SOC. The server runs as a Docker container on **brisket** (ports 8889 for GUI, 8000/8001 for client communication).

### Enrolled Clients

| Client | Host | OS |
|--------|------|----|
| 1 | brisket | Ubuntu 24.04 |
| 2 | smokehouse | QTS (QNAP) |
| 3 | sear | Kali Linux |
| 4 | DC01 | Windows Server 2022 |
| 5 | WS01 | Windows 10 |
| 6 | DVWA | Debian |
| 7 | GCP VM | Ubuntu (GCP) |

### Capabilities

- Live forensic artifact collection across all enrolled endpoints
- VQL (Velociraptor Query Language) for ad hoc investigations
- Hunt groups for fleet-wide artifact sweeps
- Integration planned with Shuffle WF4 for automated triage (not yet implemented)

## Directory Structure

| Path | Description |
|------|-------------|
| [`thehive/cortex-analyzers.json`](thehive/cortex-analyzers.json) | Cortex analyzer configuration export |
| [`velociraptor/server.config.yaml`](velociraptor/server.config.yaml) | Velociraptor server configuration (sanitized) |
| [`velociraptor/client.config.yaml`](velociraptor/client.config.yaml) | Velociraptor client configuration (sanitized) |
| [`velociraptor/docker-compose.yml`](velociraptor/docker-compose.yml) | Velociraptor Docker Compose deployment |

> **Note:** Server and client configuration files have been sanitized to remove certificates, private keys, and authentication tokens. They demonstrate the deployment architecture without exposing secrets.
