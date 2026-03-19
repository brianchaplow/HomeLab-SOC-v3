# SOC Infrastructure Redesign — haccp + OpenCTI + Consolidation

**Author:** Brian Chaplow
**Date:** 2026-03-14
**Status:** In Progress (Phases A-C complete, D mostly complete, E pending)
**Supersedes:** 2026-03-07-haccp-elk-arkime-design.md, 2026-03-09-haccp-revised-design.md (in parent project docs/plans/)

---

## Summary

Redesign the HomeLab SOC v3 infrastructure to trim redundancy, add a threat intelligence platform (OpenCTI), migrate ELK to dedicated bare metal with Arkime packet capture, and establish Sigma/YARA as operational practices. Driven by portfolio optimization — every tool must demonstrate skills a recruiter can map to SOC Analyst, SOC Engineer, Security Engineer, or DFIR roles.

## Design Principles

1. **Portfolio-first** — every running service must map to a demonstrable skill hiring managers look for
2. **Trim, don't bloat** — remove redundant tooling (dual metrics stack), consolidate where possible
3. **Clear host roles** — each machine has an explainable purpose, not a grab-bag of services
4. **Natural pairings** — co-locate services that integrate tightly (OpenCTI + TheHive + Cortex)
5. **Comfortable headroom** — no host above 85% RAM utilization under normal load

## What Changes

| Action | Detail |
|--------|--------|
| **Add** | haccp bare metal — ELK 8.17 + Arkime PCAP |
| **Add** | OpenCTI LXC on pitcrew — threat intelligence platform |
| **Migrate** | ELK stack from pitcrew LXC 201 → haccp bare metal |
| **Remove** | InfluxDB + Grafana + Telegraf (smokehouse v2 metrics stack) |
| **Remove** | Telegraf on pitcrew and smoker |
| **Remove** | LXC 201 on pitcrew (after ELK migration) |
| **Re-enable** | Cloudflare auto-block in Shuffle WF1 (remove HONEYPOT_DISABLED branch) |
| **Clean up** | 6 dead Shuffle worker containers on brisket |
| **Add practices** | Sigma rules + YARA rules as repo-based operational workflows |
| **Drop** | Ollama on haccp (use brisket's qwen3:8b over network if needed) |

## What Stays the Same

- Wazuh SIEM on brisket (10 agents, custom rules, Zeek pipeline)
- Shuffle SOAR on brisket (9 workflows, variable updates only)
- Velociraptor on brisket (7 clients)
- ML Scorer on brisket (XGBoost threat scoring API)
- Ollama on brisket (qwen3:8b, 7 Shuffle workflows)
- Prometheus + Grafana on brisket (v3 metrics)
- Capitol Signals on brisket
- TheHive + Cortex on pitcrew LXC 200
- DC01 + WS01 on pitcrew (AD lab + security monitoring + attack targets)
- Caldera on smoker
- VLAN 40 Docker targets on smoker (WordPress, crAPI, FTP, SMTP, SNMP, WAF/honeypot)
- PBS LXC 300 on smoker
- Suricata + Zeek on smokehouse (SPAN sensors)
- Fluent Bit on smokehouse (Zeek → brisket OpenSearch)
- OPNsense firewall (no rule changes — VLAN 30 ↔ VLAN 20 traffic already permitted, confirmed by existing ELK LXC 201 at 10.10.30.23 which receives data from VLAN 20 hosts via the same paths haccp will use)
- Cloudflare CDN/WAF/DNS
- Tailscale mesh VPN (add haccp as new node)
- GCP VM (portfolio hosting, Wazuh agent 009, Fluent Bit → repoint to haccp)

---

## Host Roles After Redesign

### brisket (10.10.20.30) — SOC Core

Primary SOC platform. No architectural changes — workflow variable updates only.

| Service | Change |
|---------|--------|
| Wazuh Manager + Indexer + Dashboard | Unchanged |
| Shuffle SOAR | Update `$elk_url`, `$elk_user`, `$elk_pass` to haccp. Add `$opencti_url`, `$opencti_api_key`. Re-enable CF auto-block in WF1. |
| Velociraptor | Unchanged |
| ML Scorer | Unchanged |
| Ollama (qwen3:8b) | Unchanged — serves as centralized LLM for all workflows |
| Prometheus + Grafana | Add haccp (10.10.30.25:9100) to scrape targets |
| Capitol Signals | Unchanged |
| Dead containers | Prune 6 exited Shuffle worker containers |

### haccp (10.10.30.25) — Detection & PCAP

New bare metal Ubuntu 24.04 node. Secondary SIEM (ELK migrated from pitcrew LXC 201) and full packet capture (Arkime).

**Hardware:**

| Spec | Value |
|------|-------|
| Machine | ThinkStation P340 Tiny |
| CPU | i7-10700T (8C/16T, 2.0GHz) |
| RAM | 32GB DDR4 |
| GPU | Quadro P1000 4GB (NVIDIA driver installed, available for future use) |
| Drive 1 | 2TB WD SN720 NVMe |
| Drive 2 | 1TB Vansuny NVMe |
| NIC (onboard) | 1GbE — VLAN 30 management + services |
| NIC (USB) | 2.5GbE adapter — SPAN capture (promiscuous, no IP) |

**Drive Layout:**

| Drive | Mount | Purpose |
|-------|-------|---------|
| 2TB WD SN720 | `/` | OS, Docker volumes (ES data, Kibana, Fleet, Logstash), Arkime session metadata |
| 1TB Vansuny | `/opt/arkime/raw` | PCAP rolling buffer (~900GB usable, auto-expire at 50GB free) |

**Services:**

| Service | RAM | Ports | Install Type |
|---------|-----|-------|-------------|
| Elasticsearch 8.17 | 12GB heap | 9200 | Docker |
| Kibana | 1GB | 5601 | Docker |
| Fleet Server | 512MB | 8220 | Docker |
| Logstash | 2GB | 5044 | Docker |
| Arkime capture | 3GB | — | Native (raw NIC access) |
| Arkime viewer | 512MB | 8005 | Native |
| Wazuh agent | minimal | 1514 | Native |
| Velociraptor client | minimal | — | Native |
| Tailscale | minimal | — | Native |
| node-exporter | minimal | 9100 | Native |

**Resource Budget: ~21GB / 32GB (34% headroom).** 11GB free serves as OS page cache for Elasticsearch — ideal for indexing performance.

**Network:**

| Interface | Switch Port | VLAN | Purpose |
|-----------|-------------|------|---------|
| Onboard 1GbE | TE8 | 30 | Management + service traffic |
| USB 2.5GbE | TE11 (SFP+ with RJ45 transceiver) | Mirror dest | Arkime SPAN capture |

**MokerLink Mirror Configuration:**

```
# Existing (unchanged)
mirror session 1 source interface te1-te9 both
mirror session 1 destination interface te10        # smokehouse SFP+

# New — Arkime full-take capture
mirror session 2 source interface te1-te9 both
mirror session 2 destination interface te11        # haccp USB NIC via SFP+ transceiver
```

**Elastic ML Anomaly Jobs (inside ES, no additional services):**

| Job | Data Source | Detects | Bucket Span |
|-----|------------|---------|-------------|
| Auth anomalies | DC01/WS01 Windows Security events (4624, 4625, 4672) | Unusual login times, failed auth spikes, rare user/source IP | 15 min |
| Network traffic volume | Arkime session metadata (arkime_sessions3-*) | Anomalous byte counts, connection rate spikes | 15 min |

**Arkime ↔ Elasticsearch Integration:**
- Arkime uses the same ES 8.17 instance as ELK (shared Docker network)
- Authentication via ES API key or service account (created during ELK setup)
- Arkime session indices (`arkime_sessions3-*`, `arkime_stats`) get their own ILM policy for retention management
- Index templates configured during Arkime `--init` to avoid conflicts with ELK indices

**TLS:** haccp ELK uses HTTPS (self-signed CA, matching LXC 201 convention). Fleet agent enrollment and Shuffle `$elk_url` use HTTPS. Certificates generated during ES bootstrap.

**PCAP Archival:**
- Weekly cron: rsync Arkime PCAP files to smokehouse NFS share BEFORE Arkime auto-expires them (long-term retention beyond the 1TB rolling buffer)
- Compression: tar + zstd for space efficiency
- Estimated weekly volume: 10-50GB depending on traffic (homelab rates), smokehouse RAID6 (~17TB+) has years of headroom
- smokehouse retention: manual cleanup as needed

### pitcrew (10.10.30.20) — IR, Intel & AD Lab

Proxmox host. ELK LXC removed, OpenCTI LXC added. TheHive + Cortex + AD lab unchanged.

**After changes:**

| Component | VMID | RAM | Status |
|-----------|------|-----|--------|
| Proxmox host OS | — | 3GB | Existing |
| TheHive + Cortex LXC | 200 | 8GB | Existing |
| DC01 (Win Server 2022) | 100 | 4GB | Existing |
| WS01 (Win 10) | 101 | 4GB | Existing |
| ~~ELK LXC~~ | ~~201~~ | ~~10GB~~ | **Removed** |
| OpenCTI LXC | 202 | 10GB | **New** |
| **Total** | | **29GB / 32GB** | **9% headroom** |

**pitcrew headroom note:** At 29/32GB, pitcrew is the tightest host in the design. This is acceptable because all workloads have capped memory allocations (LXC limits, VM fixed RAM) and the host runs no variable-load services. If OpenCTI's ES needs tuning down, reducing its heap from 3GB to 2GB instantly frees 1GB. Long-term mitigation: NVMe swap to 1-2TB when SSD prices normalize (separate project).

**Why DC01/WS01 stay on pitcrew:** They serve dual purpose — AD security monitoring (always-on Fleet agent telemetry to ELK, Wazuh agent events) AND attack targets for Caldera campaigns. The monitoring use case is primary and benefits from reliable, always-on connectivity. VLAN 30 isolation is acceptable since both ends are controlled.

### smoker (10.10.30.21) — Targets & Adversary Sim

Unchanged except Telegraf decommission.

| Component | Status |
|-----------|--------|
| Caldera v5.3.0 | Unchanged |
| VLAN 40 Docker targets (WordPress, crAPI, FTP, SMTP, SNMP, WAF) | Unchanged |
| DVWA VM (200) | Unchanged |
| Metasploitable 3 VMs (202, 203) | Available (stopped) |
| PBS LXC 300 | Unchanged |
| Telegraf | **Decommissioned** |

### smokehouse (10.10.20.10) — Sensors & Storage

Sensor role unchanged. v2 metrics stack decommissioned.

| Component | Status |
|-----------|--------|
| Suricata IDS (eth4 SPAN) | Unchanged |
| Zeek (eth4 SPAN) | Unchanged |
| Fluent Bit (Zeek → brisket OpenSearch) | Unchanged |
| Wazuh agent | Unchanged |
| Elastic Agent | Repoint to haccp Fleet Server (one of the 4 Fleet agents) |
| NFS share for PCAP archival | Unchanged (receives weekly rsync from haccp) |
| InfluxDB container | **Decommissioned** |
| Grafana container | **Decommissioned** |
| Telegraf container | **Decommissioned** |

---

## OpenCTI Architecture

### Deployment

New LXC on pitcrew Proxmox. All services run as Docker containers inside the LXC.

| Setting | Value |
|---------|-------|
| VMID | 202 |
| IP | 10.10.30.26 |
| VLAN | 30 |
| vCPU | 4 |
| RAM | 10GB |
| Disk | 60GB |
| OS | Ubuntu 24.04 |

### Services

All ports except 8080 are container-internal only — not exposed on the LXC host IP. Only OpenCTI's web UI/API is reachable from other hosts.

| Service | RAM | Port | Notes |
|---------|-----|------|-------|
| OpenCTI platform | 2GB | 8080 (exposed) | Web UI + GraphQL API |
| Elasticsearch (dedicated) | 3GB heap | 9200 (internal only) | OpenCTI's own ES — NOT shared with haccp |
| Redis | 512MB | 6379 (internal) | Cache + message broker |
| RabbitMQ | 512MB | 5672 (internal) | Connector task queue |
| MinIO | 256MB | 9000 (internal) | File/artifact storage |
| OpenCTI workers | 1.5GB | — | Process connector imports |
| OS + Docker overhead | 1.5GB | — | Ubuntu 24.04 + container runtime |
| **Total** | **~9.3GB / 10GB** | | Lever: reduce ES heap to 2GB to free 1GB |

### Connectors (Starter Set)

| Connector | Type | Schedule | Notes |
|-----------|------|----------|-------|
| MITRE ATT&CK | External import | Daily | Links to Caldera adversary profiles |
| CVE (NIST NVD) | External import | Daily | Vulnerability database |
| AbuseIPDB | External import | Configurable | Complements existing Shuffle lookups |
| AlienVault OTX | External import | Every 6 hours | Broad threat feed |
| CISA KEV | External import | Daily | Actively exploited CVEs |

### Integration

**Feed INTO detection (IOC push):**
- OpenCTI exports IOC lists (IPs, domains, hashes) → Wazuh CDB lists on brisket for automatic alert matching
- OpenCTI pushes threat intel indices → haccp ES for Elastic Security threat indicator match rules

**Enrich DURING investigation (query):**
- Shuffle WF1 queries OpenCTI GraphQL API during alert triage to check if IPs/domains/hashes have known threat context
- Enriched context included in TheHive case creation

**Direct connectors:**
- OpenCTI ↔ TheHive connector for observable sharing (both on pitcrew, fast local calls)

**Shuffle Variable Additions:**

| Variable | Value |
|----------|-------|
| `$opencti_url` | `http://10.10.30.26:8080` |
| `$opencti_api_key` | (generated during setup) |

---

## Data Flow

### Detection Pipeline

1. 10 Wazuh agents + OPNsense syslog → **brisket** Wazuh Manager (unchanged)
2. Suricata/Zeek on smokehouse → Wazuh agent (eve.json) + Fluent Bit (Zeek → brisket OpenSearch) (unchanged)
3. 4 Fleet agents (smokehouse, DC01, WS01, GCP VM) → **haccp** Fleet Server → **haccp** ES (migrated from LXC 201)
4. GCP Fluent Bit → **haccp** ES via Tailscale (repointed from LXC 201)
5. Arkime capture on **haccp** → session metadata in **haccp** ES + PCAPs on 1TB drive (new)
6. 214 Elastic detection rules + 2 ML anomaly jobs on **haccp** ES (migrated + new)

### Threat Intel Pipeline (New)

1. 5 connectors pull IOCs into **OpenCTI** on pitcrew
2. OpenCTI pushes IOC lists → **brisket** Wazuh CDB lists (automatic alert matching)
3. OpenCTI pushes threat intel indices → **haccp** ES (Elastic threat indicator match rules)

### Response Pipeline

1. Wazuh alert triggers → **Shuffle** WF1 on brisket
2. Shuffle queries **AbuseIPDB** + **ML Scorer** + **OpenCTI** (new) for enrichment
3. Shuffle blocks via **Cloudflare** WAF (auto-block re-enabled)
4. Shuffle creates case in **TheHive** on pitcrew with enriched observables
5. Cortex analyzers run on TheHive observables (pitcrew)
6. Velociraptor on brisket available for endpoint forensics/live response

### Monitoring

- Prometheus on brisket scrapes node-exporters: brisket, pitcrew, smoker, sear, **haccp** (new)
- Grafana on brisket for SOC overview dashboard

### PCAP Archival

- Weekly cron on haccp → compress + rsync to smokehouse NFS

### External

- Cloudflare CDN/WAF/DNS — auto-block re-enabled
- GCP VM — Wazuh agent 009 → brisket, Fluent Bit → haccp ES via Tailscale
- Discord — 3 webhook channels from Shuffle (main, honeypot, Capitol Signals)
- Tailscale — 9 nodes (add haccp)

---

## MokerLink Switch Port Map (After Changes)

| Port | Type | Host | VLAN | Notes |
|------|------|------|------|-------|
| TE1 | RJ45 | OPNsense | Trunk (all) | 802.1Q trunk |
| TE2 | RJ45 | pitcrew | 30 | |
| TE3 | RJ45 | smoker | 30+40 trunk | ipvlan L2 for VLAN 40 targets |
| TE4 | RJ45 | sear | 20 | ACL: sear-brisket |
| TE5 | RJ45 | TP-Link IoT | 50 | |
| TE6 | RJ45 | PITBOSS | 10 | |
| TE7 | RJ45 | brisket | 20 | |
| TE8 | RJ45 | haccp | 30 | Changed from VLAN 20 (temp Computrace) to VLAN 30 |
| TE9 | SFP+ | smokehouse (data) | 20 | |
| TE10 | SFP+ | smokehouse (SPAN) | Mirror dest | Mirror session 1 |
| TE11 | SFP+ | haccp (SPAN capture) | Mirror dest | Mirror session 2, RJ45 transceiver |
| TE12 | SFP+ | — | — | Open |

**Shopping list:** 2x 10GBase-T SFP+ RJ45 transceivers (10G copper modules — will auto-negotiate down to 2.5G/1G with the USB adapter). 1 for TE11, 1 spare for TE12.

**Mirror session note:** The MokerLink 10G08410GSM supports 4 mirror sessions. Session 1 (smokehouse SPAN) already exists with source TE1-TE9. Verify during Phase B that the switch allows two sessions with overlapping source ports — if not, fall back to selective mirroring (`source interface te3,te4` for smoker + sear traffic only).

---

## Decommission Order

Phased execution during rack migration downtime. No need for seamless cutover — this is a personal SOC with no active campaigns.

### Phase A: Pre-haccp (Can Do Now)

1. Re-enable Cloudflare auto-block in Shuffle WF1 (remove `HONEYPOT_DISABLED` branch condition)
2. Prune 6 dead Shuffle worker containers on brisket
3. Decommission InfluxDB + Grafana + Telegraf containers on smokehouse
4. Decommission Telegraf on pitcrew (systemctl disable, apt remove, remove influxdata repo + stale GPG keys)
5. Decommission Telegraf on smoker (same)

### Phase B: haccp Standup (After Computrace Clears)

1. Install Ubuntu 24.04 on haccp, configure dual drives (2TB root, 1TB /opt/arkime/raw)
2. Change TE8 VLAN assignment from 20 to 30 on MokerLink
3. Set IP to 10.10.30.25, hostname haccp
4. Install Docker, NVIDIA driver for P1000
5. Deploy ELK stack via Docker Compose (ES 8.17, Kibana, Fleet Server, Logstash)
6. Install Arkime native (capture + viewer)
7. Install SFP+ RJ45 transceiver in TE11, configure MokerLink mirror session 2
8. Install Wazuh agent, Velociraptor client, Tailscale, node-exporter
9. Add haccp to Prometheus scrape targets on brisket

### Phase C: ELK Migration (haccp Ready)

1. Export Kibana saved objects from LXC 201 (dashboards, index patterns, saved searches)
2. Snapshot honeypot indices on LXC 201 for reference
3. Import 214 detection rules, Fleet policies, dashboards to haccp
4. Re-enroll 4 Fleet agents to haccp Fleet Server
5. Repoint GCP VM Fluent Bit to haccp Tailscale IP
6. Update Shuffle workflow variables: `$elk_url`, `$elk_user`, `$elk_pass`
7. Retire honeypot-wazuh-sync cron on brisket (honeypot campaign ended 2026-03-12, cron already commented out — remove entirely)
8. Verify data flow end-to-end
9. Shut down and destroy LXC 201 on pitcrew

### Phase D: OpenCTI Deployment (pitcrew Freed)

1. Create OpenCTI LXC on pitcrew (VMID 202, 4 vCPU, 10GB RAM, 60GB disk)
2. Deploy OpenCTI stack via Docker Compose
3. Configure 5 connectors (MITRE ATT&CK, CVE, AbuseIPDB, AlienVault OTX, CISA KEV)
4. Set up IOC push to Wazuh CDB lists on brisket
5. Set up threat intel index push to ES on haccp
6. Add Shuffle workflow variables (`$opencti_url`, `$opencti_api_key`)
7. Update Shuffle WF1 to query OpenCTI for enrichment during triage
8. Configure OpenCTI ↔ TheHive connector

### Phase E: Operational Practices

1. Create Sigma rule directory in repo with conversion workflows (Sigma → Wazuh rules, Sigma → Elastic rules)
2. Create YARA rule directory in repo, configure Velociraptor YARA scan artifacts and Cortex YARA analyzer
3. Update portfolio documentation, architecture diagrams, and network topology docs

---

## Operational Practices

### Sigma Rules

Sigma is a vendor-agnostic detection rule format. Rules are written once and converted to platform-specific formats:

- **Sigma → Wazuh:** Convert via `sigma-cli` or `sigconverter.io` to Wazuh XML rules, deploy to brisket
- **Sigma → Elastic:** Convert to Elastic SIEM rule format (KQL/EQL), deploy to haccp

Rules stored in the portfolio repo under a dedicated directory. Demonstrates ability to write portable detections — a key skill for detection engineering roles.

### YARA Rules

YARA provides pattern-matching for malware detection. Integration points with existing tools:

- **Velociraptor:** VQL has native YARA support — scan endpoints for malware indicators via hunts
- **Cortex:** YARA analyzer on pitcrew — scan observables from TheHive cases
- **OpenCTI:** YARA indicators as STIX patterns — correlate with threat intel

Rules stored in the portfolio repo. Demonstrates malware analysis capability without requiring a full malware lab.

---

## Resource Summary

| Host | RAM Used | RAM Total | Headroom | CPU | Notes |
|------|----------|-----------|----------|-----|-------|
| brisket | ~18GB | 64GB | 72% free | 24C/24T | Most headroom — SOC core |
| haccp | ~21GB | 32GB | 34% free | 8C/16T | ES page cache benefits from free RAM |
| pitcrew | ~29GB | 32GB | 9% free | 8C/16T | Tightest host — all capped allocations, lever: reduce OpenCTI ES heap |
| smoker | ~7GB | 32GB | 78% free | 8C/16T | Light load — targets mostly idle |
| smokehouse | ~10GB | 16GB | 38% free | 4C/8T | Sensors + storage, lighter after v2 metrics decommission |
