# HomeLab SOC v3 -- Portfolio Overview

**Author:** Brian Chaplow
**Last Updated:** 2026-03-04

A comprehensive walkthrough of a production-grade Security Operations Center built on commodity hardware, open-source tooling, and machine learning. This document is written for hiring managers, interviewers, and peers evaluating hands-on SOC engineering skills. It explains not just what was built, but why each design decision was made and how the components work together as a unified detection-and-response platform.

The HomeLab SOC v3 is the result of 11 migration phases completed in 4 days (February 10--13, 2026). It replaces the v2 architecture with a centralized platform on brisket, a purpose-built SOC server with GPU acceleration for both machine learning inference and LLM-powered automation. Every component described here is live, tested against real attack traffic, and continuously monitored.

---

## Table of Contents

1. [SOC Architecture at a Glance](#1-soc-architecture-at-a-glance)
2. [The Alert Lifecycle (End-to-End)](#2-the-alert-lifecycle-end-to-end)
3. [Detection Engineering](#3-detection-engineering)
4. [SOAR and LLM Automation](#4-soar-and-llm-automation)
5. [ML Threat Scoring](#5-ml-threat-scoring)
6. [Incident Response and Case Management](#6-incident-response-and-case-management)
7. [Adversary Emulation and Validation](#7-adversary-emulation-and-validation)
8. [Honeypot Research](#8-honeypot-research)
9. [Network Security Design](#9-network-security-design)

---

## 1. SOC Architecture at a Glance

### What This SOC Is

This is a fully integrated Security Operations Center running on physical hardware in a home lab environment. It is not a proof-of-concept or a single-tool deployment. It is an end-to-end detection, enrichment, triage, response, and intelligence platform that mirrors the architecture of a mid-sized enterprise SOC -- with the addition of ML-based threat scoring and LLM-powered analyst augmentation that most production SOCs have not yet adopted.

The platform handles the complete security operations lifecycle: network traffic inspection, endpoint monitoring, automated alert enrichment, machine learning threat scoring, LLM-generated triage narratives, case management with NIST 800-61 alignment, endpoint forensics, adversary emulation for detection validation, and honeypot-based threat intelligence collection.

### Key Metrics

| Metric | Value |
|--------|-------|
| Wazuh SIEM agents | 10 (spanning all 5 VLANs + external GCP VM) |
| Elastic detection rules (enabled) | 214 of 1,419 total |
| ML threat scorer PR-AUC | 0.9998 (XGBoost binary classifier) |
| Velociraptor DFIR clients | 7 enrolled endpoints |
| SOAR workflows | 7 active (WF1--WF3, WF5--WF8), 1 planned (WF4) |
| Workflows using LLM | 5 of 7 (WF1, WF2, WF6, WF7, WF8) |
| MITRE ATT&CK adversary profiles | 29 (Caldera) |
| Docker containers on brisket | 12 + Ollama as host service |
| Suricata IDS rules | 47,487 ET Open + 10 custom SIDs |
| Zeek NSM indices | 7 (conn, dns, http, ssl, ssh, files, notice) |
| Honeypot research records | ~9,802 across 3 indices |
| Network VLANs | 5 security zones + isolated family network |

### Technology Stack

| Category | Technology | Version / Detail |
|----------|-----------|-----------------|
| SIEM (primary) | Wazuh | 4.14.2 (Manager + Indexer + Dashboard) |
| SIEM (secondary) | Elastic Security | ES 8.17 + Kibana + Fleet + Logstash |
| SOAR | Shuffle | Frontend, Backend, Orborus, OpenSearch |
| Case management | TheHive | 4 (with NIST 800-61 task templates) |
| Analyzer framework | Cortex | 3 (5 configured analyzers) |
| DFIR | Velociraptor | 0.75.3 (Docker, 7 clients) |
| Adversary emulation | MITRE Caldera | 5.3.0 (4 Sandcat agents) |
| ML threat scoring | XGBoost + IsolationForest | Hybrid scorer, FastAPI on Docker |
| LLM inference | Ollama | qwen3:8b (8B parameters) |
| Network IDS | Suricata | ET Open ruleset + custom SIDs 9000001--9000021 |
| Network monitor | Zeek | JSON logging on SPAN port |
| Firewall | OPNsense | Protectli VP2420 appliance |
| Metrics | Prometheus + Grafana | 6 scrape targets, SOC v3 Overview dashboard |
| Backup | Proxmox Backup Server | NFS to smokehouse 17 TB RAID |

### Hardware

The lab runs on 8 physical hosts with a combined 176 GB of RAM and 12 GB of GPU VRAM across two NVIDIA GPUs. All hosts use BBQ-themed names -- a nod to the intersection of low-and-slow cooking and security operations, where patience is a virtue in both disciplines.

| Host | Hardware | CPU | RAM | GPU | Primary Role |
|------|----------|-----|-----|-----|-------------|
| brisket | Lenovo ThinkStation P3 Tiny Gen 2 | Intel Ultra 9 285 (24C/24T) | 64 GB DDR5 | RTX A1000 (8 GB) | SOC platform -- SIEM, SOAR, DFIR, ML, LLM |
| PITBOSS | ASUS TUF Dash F15 | i7-12650H (10C/16T) | 64 GB DDR5 | -- | Admin workstation (Windows 11) |
| pitcrew | Lenovo ThinkStation P340 Tiny | i7-10700T (8C/16T) | 32 GB DDR4 | -- | Proxmox VE -- AD lab, TheHive, ELK |
| smoker | Lenovo ThinkStation P340 Tiny | i7-10700T (8C/16T) | 32 GB DDR4 | -- | Proxmox VE -- Caldera, targets, backup |
| sear | ASUS ROG Strix G512LI | i5-10300H (4C/8T) | 32 GB DDR4 | GTX 1650 Ti (4 GB) | Kali attack box, ML training |
| smokehouse | QNAP TVS-871 NAS | i7-4790S (4C/8T) | 16 GB DDR3 | -- | Suricata + Zeek sensor, 32 TB RAID |
| OPNsense | Protectli VP2420 | J6412 (4C/4T) | 8 GB DDR4 | -- | Firewall, inter-VLAN routing |
| MokerLink | 10G08410GSM | -- | -- | -- | L3 switch (8x10GbE + 4xSFP+), SPAN, ACL |

**GPU allocation:** The RTX A1000 on brisket handles both ML inference (ml-scorer container) and LLM inference (Ollama qwen3:8b). The GTX 1650 Ti on sear is dedicated to offline ML model training (XGBoost, LightGBM, IsolationForest). This separation ensures training workloads never compete with production inference.

### High-Level Data Flow

Data flows through the SOC in five interconnected pipelines:

1. **Collection.** Ten Wazuh agents across all VLANs ship security events to the Wazuh Manager on brisket. OPNsense forwards firewall syslog. smokehouse runs Suricata and Zeek against SPAN-mirrored traffic from every switch port. Fluent Bit ships Zeek metadata directly to OpenSearch. The GCP honeypot ships credential capture data and access logs to ELK via Tailscale.

2. **Detection.** Wazuh correlates events against its ruleset and generates alerts stored in OpenSearch. Independently, the ELK stack runs 214 Elastic Security detection rules against Fleet agent data. Suricata fires on 47,487+ IDS signatures. These three detection engines provide overlapping coverage with different strengths.

3. **Enrichment and Scoring.** When Wazuh generates a high-severity alert (level 8+), it triggers Shuffle WF1, which enriches the alert with AbuseIPDB reputation data, XGBoost ML threat probability, and an LLM-generated triage summary. The combined score determines automated response actions.

4. **Response.** High-scoring alerts trigger automatic Cloudflare WAF blocks, TheHive case creation with NIST 800-61 task templates, and Discord notifications. Velociraptor provides on-demand endpoint forensics. Cortex analyzers enrich observables within cases.

5. **Intelligence.** Six scheduled workflows generate continuous intelligence: watch turnover digests (WF2), alert cluster triage (WF5), ML drift monitoring (WF6), honeypot intelligence reports (WF7), and log anomaly detection (WF8). WF3 measures detection coverage after Caldera campaigns. All intelligence feeds back into detection tuning and model retraining.

---

## 2. The Alert Lifecycle (End-to-End)

This section traces a single alert from initial network activity through to case closure, showing how every component in the SOC participates in the response. This is not a theoretical workflow -- it is the actual path that a Wazuh level 8+ alert follows through the platform.

### Stage 1: Detection

An attacker scans or exploits a target on VLAN 40. The traffic crosses the MokerLink switch, where the SPAN port (TE10) mirrors it to smokehouse. Two sensors process it simultaneously:

- **Suricata** inspects the packet payload against 47,487 ET Open rules plus custom SIDs (9000001--9000021). If a signature matches, Suricata writes an alert to `eve.json`. The Wazuh agent on smokehouse ships this event to the Wazuh Manager on brisket, where it is normalized, enriched with decoder fields, and indexed into `wazuh-alerts-4.x-*` in OpenSearch.

- **Zeek** extracts connection metadata -- source/destination IPs, ports, protocol, duration, bytes transferred, connection state, and service identification. Fluent Bit ships Zeek's JSON logs to seven dedicated indices on brisket's OpenSearch (`zeek-conn`, `zeek-dns`, `zeek-http`, `zeek-ssl`, `zeek-ssh`, `zeek-files`, `zeek-notice`).

If the Wazuh alert reaches severity level 8 or higher, the Wazuh Manager fires a webhook to Shuffle.

### Stage 2: Automated Enrichment (Shuffle WF1)

The webhook lands on Shuffle WF1 (Threat Enrichment and Auto-Block), which immediately fans out to three enrichment sources in parallel:

- **AbuseIPDB lookup** -- queries the source IP against the AbuseIPDB reputation database, returning a confidence score (0--100) and the number of abuse reports filed by other organizations.

- **ML Scorer** -- sends the alert's feature vector to the XGBoost threat scoring API on brisket:5002. The model evaluates 31 behavioral features (temporal patterns, Zeek connection metadata, alert context) and returns a threat probability between 0.0 and 1.0. The model was trained on 1.28 million alerts labeled via 13 Caldera campaigns and achieves PR-AUC 0.9998.

- **Ollama LLM** -- sends the alert context to qwen3:8b with a structured prompt (prefixed with `/no_think` to suppress reasoning tokens, temperature 0.3 for deterministic output). The LLM generates a natural-language triage summary explaining what the alert likely means, its potential impact, and recommended next steps.

### Stage 3: Scoring Decision

WF1 computes a combined score using the formula:

```
combined_score = max(abuseipdb_normalized, ml_xgboost_score)
```

The higher of the two signals drives the response. This design ensures that both reputation-based intelligence (known bad actors) and behavioral analysis (novel threats that match attack patterns) can independently trigger response actions.

**Auto-block criteria:** If `abuseipdb_score >= 90` AND `abuse_reports >= 5`, the IP is automatically added to the Cloudflare WAF blocklist. This dual threshold prevents blocking on a single high score with no corroborating reports.

Note: Auto-blocking is currently disabled for honeypot research (branch condition `HONEYPOT_DISABLED`), allowing attack traffic to continue flowing to the GCP honeypot for intelligence collection.

### Stage 4: Case Creation

If the combined score exceeds the case-creation threshold, WF1 creates a new case in TheHive (10.10.30.22:9000) via its REST API. The case includes:

- The original Wazuh alert data (rule ID, severity, source/destination, timestamps)
- AbuseIPDB reputation results
- ML scorer output (threat probability and feature contributions)
- The LLM-generated triage summary
- NIST 800-61 task templates for structured incident handling

Cases are tagged with severity, alert source, and MITRE ATT&CK technique mappings where available.

### Stage 5: Investigation

The analyst (or the next scheduled workflow) picks up the case in TheHive and conducts investigation using the available tools:

- **Velociraptor** -- live endpoint forensics on any of the 7 enrolled clients. VQL queries can collect process listings, file system artifacts, network connections, registry keys, and memory artifacts. Hunt groups enable fleet-wide sweeps when lateral movement is suspected.

- **Cortex analyzers** -- observable enrichment through 5 configured analyzers: AbuseIPDB (IP reputation), VirusTotal (file/URL/hash reputation), Shodan (host exposure), Abuse Finder (abuse contact lookup), and Google DNS (DNS resolution). Analysts can run these directly from TheHive's observable panel.

- **Zeek correlation** -- the seven Zeek indices in OpenSearch provide connection-level context that Wazuh alerts alone may lack. An analyst can pivot from an alert's source IP to its full connection history: DNS lookups, HTTP requests, SSL certificate details, SSH sessions, and file transfers.

- **ELK detection rules** -- the 214 enabled Elastic Security rules may have independently flagged related activity on Fleet-monitored endpoints, providing additional detection context.

### Stage 6: Response

Based on investigation findings, response actions may include:

- **Cloudflare WAF block** -- adding the attacker IP to the blocklist (automated in WF1 or manual)
- **Endpoint isolation** -- Velociraptor can quarantine compromised endpoints
- **Wazuh active response** -- the Wazuh Manager can execute predefined response scripts on managed agents
- **Rule tuning** -- if the alert exposed a detection gap, new Wazuh rules or Elastic detection rules are authored

### Stage 7: Closure and After-Action Review

Cases follow the NIST 800-61 incident response lifecycle through closure:

- **Containment, Eradication, Recovery** (NIST 800-61 Sections 3.2--3.3) -- documented in TheHive case tasks
- **Post-Incident Activity** (NIST 800-61 Section 3.4) -- after-action review documenting root cause, detection effectiveness, response timeline, and lessons learned
- **Metrics** -- MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond) are tracked per case to measure SOC performance over time

### Stage 8: Intelligence Loop

The alert lifecycle does not end at case closure. Multiple scheduled workflows feed intelligence back into the SOC:

- **WF2 (Watch Turnover Digest)** -- runs every 12 hours (06:05 and 18:05 EST), summarizing recent alert activity with an LLM-generated narrative for shift handoff context
- **WF5 (Daily Alert Cluster Triage)** -- runs daily at 06:00 EST, grouping alerts by behavioral similarity and generating LLM-powered cluster summaries to identify campaigns or persistent threats
- **WF6 (Model Drift Detector)** -- runs daily at 09:00 EST, sampling 150 recent alerts and comparing their ML score distribution against a stored baseline. Drift metrics are written to the `ml-drift` index in ELK
- **WF8 (LLM Log Anomaly Finder)** -- runs daily at 15:00 EST, scanning for rare alert patterns that rule-based detection might miss, using LLM classification

This feedback loop ensures that each alert contributes to improving detection coverage, model accuracy, and analyst situational awareness.

---

## 3. Detection Engineering

### Dual-SIEM Rationale

The SOC runs two independent SIEM platforms: Wazuh (primary) and Elastic Security (secondary). This is a deliberate architectural choice, not redundancy for its own sake.

**Wazuh** excels at agent-based endpoint monitoring. It provides file integrity monitoring (FIM), security configuration assessment (SCA), vulnerability detection, and real-time log analysis with custom rules and decoders. Its OpenSearch-based indexer stores both Wazuh alerts and Zeek network metadata, making it the central data lake for ML training and SOAR enrichment.

**Elastic Security** excels at detection-as-code with pre-built MITRE ATT&CK rule coverage. The Elastic detection engine evaluates 214 enabled rules against Fleet agent data, covering tactics and techniques that Wazuh's rule format handles less naturally (complex multi-event correlations, ML-based anomaly jobs, threshold-based detections). It also serves as the honeypot research platform, housing the three honeypot indices and their 15-panel Kibana dashboard.

Together, they provide overlapping coverage: Wazuh catches what its agent-based model sees best, Elastic catches what its detection rule engine handles best, and the analyst benefits from both perspectives without a single point of detection failure.

### Wazuh SIEM

**Deployment:** Docker stack on brisket (Manager, Indexer, Dashboard). Ports 1514 (agent transport), 1515 (enrollment), 514/UDP (syslog), 55000 (REST API with JWT authentication).

**Agent coverage:** 10 agents spanning every network zone:

| Agent | Host | VLAN | OS |
|-------|------|------|----|
| 001 | brisket | 20 (SOC) | Ubuntu 24.04 |
| 002 | smokehouse | 20 (SOC) | QTS (QNAP) |
| 003 | sear | 20 (SOC) | Kali Linux |
| 004 | PITBOSS | 10 (Mgmt) | Windows 11 |
| 005 | DC01 | 30 (Lab) | Windows Server 2022 |
| 006 | WS01 | 30 (Lab) | Windows 10 |
| 007 | DVWA | 40 (Targets) | Debian |
| 008 | smoker | 30 (Lab) | Proxmox VE |
| 009 | GCP VM | External | Ubuntu (GCP) |
| -- | OPNsense | 10 (Mgmt) | Syslog (514/UDP) |

**Custom rules and decoders:** The `local_rules.xml` file layers custom detection rules on top of Wazuh's default ruleset. Custom decoders in `local_decoder.xml` handle non-standard log formats. Detection examples with worked write-ups (including SQL injection detection via Wazuh + Zeek correlation) are documented in the repository.

**Capabilities beyond alerting:** Wazuh agents provide file integrity monitoring (detecting unauthorized changes to critical system files), security configuration assessment (benchmarking hosts against CIS baselines), and vulnerability detection (correlating installed packages against CVE databases). These capabilities run continuously on all 10 agents.

### Network Detection: Suricata and Zeek

smokehouse connects to the MokerLink switch via two SFP+ uplinks: TE9 for data (VLAN 20) and TE10 for SPAN capture (all switch ports mirrored, no IP assigned). Every packet crossing the switch is mirrored to TE10, giving the sensors full network visibility.

**Suricata IDS** runs on smokehouse's eth4 (SPAN interface) with:
- 47,487 ET Open community rules providing broad signature coverage
- 10 custom rules (SIDs 9000001--9000021) targeting lab-specific attack patterns
- Alerts written to `eve.json` and shipped to Wazuh via the smokehouse Wazuh agent

**Zeek NSM** runs on the same SPAN interface, extracting protocol-level metadata rather than signature-matching. Zeek produces structured JSON logs covering seven data types:

| Index | Content | ML Pipeline Use |
|-------|---------|-----------------|
| `zeek-conn` | Connection 5-tuples, duration, bytes, packets, conn_state | 31 network-level behavioral features |
| `zeek-dns` | DNS queries and responses | Domain reputation correlation |
| `zeek-http` | HTTP requests with headers, URIs, methods | Web attack pattern analysis |
| `zeek-ssl` | TLS handshakes, certificates, cipher suites | Encrypted traffic profiling |
| `zeek-ssh` | SSH connection metadata | Brute-force detection |
| `zeek-files` | File transfers (type, size, hash) | Malware delivery detection |
| `zeek-notice` | Zeek-generated notices (anomalies, policy violations) | Unusual protocol behavior |

Fluent Bit on smokehouse ships all seven Zeek log types directly to brisket's OpenSearch (Wazuh Indexer) on port 9200. These indices are critical for the ML pipeline's feature engineering stage, providing 31 network-level behavioral features that the XGBoost model uses for threat scoring.

### Elastic Security Detection Rules

ELK LXC 201 (10.10.30.23) runs Elasticsearch 8.17, Kibana, Fleet Server, and Logstash in Docker (6 vCPU, 10 GB RAM). Four Fleet agent policies collect endpoint telemetry:

| Policy | Endpoints |
|--------|-----------|
| SOC Endpoints | brisket, sear |
| Windows Endpoints | DC01, WS01 |
| Sensors | smokehouse |
| Fleet Server | Self-monitoring |

Of the 1,419 total detection rules in the deployment, **214 are actively enabled**, selected for relevance to the lab's attack surface and endpoint mix. The enabled rules map to MITRE ATT&CK tactics with the following distribution:

| Tactic | Enabled Rules | Why This Coverage |
|--------|--------------|-------------------|
| Defense Evasion | 57 | Largest category -- attackers consistently try to avoid detection |
| Credential Access | 45 | AD lab (DC01/WS01) is a primary credential theft target |
| Execution | 38 | Covers command-line, scripting, and exploitation techniques |
| Persistence | 31 | Detects backdoors, scheduled tasks, registry modifications |
| Privilege Escalation | 29 | Catches post-exploitation privilege gain on Windows and Linux |
| Lateral Movement | 21 | Critical for detecting east-west movement between VLANs |

Additional rules cover Initial Access, Discovery, and Command and Control. The full rule set is exported as NDJSON for version control and reproducible Kibana imports.

### OPNsense Syslog

The OPNsense firewall (Protectli VP2420) forwards syslog events to the Wazuh Manager on brisket via UDP 514. This provides visibility into firewall rule matches, blocked connection attempts, NAT translations, and inter-VLAN routing decisions. Firewall logs are particularly valuable for detecting VLAN 40 breakout attempts (which should never succeed) and anomalous east-west traffic patterns.

---

## 4. SOAR and LLM Automation

### Shuffle Architecture

Shuffle SOAR runs as four Docker containers on brisket:

| Component | Port | Function |
|-----------|------|----------|
| Shuffle Frontend | 3443 (HTTPS) | Web interface for workflow design and monitoring |
| Shuffle Backend | 5001 | REST API and workflow execution engine |
| Shuffle Orborus | -- | Worker container orchestrator (spawns execution containers) |
| Shuffle OpenSearch | 9202 | Internal state store for workflow data and execution history |

The backend receives webhook triggers from Wazuh and cron-initiated HTTP POST requests from system cron on brisket. It orchestrates workflow execution by spawning ephemeral containers via Orborus for each action node in a workflow.

### Workflow Inventory

| ID | Workflow Name | Trigger | Schedule (EST) | LLM | Purpose |
|----|--------------|---------|----------------|-----|---------|
| WF1 | Threat Enrichment and Auto-Block | Wazuh webhook (level 8+) | On alert | Yes | Real-time enrichment (AbuseIPDB + ML + LLM) and automated response |
| WF2 | Watch Turnover Digest | System cron | 06:05 / 18:05 | Yes | 12-hour alert summary with LLM narrative for shift handoff |
| WF3 | Detection Gap Analyzer | Webhook (on demand) | Manual trigger | No | Compares Caldera campaign telemetry against Wazuh alerts for coverage % |
| WF5 | Daily Alert Cluster Triage | System cron | 06:00 | Yes | Groups alerts by behavioral similarity, LLM-powered cluster analysis |
| WF6 | Model Drift Detector | System cron | 09:00 | Yes | Samples 150 recent alerts, compares ML score distribution to baseline |
| WF7 | Honeypot Intel Report | System cron | 12:00 Sunday | Yes | Weekly intelligence summary from 3 honeypot indices |
| WF8 | LLM Log Anomaly Finder | System cron | 15:00 | Yes | Rare alert pattern classification and daily anomaly summary |

WF4 (Velociraptor Triage) is planned but not yet implemented. It will automate artifact collection triggered by high-severity cases in TheHive.

### Scheduling Architecture

Shuffle's on-premises scheduler is interval-based, not cron-based. The `frequency` field in schedule documents must be an integer representing seconds; cron strings fail at parse time. To achieve precise wall-clock execution times, all scheduled workflows use **system cron on brisket** that triggers workflows via `curl POST` to the Shuffle API.

Trigger scripts are maintained in the `shuffle/trigger-scripts/` directory and registered in brisket's crontab. This approach provides:

- Exact time-anchored execution (not interval drift)
- Standard cron logging and monitoring via systemd journal
- GPU scheduling control through deliberate time staggering

### GPU Scheduling

Five workflows use Ollama for LLM inference, which requires the RTX A1000 GPU on brisket. To prevent GPU memory contention (qwen3:8b requires approximately 5 GB VRAM), workflow schedules are staggered at least 3 hours apart:

| Time (EST) | Workflow | GPU Use |
|------------|----------|---------|
| 06:00 | WF5 (Alert Cluster Triage) | Ollama -- cluster analysis |
| 06:05 | WF2 (Watch Turnover Digest) | Ollama -- narrative generation |
| 09:00 | WF6 (Model Drift Detector) | Ollama -- drift interpretation |
| 12:00 Sun | WF7 (Honeypot Intel Report) | Ollama -- intelligence summary |
| 15:00 | WF8 (Log Anomaly Finder) | Ollama -- anomaly classification |
| 18:05 | WF2 (Watch Turnover Digest) | Ollama -- narrative generation |

WF5 and WF2 are only 5 minutes apart because WF5 completes its LLM calls before WF2 starts its own. The 3-hour minimum applies to workflows whose GPU usage might overlap.

### Workflow Variables

All credentials, API keys, and service URLs are centralized as **workflow variables** (`$varname`). Shuffle substitutes `$varname` with the actual value at runtime before executing each action. This convention provides three benefits:

1. **No hardcoded secrets** in workflow JSON exports or `execute_python` code blocks -- exported workflows in the repository are safe to share
2. **Single-point credential rotation** -- updating a variable value propagates to every workflow that references it
3. **Clean separation of configuration from logic** -- workflow design focuses on orchestration, not connection strings

Key variables include `$discord_webhook`, `$abuseipdb_key`, `$cf_api_token`, `$thehive_url`, `$thehive_api_key`, `$opensearch_url`, `$ollama_url`, `$ml_scorer_url`, `$elk_url`, `$caldera_url`, and their associated credentials. The full variable inventory is documented in the project reference.

### LLM Integration Details

Five workflows use the Ollama API (brisket:11434) with the `qwen3:8b` model (8 billion parameters). Implementation details that matter for reliability:

**Prompt engineering:**
- All prompts are prefixed with `/no_think` to suppress qwen3's internal chain-of-thought reasoning tokens. Without this prefix, the model emits `<think>...</think>` blocks that consume the token budget without contributing to the output.
- `num_predict` is set to 1000+ to ensure sufficient token budget for substantive analysis even if some reasoning tokens leak through.
- Temperature is set to 0.3 for deterministic, focused output appropriate for security analysis.

**Post-processing:**
- `<think>` tags are stripped from responses using regex post-processing
- Double quotes are replaced and newlines are escaped before delivery to Discord (which has its own Markdown rendering that conflicts with raw LLM output)

**Failure handling:** If Ollama is unavailable (GPU busy, service down), the workflow continues without the LLM component. Alert enrichment and scoring proceed normally -- the LLM provides analyst-facing narrative, not scoring logic.

---

## 5. ML Threat Scoring

### Architecture

The ML pipeline implements a hybrid supervised + unsupervised approach to threat detection:

- **XGBoost binary classifier** -- the primary supervised model, trained on labeled attack and benign traffic
- **IsolationForest anomaly detector** -- an unsupervised model that identifies statistical outliers, providing zero-day coverage for attack patterns not present in training data

The hybrid scoring formula blends both signals: `(1-w) * xgboost_prob + w * isolation_forest_score`, where `w` controls the balance between supervised classification confidence and unsupervised anomaly detection. This ensures that both known attack patterns and novel anomalies contribute to the final threat score.

### Training Data

The model was trained on **1.28 million Wazuh alerts** enriched with Zeek connection metadata and labeled via **13 Caldera adversary emulation campaigns**. Ground truth labels come from two sources:

- **Caldera campaign telemetry** -- the Caldera API provides execution records for each technique run during a campaign, which the `GroundTruthExtractor` module temporally joins against Wazuh alerts to label attack traffic
- **run_attack.sh CSV log** -- manual attacks executed via the logging wrapper produce timestamped CSV records that serve as additional ground truth for the `GroundTruthExtractor`

### Feature Engineering

The pipeline computes **31 behavioral features** across three categories. IP addresses and signature IDs are deliberately excluded to prevent the model from encoding network-specific biases or leaking label information through rule IDs.

| Category | Features | Examples |
|----------|----------|---------|
| Temporal | Alert frequency, inter-arrival time, burst detection | Rapid-fire alerts from a single source indicate automated scanning |
| Zeek connection | conn_state distribution, history flags, service DPI, duration, byte/packet ratios, connection overhead | Unusual conn_state patterns (S0, REJ) suggest scanning; abnormal byte ratios suggest exfiltration |
| Alert context | Rule severity patterns, agent diversity, rule group distributions | Alerts spanning multiple agents suggest lateral movement; clustered severity suggests campaign |

The full pipeline (data extraction, Zeek enrichment, ground truth labeling, feature engineering, model training) is implemented in the separate [soc-ml repository](https://github.com/brianchaplow/soc-ml) and runs on sear using the GTX 1650 Ti GPU.

### Why PR-AUC?

The primary evaluation metric is **PR-AUC (Precision-Recall Area Under Curve)** rather than the more common ROC-AUC. This choice is deliberate and reflects the dataset's class imbalance:

In a SOC environment, benign traffic vastly outnumbers attack traffic (typically 99%+ benign). ROC-AUC can be misleadingly high in imbalanced datasets because it rewards correct classification of the majority class. PR-AUC directly measures the model's ability to find attacks (recall) without generating excessive false positives (precision) -- exactly what a SOC analyst cares about.

The XGBoost binary classifier achieves **PR-AUC 0.9998** on temporal test splits, meaning it correctly identifies nearly all attacks while maintaining near-zero false positive rate.

### Temporal Train/Test Split

Data is split by time, never randomly. This prevents future information from leaking into training -- a critical requirement because attack campaigns have temporal structure. If a random split placed alerts from the middle of a campaign in both train and test sets, the model would learn campaign-specific patterns that do not generalize.

### Deployment

The trained XGBoost model is deployed as a FastAPI service inside a Docker container on brisket (port 5002). The `ml-scorer` container:

- Accepts alert feature vectors via POST request
- Returns threat probability scores (0.0 to 1.0)
- Uses GPU acceleration via the RTX A1000 for inference
- Includes a `_safe_col` fix (deployed 2026-02-18) for robust feature column handling

**Integration points:**
- **Shuffle WF1** sends alerts to the scorer in real time; the combined score (ML + AbuseIPDB) determines response actions
- **Shuffle WF6** runs daily model drift detection by sampling 150 recent alerts, scoring them, and comparing the score distribution against a stored baseline. Drift metrics are written to the `ml-drift` index in ELK for trend analysis

### Six Models Trained

The training pipeline evaluates multiple algorithms before selecting the best performer:

| Model | Type | Purpose |
|-------|------|---------|
| XGBoost | Gradient boosted trees | Primary classifier (best PR-AUC) |
| LightGBM | Gradient boosted trees | Fast alternative for comparison |
| Random Forest | Ensemble | Baseline ensemble method |
| Logistic Regression | Linear | Baseline linear method |
| IsolationForest | Unsupervised anomaly | Zero-day detection component |
| Hybrid (XGBoost + IF) | Blended | Production deployment model |

XGBoost consistently outperforms the alternatives on PR-AUC, which is why it serves as the primary scorer. The IsolationForest component is retained in the hybrid for its ability to flag anomalies that fall outside the supervised model's training distribution.

---

## 6. Incident Response and Case Management

### TheHive 4 -- Case Management

TheHive runs on pitcrew LXC 200 (10.10.30.22, 4 vCPU, 8 GB RAM) and serves as the central case management platform for the SOC. It follows the **NIST 800-61 Computer Security Incident Handling Guide** lifecycle:

1. **Preparation** -- case templates with pre-defined task checklists
2. **Detection and Analysis** -- automated case creation from Shuffle WF1 with enrichment data pre-populated
3. **Containment, Eradication, Recovery** -- structured task tracking through response phases
4. **Post-Incident Activity** -- after-action review documentation, lessons learned, MTTD/MTTR calculation

**Automated case creation:** When Shuffle WF1 determines that an alert warrants investigation (combined score exceeds threshold), it creates a TheHive case via the REST API. The case includes the original Wazuh alert, AbuseIPDB reputation data, ML scorer output, and the LLM-generated triage summary. Task templates based on NIST 800-61 sections are applied automatically.

**Workflow integration:** Four Shuffle workflows interact with TheHive:
- WF1 creates cases for high-scoring alerts
- WF2 queries recent cases for the watch turnover digest
- WF3 creates cases for detection gaps identified after Caldera campaigns
- WF5 links alert clusters to existing cases or creates new ones

### Cortex 3 -- Automated Analysis

Cortex runs alongside TheHive on the same LXC and provides automated observable enrichment through five configured analyzers:

| Analyzer | Function | Status |
|----------|----------|--------|
| AbuseIPDB_1_0 | IP reputation lookup (confidence score, report count) | Operational |
| VirusTotal_GetReport_3_1 | File, URL, and hash reputation checking | Configured (needs production API key) |
| Shodan_DNSResolve_2_0 | DNS resolution and internet-facing host exposure | Configured (needs production API key) |
| Abuse_Finder_3_0 | Abuse contact lookup for IPs and domains | Operational |
| GoogleDNS_resolve_1_0_0 | DNS resolution via Google public DNS (8.8.8.8) | Operational |

Analysts can trigger analyzers directly from TheHive's observable panel. When investigating an IP address in a case, a single click runs all applicable analyzers and displays results inline. AbuseIPDB, Abuse Finder, and Google DNS are fully operational. VirusTotal and Shodan are configured and ready for production API key provisioning.

### Velociraptor v0.75.3 -- DFIR

Velociraptor provides endpoint visibility and forensic artifact collection across the SOC. The server runs as a Docker container on brisket (port 8889 for GUI, 8000/8001 for client communication).

**Enrolled clients:**

| Client | Host | OS | VLAN |
|--------|------|----|------|
| 1 | brisket | Ubuntu 24.04 | 20 |
| 2 | smokehouse | QTS (QNAP) | 20 |
| 3 | sear | Kali Linux | 20 |
| 4 | DC01 | Windows Server 2022 | 30 |
| 5 | WS01 | Windows 10 | 30 |
| 6 | DVWA | Debian | 40 |
| 7 | GCP VM | Ubuntu (GCP) | External |

**Capabilities:**
- **Live artifact collection** -- process listings, file system metadata, network connections, registry hives, browser history, event logs
- **VQL (Velociraptor Query Language)** -- a SQL-like query language for ad hoc forensic investigations across any enrolled endpoint
- **Hunt groups** -- fleet-wide artifact sweeps when a threat indicator (file hash, process name, registry key) needs to be checked across all endpoints simultaneously
- **Timeline analysis** -- correlating endpoint artifacts with Wazuh alerts and Zeek network data for comprehensive incident reconstruction

**Planned integration:** WF4 (Velociraptor Triage) will automate artifact collection triggered by high-severity TheHive cases, reducing the manual steps between case creation and forensic evidence gathering.

### After-Action Process

Every significant incident follows NIST 800-61 Section 3.4 (Post-Incident Activity):

- **Root cause documentation** -- what vulnerability or misconfiguration allowed the incident
- **Detection effectiveness** -- did the SOC detect the activity? How quickly? What signals were missed?
- **Response timeline** -- MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond) calculated per case
- **Lessons learned** -- what detection rules, SOAR logic, or response procedures need updating
- **Intelligence contribution** -- findings fed back into Wazuh rules, Elastic detection rules, ML model retraining, and Caldera profile updates

---

## 7. Adversary Emulation and Validation

### MITRE Caldera v5.3.0

Caldera runs on smoker (10.10.30.21:8888) and provides automated adversary emulation using MITRE ATT&CK techniques. It manages four Sandcat agents deployed to targets:

| Agent | Host | VLAN | OS |
|-------|------|------|----|
| Sandcat | DC01 | 30 | Windows Server 2022 |
| Sandcat | WS01 | 30 | Windows 10 |
| Sandcat | DVWA | 40 | Debian |
| Sandcat | Metasploitable | 40 | Ubuntu |

**29 MITRE ATT&CK adversary profiles** are configured, mapping to real-world threat actor TTPs. These profiles serve three purposes:

1. **Detection validation** -- after deploying new Wazuh rules or Elastic detection rules, Caldera campaigns verify that the expected techniques actually trigger alerts
2. **ML training data generation** -- Caldera campaigns produce labeled attack traffic that the `GroundTruthExtractor` uses to label Wazuh alerts for model training
3. **Coverage measurement** -- Shuffle WF3 (Detection Gap Analyzer) compares Caldera campaign telemetry against Wazuh alert data to calculate detection coverage percentages

**Campaign configuration requirements:**
- `auto_close: false` -- prevents premature campaign termination before all techniques execute
- `source: basic` -- references the default fact source for agent discovery
- `group: "targets"` -- ensures execution on the correct agent group
- Full adversary UUIDs must be used (truncated UUIDs cause 0-link failures)

### Ground-Truth Logging with run_attack.sh

All manual attacks (those not executed via Caldera) use the `run_attack.sh` wrapper script. This script logs every attack execution to a CSV file with timestamps, attack type, target IP, and parameters.

```
./run_attack.sh <attack_type> <target_ip> [additional_args]
```

The script supports **200+ attack types** covering network scanning, web application attacks, credential attacks, exploitation, and post-exploitation techniques. All attacks MUST target VLAN 40 (10.10.40.0/24) exclusively -- this is enforced by convention and verified during review.

The CSV ground-truth log feeds the ML pipeline's `GroundTruthExtractor`, which temporally joins attack records against Wazuh alerts to produce training labels. This creates a closed loop: attacks generate labeled data, labeled data trains the model, the model scores future alerts.

### Purple Team Closed Loop

The adversary simulation workflow follows a five-step closed loop that continuously improves the SOC's detection and response capabilities:

```
Execute --> Detect --> Measure --> Improve --> Retrain
   |                                             |
   +---------------------------------------------+
```

1. **Execute** -- run Caldera campaigns or manual attacks via `run_attack.sh` against VLAN 40 targets
2. **Detect** -- verify that Wazuh alerts and/or Elastic detection rules fire for each technique executed
3. **Measure** -- Shuffle WF3 correlates Caldera campaign telemetry with Wazuh alert data to calculate detection coverage percentage per technique and per tactic
4. **Improve** -- write new Wazuh custom rules, tune Suricata signatures, or author new Elastic detection rules to close identified gaps
5. **Retrain** -- feed the newly labeled attack data into the ML pipeline on sear, producing updated XGBoost models that incorporate the latest attack patterns

This is not a one-time exercise. Each Caldera campaign or manual attack run generates new training data, validates existing detection coverage, and identifies gaps. The cycle repeats continuously.

---

## 8. Honeypot Research

### Deployment

A WordPress login honeypot runs on a **GCP VM** (Google Cloud, us-east4 region) as part of the INST 570 cybersecurity research project. The honeypot presents a fake WordPress `/wp-login.php` page to internet attackers, capturing credential stuffing attempts, automated bot traffic, and attack tool fingerprints.

The GCP VM serves dual purposes:
- **Public-facing sites** -- brianchaplow.com and bytesbourbonbbq.com behind Cloudflare CDN/WAF
- **Honeypot research** -- the PHP credential capture honeypot on a separate Apache virtual host

### Data Pipeline

Honeypot data flows from the GCP VM to the ELK stack on pitcrew LXC 201 via two independent pipelines:

**Fluent Bit pipeline (real-time):**
- PHP honeypot writes credential capture events to `/var/log/honeypot/credentials.json`
- Apache logs honeypot virtual host access to `/var/log/apache2/honeypot-access.log`
- Fluent Bit on the GCP VM ships both log streams to Elasticsearch on ELK LXC 201 using the `es` output plugin
- Transport runs over the **Tailscale overlay network** (WireGuard mesh), requiring zero inbound port exposure on the home network

**Wazuh sync pipeline (cron-based):**
- Wazuh agent 009 on the GCP VM ships OS-level security events to brisket's Wazuh Manager
- A cron job on brisket (`honeypot-wazuh-sync.py`, every 15 minutes) copies agent 009 alerts from Wazuh's OpenSearch to the `honeypot-wazuh` index in ELK
- The sync uses Wazuh document `_id` as the Elasticsearch `_id`, making it idempotent -- re-runs never create duplicate records

### Research Indices

| Index | Source | Records | Content |
|-------|--------|---------|---------|
| `honeypot-credentials` | Fluent Bit | ~3,140 | Username/password pairs from credential stuffing attempts |
| `honeypot-access` | Fluent Bit | ~737 | Apache access logs for the honeypot virtual host |
| `honeypot-wazuh` | Cron sync | ~5,925 | Wazuh alerts for GCP VM (rule triggers, MITRE ATT&CK mappings) |
| `apache-parsed-v2` | Fluent Bit | -- | Portfolio and blog site access logs with Cloudflare geo fields |

### Kibana Dashboard

The **Honeypot Research Dashboard -- INST 570** contains **15 visualization panels** built programmatically via the Kibana saved objects API:

- Credential capture volume over time (date histogram)
- Top attempted usernames and passwords (data tables)
- Source IP geolocation by country (choropleth map)
- Wazuh rule trigger frequency and MITRE ATT&CK technique mapping
- HTTP method and user-agent analysis
- Attack pattern clustering by time-of-day and day-of-week
- Unique source IP count trends

The dashboard builder script generates Kibana saved objects programmatically, ensuring reproducibility across ELK redeployments.

### Shuffle Integration

- **WF7 (Honeypot Intel Report)** -- runs weekly on Sundays at 12:00 EST. Queries all three honeypot indices, computes statistics (top credentials, source countries, attack volume trends), and generates an LLM-authored intelligence summary delivered to Discord. Reports are also indexed to `honeypot-intel` in ELK for historical tracking.
- **WF8 (LLM Log Anomaly Finder)** -- includes honeypot-wazuh patterns in its daily rare alert classification, catching unusual attacker behavior that standard signatures miss.

### Tailscale Overlay Network

The GCP VM has no direct route to the home network's RFC 1918 address space (10.10.x.x). Tailscale provides a WireGuard-based mesh VPN that:

- Assigns each node a stable 100.x.x.x address with automatic NAT traversal
- Requires no port forwarding or public exposure of ELK services
- Advertises no subnet routes -- only point-to-point peer connections between the GCP VM and ELK LXC 201
- Encrypts all data in transit with WireGuard (ChaCha20-Poly1305)

This design ensures that the honeypot research pipeline operates without exposing any internal lab services to the internet.

---

## 9. Network Security Design

### VLAN Segmentation

The network is divided into five 802.1Q VLANs, each serving a distinct security function. All inter-VLAN traffic routes through OPNsense, where stateful packet filtering enforces explicit policy. No VLAN can communicate with another unless a firewall rule explicitly permits it.

| VLAN | Subnet | Purpose | Security Posture |
|------|--------|---------|-----------------|
| 10 | 10.10.10.0/24 | Management | Firewall, switch, admin workstation -- restricted access from other VLANs |
| 20 | 10.10.20.0/24 | SOC Infrastructure | SIEM, SOAR, sensors, ML, LLM -- the operational core |
| 30 | 10.10.30.0/24 | Lab / Proxmox / AD | Hypervisors, AD domain, TheHive, ELK, backup -- service tier |
| 40 | 10.10.40.0/24 | Targets (ISOLATED) | Attack surfaces only -- fully isolated, deny-all outbound |
| 50 | 10.10.50.0/24 | IoT | Internet-only access, no lateral movement to any internal VLAN |

An additional family network (192.168.100.0/24 DMZ + 192.168.50.0/24 LAN) connects via a dedicated OPNsense physical interface (igc3) to an ASUS consumer router. This creates a hard physical and logical boundary between SOC operations and family internet usage.

### OPNsense Firewall

OPNsense runs on a Protectli VP2420 appliance (Intel J6412, 8 GB RAM, 128 GB eMMC) with four Intel NICs:

| NIC | Function | Connection |
|-----|----------|-----------|
| igc0 | 802.1Q trunk (all 5 VLANs) | MokerLink switch |
| igc1 | WAN (DHCP from ISP) | Verizon uplink |
| igc3 | Family network handoff | ASUS router (192.168.100.1/24) |

**Key firewall policies:**

- **VLAN 40 deny-all outbound** -- the cornerstone of the security architecture. Target hosts cannot initiate connections to any other VLAN or the internet. Only established/related return traffic (responses to inbound attack connections from VLAN 20 or VLAN 30) is permitted. This ensures that compromised targets cannot pivot to production infrastructure or exfiltrate data.

- **VLAN 50 internet-only** -- IoT devices can reach the internet for firmware updates and cloud services, but have zero visibility or access to any internal VLAN. No lateral movement is possible.

- **VLAN 20 to VLAN 30 bidirectional** -- SOC tools on VLAN 20 (brisket) need to communicate with lab services on VLAN 30 (TheHive, ELK, Caldera, Proxmox management). The reverse path allows TheHive and ELK to report back to Wazuh and Shuffle.

- **VLAN 20 and VLAN 30 to VLAN 40** -- both the SOC and lab VLANs can initiate connections to targets for attacks and management, but targets can never initiate back.

- **OPNsense syslog** -- firewall events are forwarded to Wazuh via UDP 514, providing visibility into inter-VLAN routing decisions, blocked connections, and NAT translations.

### MokerLink ACL Micro-Segmentation

**The problem:** sear (10.10.20.20, Kali attack box) and brisket (10.10.20.30, SOC platform) are both on VLAN 20. Intra-VLAN traffic is Layer 2 switched -- it never routes through OPNsense, so firewall rules do not apply. Without additional controls, a compromised sear could access every service on brisket (Shuffle SOAR, Grafana, Wazuh Dashboard, Velociraptor, and more).

**The solution:** The MokerLink 10G08410GSM L3 managed switch supports IPv4 ACLs bound to physical ports. A 9-rule stateless ACL (`sear-brisket`) is bound to TE4 (sear's physical switch port), filtering all traffic between the two hosts at the switch level.

**Permitted flows (sear to brisket):**
| Port | Purpose |
|------|---------|
| TCP 1514 | Wazuh agent event transport |
| TCP 1515 | Wazuh agent enrollment |
| TCP 9200 | OpenSearch queries (ML pipeline data extraction) |

**Permitted flows (brisket to sear):**
| Port | Purpose |
|------|---------|
| TCP 9100 | Prometheus node_exporter scrape |
| TCP 22 | SSH management |

**Everything else is denied.** sear cannot reach Shuffle (3443), Grafana (3000), Wazuh Dashboard (5601), Velociraptor (8889), the ML Scorer (5002), or Ollama (11434) on brisket.

**Stateless ACL nuance:** Unlike OPNsense's stateful firewall, switch ACLs do not track TCP connections. A SYN and its SYN-ACK are evaluated independently. This means every brisket-initiated connection to sear requires two rules: one for the outbound request (matching destination port) and one for the inbound return (matching source port). Without the return-path rule, the SYN-ACK from sear hits the deny-all before reaching the catch-all permit.

### Defense-in-Depth Layers

The SOC implements six overlapping security boundaries. An attacker must defeat multiple independent layers to move from initial access to objective:

**Layer 1 -- Perimeter (OPNsense)**
Stateful firewall on all inter-VLAN traffic. NAT for outbound internet access. Syslog forwarding to Wazuh for firewall event visibility. The first barrier any east-west or north-south traffic encounters.

**Layer 2 -- Network Segmentation (VLANs)**
Five VLANs isolate functional zones. VLAN 40 is fully isolated. VLAN 50 is internet-only. The family network is physically separated. Each zone has explicit policy governing what it can and cannot reach.

**Layer 3 -- Switch ACL Micro-Segmentation (MokerLink)**
Stateless ACLs on sear's switch port restrict intra-VLAN access to brisket. This layer covers the blind spot where Layer 2 switching bypasses the OPNsense firewall entirely.

**Layer 4 -- Host-Level Controls**
Wazuh agents on all 10 endpoints provide file integrity monitoring, vulnerability scanning, and security configuration assessment. Suricata inspects all network traffic via SPAN with 47,487+ signatures. Zeek extracts protocol-level metadata for behavioral analysis.

**Layer 5 -- Detection and Response**
214 Elastic Security detection rules cover MITRE ATT&CK tactics. 7 Shuffle SOAR workflows automate enrichment, triage, and response. TheHive and Cortex manage cases with 5 threat intelligence analyzers. Velociraptor provides endpoint forensics across 7 clients.

**Layer 6 -- AI/ML Augmentation**
XGBoost threat scorer (PR-AUC 0.9998) provides real-time behavioral classification. Ollama LLM (qwen3:8b) generates analyst-facing triage narratives, anomaly classifications, and intelligence reports. WF6 monitors model drift to ensure ML accuracy over time. WF8 catches patterns that rule-based detection misses.

### Docker Targets on VLAN 40

Six Docker containers on smoker serve as attack targets using **ipvlan L2 networking** on vmbr0v40 (the VLAN 40 bridge). This networking mode places each container directly on the 10.10.40.0/24 subnet with its own routable IP address, while the smoker host itself remains on VLAN 30 (10.10.30.21).

| Container | IP | Service |
|-----------|-----|---------|
| WordPress | 10.10.40.30 | WPScan target |
| crAPI | 10.10.40.31 | REST API security target |
| vsftpd | 10.10.40.32 | FTP exploitation target |
| Honeypot | 10.10.40.33 | WAF evasion target |
| SMTP relay | 10.10.40.42 | SMTP target |
| SNMPd | 10.10.40.43 | SNMP target |

**Why ipvlan L2?** Standard Docker bridge networking would require NAT, placing all containers behind smoker's VLAN 30 IP and breaking the isolation model. ipvlan L2 assigns each container a real VLAN 40 IP that is subject to OPNsense's deny-all outbound rule, maintaining the isolation guarantee. Attackers interact with targets at their real network addresses, producing realistic traffic patterns that Suricata and Zeek capture accurately on the SPAN port.

---

*This document describes the HomeLab SOC v3 platform as of March 2026. For component-specific details, configuration files, and deployment instructions, see the individual component READMEs in this repository. For questions about this lab or its architecture, contact Brian Chaplow via [GitHub](https://github.com/brianchaplow).*
