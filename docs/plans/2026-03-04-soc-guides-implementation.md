# SOC Analyst Guides Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create two comprehensive SOC reference documents — a portfolio overview for reviewers and an operational playbook for hands-on analysts.

**Architecture:** Two standalone markdown files in `docs/guides/`. The portfolio overview tells the narrative story of the SOC with enough operational detail to prove competence. The SOC playbook is a pure operational handbook with copy-paste commands, step-by-step procedures, and scenario runbooks. Both reference the same underlying infrastructure documented in the repo.

**Tech Stack:** Markdown documentation. Content sourced from repo configs, workflow JSONs, architecture docs, and CLAUDE.md project reference.

---

## Phase 1: Portfolio Overview

### Task 1: Portfolio Overview — Header, Architecture, and Alert Lifecycle

**Files:**
- Create: `docs/guides/portfolio-overview.md`

**Step 1: Write sections 1-2**

Create `docs/guides/portfolio-overview.md` with:

**Section 1 — SOC Architecture at a Glance:**
- Title and introduction (what this SOC is, why it exists)
- Key metrics summary table: 10 Wazuh agents, 214 Elastic detection rules, PR-AUC 0.9998, 7 Velociraptor clients, 8 SOAR workflows (7 with LLM), 29 MITRE ATT&CK profiles, 12 Docker containers on brisket
- Technology stack table: Wazuh 4.14.2, Elasticsearch 8.17, Shuffle SOAR, TheHive 4, Cortex 3, Velociraptor 0.75.3, Caldera 5.3.0, XGBoost ML, Ollama qwen3:8b
- Hardware inventory summary: 8 physical hosts, 176 GB cluster RAM, 12 GB GPU VRAM (RTX A1000 8GB + GTX 1650 Ti 4GB)
- High-level data flow narrative: Endpoints -> Sensors -> SIEM -> SOAR -> Response (with Mermaid or text diagram)

**Section 2 — The Alert Lifecycle (End-to-End):**
Trace a real alert through the full lifecycle with these subsections:
- **Detection:** Suricata IDS on smokehouse SPAN port (eth4) fires on SQL injection payload -> eve.json -> Wazuh agent ships to Manager -> decoded/rule-matched -> alert created with rule.id/level/MITRE -> indexed in OpenSearch `wazuh-alerts-4.x-YYYY.MM.DD`. Parallel: Zeek captures HTTP flow metadata -> Fluent Bit -> `zeek-http` index.
- **Automated Enrichment:** Alert level 8+ triggers Shuffle WF1 webhook -> AbuseIPDB lookup (confidence score, reports, country, ISP) + ML Scorer POST to brisket:5002 (returns ml_score 0-1, ml_label, top features) + Ollama qwen3:8b generates 1-2 sentence triage summary.
- **Scoring Decision:** `combined_score = max(abuse_normalized, ml_score)`. Block decision: abuse >= 90 AND reports >= 5 AND NOT whitelisted. Alert decision: combined >= 0.7 OR rule_level >= 10.
- **Case Creation:** TheHive case auto-created via Shuffle with title, enrichment context, severity mapping, TLP-AMBER, tags. NIST 800-61 task structure: Identification, Containment, Eradication, Recovery, Lessons Learned.
- **Investigation:** Velociraptor artifact collection on affected endpoint (processes, network connections, file hashes, persistence). Zeek flow correlation (5-tuple + timestamp join). Cortex analyzers (VirusTotal for hashes, Shodan for IPs).
- **Response:** Cloudflare IP block (firewall access rule). Endpoint isolation via Velociraptor. Document all actions in TheHive case tasks.
- **Closure & After-Action:** Root cause documented. IOCs entered as observables. Detection rules updated. After-action report (NIST 800-61 Sec 3.4): timeline, root cause, impact, improvements, MTTD/MTTR metrics.
- **Intelligence Loop:** WF2 watch digest captures in next shift turnover. WF5 daily triage classifies cluster. WF8 checks for related anomalies. WF6 monitors if new attack type causes model drift.

**Step 2: Verify content accuracy**

Cross-reference all IPs, ports, workflow details, and scoring logic against:
- `shuffle/workflows/wf1-threat-enrichment.json` (scoring logic)
- `wazuh/configs/ossec.conf` (integration level 8+)
- `docs/architecture.md` (hardware specs)
- CLAUDE.md (credentials, service inventory)

**Step 3: Commit**

```bash
git add docs/guides/portfolio-overview.md
git commit -m "Add portfolio overview: architecture and alert lifecycle sections"
```

---

### Task 2: Portfolio Overview — Detection Engineering and SOAR/LLM

**Files:**
- Modify: `docs/guides/portfolio-overview.md`

**Step 1: Write sections 3-4**

**Section 3 — Detection Engineering:**
- Dual-SIEM architecture rationale: Wazuh (opinionated integrated platform — manager/agents/rules/dashboard tightly coupled) vs Elastic (flexible query-driven — KQL/EQL, pre-built rules, ML jobs). Why both: interview differentiator, resilience, comparison experience.
- Wazuh detection: 10 agents across 5 VLANs + GCP. Agent enrollment via wazuh-authd (:1515). Alert levels 0-15. Custom rules (local_rules.xml, IDs 100000+). Custom decoders for non-standard log formats. FIM (syscheck) every 12h. SCA compliance checks. Vulnerability detection with hourly feed updates.
- Network detection: Suricata IDS on smokehouse SPAN (47,487 ET Open rules + custom SIDs 9000001-9000021 for SQL injection, XSS, command injection, directory traversal). Zeek NSM producing 7 index types (conn, dns, http, ssl, files, notice, weird).
- ELK detection: 214 enabled rules (of 1,419 total) mapped to MITRE ATT&CK. Breakdown: Defense Evasion 57, Credential Access 45, Execution 38, Persistence 31, Privilege Escalation 29, Lateral Movement 21. Rules run on 5-minute intervals querying logs-* indices.
- OPNsense syslog: Firewall events via UDP 514, decoded by Wazuh.

**Section 4 — SOAR & LLM Automation:**
- Shuffle architecture: Frontend (:3443), Backend (:5001), Orborus (worker spawner), OpenSearch (:9202 internal state). All on brisket.
- Workflow inventory table: WF1 (real-time enrichment, webhook), WF2 (watch digest, 0605/1805 EST), WF3 (detection gaps, on-demand), WF5 (cluster triage, 0600 EST), WF6 (model drift, 0900 EST), WF7 (honeypot intel, Sun 1200 EST), WF8 (anomaly finder, 1500 EST).
- Scheduling architecture: Shuffle's native scheduler is interval-based (seconds), not cron. Precise wall-clock execution uses system cron on brisket with `curl POST` to `/api/v1/workflows/{id}/execute`.
- Workflow variable convention: All credentials use `$varname` substitution. Never hardcoded. Safe for repo export.
- Ollama integration patterns: qwen3:8b model, `/no_think` prefix suppresses reasoning tokens, `<think>` tags stripped via regex, temperature 0.3, `num_predict` 1000-3000.
- GPU scheduling: 3+ hour stagger between Ollama-heavy workflows to avoid RTX A1000 contention. Schedule: 0600 WF5, 0605 WF2, 0900 WF6, 1200 WF7, 1500 WF8, 1805 WF2.
- Real-time vs scheduled: WF1 is event-driven (webhook). All others are cron-scheduled or on-demand.

**Step 2: Commit**

```bash
git add docs/guides/portfolio-overview.md
git commit -m "Add portfolio overview: detection engineering and SOAR/LLM sections"
```

---

### Task 3: Portfolio Overview — ML, IR, Adversary Sim, Honeypot, Network

**Files:**
- Modify: `docs/guides/portfolio-overview.md`

**Step 1: Write sections 5-9**

**Section 5 — ML Threat Scoring:**
- Architecture: XGBoost supervised classifier + IsolationForest anomaly detector. Hybrid score: `(1-w) * xgboost_prob + w * isolation_score`.
- Training data: 1.28M alerts from Wazuh indices. Labels from 13 Caldera campaigns (3,868 attack-labeled) + manual red-team logs via run_attack.sh.
- 102 behavioral features across 6 categories: alert metadata (~15), temporal (~10), agent behavioral (~15), Zeek network (~31, join rate ~20%), anomaly meta (~5), interaction/derived (~26). No IP-based features (avoids topology bias).
- Temporal train/test split: All training samples precede test samples chronologically. Prevents data leakage.
- PR-AUC 0.9998: Chosen over ROC-AUC because dataset is heavily imbalanced (benign >> attack). PR-AUC finds needles in haystacks.
- 6 models trained: XGBoost, LightGBM, RandomForest, LogisticRegression, IsolationForest, SelfTrainingClassifier.
- Deployment: FastAPI container ml-scorer on brisket:5002. GPU-accelerated (RTX A1000). Health check at `/health`.
- Drift monitoring: WF6 daily samples ~200 alerts, compares distribution vs baseline, classifies STABLE/MINOR_DRIFT/SIGNIFICANT_DRIFT.
- Training code in separate repo: github.com/brianchaplow/soc-ml.

**Section 6 — Incident Response & Case Management:**
- TheHive 4 on pitcrew LXC 200 (10.10.30.22:9000). Case lifecycle aligned to NIST 800-61.
- Cortex 3 on same LXC (10.10.30.22:9001). 5 analyzers: AbuseIPDB (fully operational), VirusTotal (needs API key), Shodan (needs API key), Abuse Finder (operational), GoogleDNS (operational).
- Velociraptor v0.75.3 on brisket (GUI :8889, client frontend :8000, gRPC :8001). 7 enrolled clients across all host types. VQL for live forensic artifact collection.
- Integration: Shuffle WF1 auto-creates cases. WF5 creates TheHive alerts for INVESTIGATE clusters. WF3 creates cases for detection gap reports.
- After-action process: NIST 800-61 Section 3.4 template. MTTD/MTTR metrics tracked per case.

**Section 7 — Adversary Emulation & Validation:**
- Caldera v5.3.0 on smoker (10.10.30.21:8888). 4 Sandcat agents (DC01, WS01, DVWA, Metasploitable 3).
- 29 MITRE ATT&CK adversary profiles for validating detection coverage.
- run_attack.sh: 200+ attack types across 15+ categories. CSV ground-truth logging with attack_id, timestamps, MITRE technique, tool, source/target IPs, success flag. All attacks originate from sear (10.10.20.20), target VLAN 40 only.
- Purple team closed loop: Execute (Caldera/manual) -> Detect (Wazuh alerts) -> Measure (WF3 coverage %) -> Improve (write rules) -> Retrain (ML pipeline).
- VLAN 40 isolation: Targets cannot initiate outbound. All attack traffic contained.

**Section 8 — Honeypot Research:**
- GCP WordPress honeypot (INST 570 course project). PHP wp-login.php trap captures credentials.
- Data pipeline: Fluent Bit ships credentials.json + Apache access logs to ELK LXC 201 via Tailscale overlay. Wazuh agent 009 ships OS events to brisket, synced to ELK via honeypot-wazuh-sync.py (cron */15).
- 3 ELK indices: honeypot-credentials (~3,140), honeypot-access (~737), honeypot-wazuh (~5,925).
- 15-panel Kibana dashboard (programmatically built): geographic map, credential word clouds, MITRE technique breakdown, attacker profiles.
- WF7 weekly intelligence reports (Ollama-generated CTI analysis).
- Tailscale: GCP VM connects via WireGuard mesh (100.x.x.x). No inbound port exposure on home network.

**Section 9 — Network Security Design:**
- 5 VLANs: 10 (Management), 20 (SOC), 30 (Lab/Proxmox/AD), 40 (Targets-ISOLATED), 50 (IoT).
- OPNsense firewall (Protectli VP2420): Stateful inter-VLAN routing policy. VLAN 40 deny-all-outbound. VLAN 50 internet-only.
- MokerLink 10G managed switch: SPAN mirror on TE10 -> smokehouse eth4. 9-rule stateless ACL on TE4 (sear) for intra-VLAN micro-segmentation — permits only Wazuh (1514/1515), OpenSearch (9200), Velociraptor (8000), Prometheus (9100), SSH (22); denies all else.
- Defense-in-depth layers: Perimeter (OPNsense) -> Segmentation (VLANs) -> Micro-segmentation (ACLs) -> Host (Wazuh agents, FIM, SCA) -> Detection (214 rules, Suricata, Zeek) -> AI/ML (XGBoost, Ollama).
- Docker target networking: ipvlan L2 on vmbr0v40 (VLAN 40 bridge) places containers directly on isolated subnet without NAT.

**Step 2: Commit**

```bash
git add docs/guides/portfolio-overview.md
git commit -m "Add portfolio overview: ML, IR, adversary sim, honeypot, network sections"
```

---

## Phase 2: SOC Playbook — Core Operations

### Task 4: SOC Playbook — Quick Access Reference and Daily Checklist

**Files:**
- Create: `docs/guides/soc-playbook.md`

**Step 1: Write sections 1-2**

**Section 1 — Quick Access Reference:**

Service access table with every URL, port, credential:

| Service | URL | User | Password |
|---------|-----|------|----------|
| Wazuh Dashboard | https://10.10.20.30:5601 | admin | <PLATFORM_PASSWORD> |
| Wazuh API | https://10.10.20.30:55000 | wazuh-wui | <WAZUH_API_PASSWORD> |
| OpenSearch (Wazuh) | https://10.10.20.30:9200 | admin | (in .env) |
| Shuffle SOAR | https://10.10.20.30:3443 | admin | <PLATFORM_PASSWORD> |
| Shuffle API | http://10.10.20.30:5001 | — | API key: <SHUFFLE_API_KEY> |
| TheHive | http://10.10.30.22:9000 | socadmin@thehive.local | <PLATFORM_PASSWORD> |
| Cortex | http://10.10.30.22:9001 | socadmin@SOC | <PLATFORM_PASSWORD> |
| Velociraptor | https://10.10.20.30:8889 | admin | <PLATFORM_PASSWORD> |
| Caldera | http://10.10.30.21:8888 | red | <PLATFORM_PASSWORD> |
| ELK Kibana | http://10.10.30.23:5601 | elastic | <PLATFORM_PASSWORD> |
| ELK Elasticsearch | https://10.10.30.23:9200 | elastic | <PLATFORM_PASSWORD> |
| Grafana | http://10.10.20.30:3000 | admin | (same as OpenSearch) |
| Prometheus | http://10.10.20.30:9090 | — | — |
| ML Scorer | http://10.10.20.30:5002 | — | — |
| Ollama | http://10.10.20.30:11434 | — | — |

SSH commands table (LAN + Tailscale variants).

**Section 2 — Daily Operations Checklist:**

Shift start procedure:
1. Check Discord channels for overnight WF2 digest, WF8 anomalies, WF1 alerts
2. Verify Wazuh agent health: `curl -k -u wazuh-wui:'<WAZUH_API_PASSWORD>' https://10.10.20.30:55000/agents?status=active` — expect 10 agents
3. Check Shuffle workflow status: https://10.10.20.30:3443 -> Workflows -> verify last execution times match schedules
4. Review open TheHive cases: `curl -u socadmin@thehive.local:'<PLATFORM_PASSWORD>' http://10.10.30.22:9000/api/case?range=0-20&sort=-createdAt`
5. Check Grafana SOC v3 Overview: http://10.10.20.30:3000 -> CPU, memory, alert rates
6. Verify ELK containers running: `ssh root@10.10.30.20` then `pct exec 201 -- docker ps` — expect elasticsearch, kibana, fleet-server, logstash
7. Check ML Scorer health: `curl http://10.10.20.30:5002/health`
8. Check Velociraptor client status: https://10.10.20.30:8889 -> Clients -> verify 7 clients

**Step 2: Commit**

```bash
git add docs/guides/soc-playbook.md
git commit -m "Add SOC playbook: quick access reference and daily checklist"
```

---

### Task 5: SOC Playbook — Working with Alerts

**Files:**
- Modify: `docs/guides/soc-playbook.md`

**Step 1: Write section 3**

**Section 3 — Working with Alerts:**

**3.1 Alert Severity Scale:**
- Levels 0-2: Informational (not logged)
- Levels 3-4: Low (logged to alerts.log only)
- Levels 5-7: Medium (logged, visible in dashboard)
- Levels 8-11: High (forwarded to Shuffle WF1 webhook)
- Levels 12-15: Critical (email alert if enabled)

**3.2 Wazuh Dashboard Navigation:**
- Login: https://10.10.20.30:5601 -> admin / <PLATFORM_PASSWORD>
- Modules -> Security Events: real-time alert stream
- Filter by: agent.name, rule.level, rule.id, data.srcip, @timestamp
- Click any alert row to expand full JSON details
- Agents tab: connection status, per-agent alert history

**3.3 OpenSearch Query Templates (copy-paste ready):**

Provide 15+ complete curl commands with JSON bodies:
1. Last hour alerts
2. Alerts by source IP
3. Alerts by destination IP
4. Alerts by rule ID
5. Alerts by agent name
6. Critical alerts (level 12+)
7. High alerts (level 8+)
8. MITRE technique aggregation
9. Top source IPs (last 24h)
10. Top rules fired (last 24h)
11. Authentication failures
12. File integrity changes (syscheck)
13. Vulnerability detections
14. Zeek HTTP requests by source IP
15. Zeek DNS queries for specific domain
16. Zeek connection flows between two IPs
17. Alerts with specific MITRE technique ID

Each query as a complete curl command:
```bash
curl -k -u admin:'PASSWORD' -X GET "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{...}'
```

**3.4 ELK Elasticsearch Queries:**

10+ queries against ELK (10.10.30.23:9200):
1. All detection rule alerts (last 24h)
2. Alerts by MITRE tactic
3. Alerts by agent hostname
4. Windows security events (Event ID filter)
5. Linux auth events
6. Fleet agent status
7. Honeypot credential captures (last 7d)
8. Honeypot attacker IPs by country
9. Honeypot MITRE techniques
10. Events by data stream dataset

**3.5 Reading Shuffle WF1 Execution History:**
- Navigate: https://10.10.20.30:3443 -> Workflows -> WF1 Threat Enrichment
- Click "Executions" -> select execution by timestamp
- Each node shows: input JSON, output JSON, status (success/failure/skipped)
- Key nodes to check: parse_alert (was it external?), evaluate_score (what was combined_score?), cloudflare_block (did it fire?), thehive_case (was case created?)

**Step 2: Commit**

```bash
git add docs/guides/soc-playbook.md
git commit -m "Add SOC playbook: working with alerts and query templates"
```

---

### Task 6: SOC Playbook — Triage, Escalation, and Investigation

**Files:**
- Modify: `docs/guides/soc-playbook.md`

**Step 1: Write sections 4-5**

**Section 4 — Triaging & Escalating Alerts:**

**4.1 Interpreting ML Scores:**
- Score 0.0-0.3: Low risk, likely benign
- Score 0.3-0.7: Moderate, review context
- Score 0.7-0.9: High risk, investigate
- Score 0.9-1.0: Critical, immediate action
- `ml_label`: "malicious" / "benign" / "unknown"
- Top features explain which behavioral indicators drove the score

**4.2 Interpreting AbuseIPDB Enrichment:**
- Confidence score 0-25: Clean
- Confidence score 25-50: Low threat
- Confidence score 50-75: Moderate threat
- Confidence score 75-90: High threat
- Confidence score 90-100: Confirmed malicious
- Reports count: Higher = more community confirmations
- Key fields: country, ISP, domain, usageType, isTor, isPublicProxy

**4.3 Reading Ollama Triage Summaries:**
- Generated by WF1 evaluate_score node
- 1-2 sentence analyst explanation of alert context
- If ml_score >= 0.7: additional ML explanation with top 7 feature analysis
- Temperature 0.3 (deterministic, not creative)

**4.4 Escalation Decision Matrix:**

| Combined Score | Rule Level | Action |
|----------------|------------|--------|
| >= 0.9 | Any | Immediate investigation + case |
| >= 0.7 | >= 10 | Create case, investigate within shift |
| >= 0.7 | < 10 | Create case, investigate within 24h |
| < 0.7 | >= 12 | Create case (rule severity alone warrants) |
| < 0.7 | 8-11 | Monitor, review in WF5 cluster triage |
| < 0.7 | < 8 | Log review only |

**4.5 Creating TheHive Cases Manually:**

Via API:
```bash
curl -H 'Authorization: Bearer <THEHIVE_API_KEY>' \
  -H 'Content-Type: application/json' \
  -X POST http://10.10.30.22:9000/api/case \
  -d '{
    "title": "[Manual] Description of incident",
    "description": "Full context here",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["manual", "source-type"]
  }'
```

Via UI: TheHive -> New Case -> fill severity, TLP, description, tags.

**4.6 Promoting TheHive Alerts to Cases:**
- Shuffle WF5 creates alerts (not cases) for INVESTIGATE items
- In TheHive UI: Alerts tab -> select alert -> "Create Case" button
- Or merge into existing case if related

**Section 5 — Investigating Alerts:**

**5.1 Zeek Flow Correlation:**

Query templates for each Zeek index type with explanation of key fields:
- `zeek-conn`: conn_state (S0=no reply, SF=normal, REJ=rejected), duration, orig_bytes, resp_bytes, history flags
- `zeek-http`: method, host, uri, status_code, user_agent, response_body_len
- `zeek-dns`: query, qtype, rcode, answers
- `zeek-ssl`: server_name (SNI), issuer, subject, validation_status
- `zeek-files`: mime_type, md5, sha1, source, analyzers

Each with full curl query example.

**5.2 Velociraptor Hunts:**

VQL query examples (run via GUI -> Notebooks or Hunt Manager):
- List running processes: `SELECT Pid, Name, CommandLine, Username FROM pslist()`
- Network connections: `SELECT * FROM netstat() WHERE Status = 'ESTABLISHED'`
- File hash check: `SELECT FullPath, Size, Hash FROM glob(globs='/tmp/**') WHERE Hash.SHA256 = 'target_hash'`
- Persistence mechanisms: `SELECT * FROM Artifact.Windows.Sys.StartupItems()`
- Scheduled tasks: `SELECT * FROM Artifact.Windows.System.TaskScheduler()`
- Recent file modifications: `SELECT * FROM glob(globs='/etc/**') WHERE Mtime > timestamp(epoch=now() - 3600)`

**5.3 Running Cortex Analyzers:**

Per-analyzer procedure:
- AbuseIPDB: Observable type=ip -> returns confidence, reports, country
- VirusTotal: Observable type=hash/domain/ip/url -> returns detection ratio, scan results
- Shodan: Observable type=ip -> returns open ports, services, vulns
- Abuse Finder: Observable type=ip/domain -> returns abuse contact info
- GoogleDNS: Observable type=domain/fqdn -> returns DNS resolution

API example:
```bash
curl -H 'Authorization: Bearer <CORTEX_API_KEY>' \
  -H 'Content-Type: application/json' \
  -X POST http://10.10.30.22:9001/api/analyzer/AbuseIPDB_1_1/run \
  -d '{"data": "1.2.3.4", "dataType": "ip", "tlp": 2}'
```

**5.4 Wazuh FIM (Syscheck) Correlation:**
- Query syscheck events for file changes on affected agent
- Key fields: syscheck.path, syscheck.event (added/modified/deleted), syscheck.md5_after, syscheck.sha256_after
- OpenSearch query template for FIM events by agent and time window

**5.5 ELK Detection Rule Cross-Reference:**
- Check if ELK detection rules fired for same timeframe/host
- Query: `.alerts-security.alerts-default` index on ELK
- Compare Wazuh detection vs Elastic detection for same event

**Step 2: Commit**

```bash
git add docs/guides/soc-playbook.md
git commit -m "Add SOC playbook: triage, escalation, and investigation sections"
```

---

### Task 7: SOC Playbook — Response and TheHive Case Management (NIST 800-61)

**Files:**
- Modify: `docs/guides/soc-playbook.md`

**Step 1: Write sections 6-7**

**Section 6 — Responding to Alerts:**

**6.1 Blocking IPs via Cloudflare:**

Manual API call:
```bash
curl -X POST "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/firewall/access_rules/rules" \
  -H "Authorization: Bearer CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "block",
    "configuration": {"target": "ip", "value": "1.2.3.4"},
    "notes": "Blocked by SOC analyst - abuse score 95, 12 reports"
  }'
```

WF1 auto-block conditions: abuse_score >= 90 AND reports >= 5 AND NOT whitelisted. Currently disabled (HONEYPOT_DISABLED).

**6.2 Endpoint Isolation:**
- Velociraptor: Can restrict network access or kill processes via VQL artifacts
- OPNsense: Add firewall rule to block specific host IP
- Wazuh Active Response: Can trigger scripts on alert match (configured in ossec.conf)

**6.3 TheHive Response Documentation:**
- Add observables (IOCs) to case: IPs, hashes, domains, URLs, filenames
- Create tasks for each IR phase
- Log all response actions as task logs with timestamps
- Attach evidence files (pcaps, screenshots, VQL results)

**Section 7 — TheHive Case Management (NIST 800-61 Aligned):**

Full industry-standard case management procedures as specified in design doc:

**7.1 Case Creation:**
- Severity: 1=Low, 2=Medium, 3=High, 4=Critical
- TLP: WHITE (public), GREEN (community), AMBER (organization), RED (eyes only)
- PAP: WHITE (active actions), GREEN (passive analysis), AMBER (restricted), RED (no sharing)
- Tag taxonomy: auto-enriched, manual, campaign-caldera, honeypot, cve-YYYY-NNNNN
- API example for case creation with all fields

**7.2 Case Workflow:**
- New -> InProgress (analyst assigned, investigation started)
- InProgress -> Resolved/TruePositive (confirmed incident, response complete)
- InProgress -> Resolved/FalsePositive (confirmed not an incident)
- InProgress -> Resolved/Indeterminate (insufficient evidence)
- Impact: None / Low / Medium / High / Critical

**7.3 IR Phase Tasks (create these 5 tasks on every confirmed case):**
- Task 1 — Identification: Confirm incident scope, identify affected systems, collect initial evidence, document timeline
- Task 2 — Containment (Short-term): Isolate affected systems, block malicious IPs/domains, preserve evidence. (Long-term): Apply patches, harden configs, update firewall rules
- Task 3 — Eradication: Remove malware/backdoors, eliminate persistence mechanisms, verify clean system state
- Task 4 — Recovery: Restore from backup if needed, verify services operational, monitor for reinfection (72h watch)
- Task 5 — Lessons Learned: Complete after-action report, update detection rules, assess ML retraining need

**7.4 Observable Management:**
- IOC types: ip, domain, fqdn, url, hash (md5/sha1/sha256), filename, mail, registry, user-agent
- For each observable: set TLP, add tags, run appropriate Cortex analyzers
- API example for adding observable to case
- Bulk import via TheHive API

**7.5 Escalation Procedures:**
- Increase severity when: additional systems affected, data exfiltration confirmed, persistence found, lateral movement detected
- Merge cases when: same attacker IP, same campaign, related MITRE techniques
- Create child cases when: incident spawns separate investigation threads

**7.6 Case Closure Checklist:**
Provide as a numbered checklist with API commands to verify each item.

**7.7 After-Action Report (AAR) Template:**

Full NIST 800-61 Section 3.4 template in markdown format:

```markdown
## After-Action Report

### Incident Summary
- **Case ID:** TH-YYYY-NNNN
- **Classification:** [Malware/Intrusion/DoS/Unauthorized Access/Policy Violation]
- **Severity:** [1-4]
- **Analyst:** [Name]
- **Date Range:** [First detection] to [Case closure]

### Executive Summary
[1-2 paragraph overview of incident, impact, and outcome]

### Timeline of Events
| Time (UTC) | Event | Source | Action Taken |
|------------|-------|--------|--------------|
| YYYY-MM-DD HH:MM | Initial detection | Wazuh Rule XXXXX | Alert triaged |
| ... | ... | ... | ... |

### Root Cause Analysis
[What vulnerability/misconfiguration/attack vector was exploited]

### Impact Assessment
- **Systems Affected:** [List]
- **Data Exposure:** [None/Confidential/PII/Credentials]
- **Duration (Dwell Time):** [Hours/Days]
- **Business Impact:** [None/Low/Medium/High]

### What Worked Well
- [Detection coverage that caught the attack]
- [Automation that accelerated response]
- [Process that functioned correctly]

### Areas for Improvement
- [Detection gaps identified]
- [Process delays or manual steps]
- [Tool limitations encountered]

### Action Items
| # | Action | Owner | Deadline | Status |
|---|--------|-------|----------|--------|
| 1 | [Specific action] | [Name] | [Date] | Open |

### Detection Engineering Updates
- [ ] Wazuh rule created/updated: [Rule ID]
- [ ] Elastic rule created/updated: [Rule name]
- [ ] Suricata rule created/updated: [SID]
- [ ] ML model retraining assessed: [Yes/No — reason]

### Metrics
- **MTTD (Mean Time to Detect):** [Time from first malicious activity to first alert]
- **MTTR (Mean Time to Respond):** [Time from first alert to containment]
- **Dwell Time:** [Time attacker was present before detection]
```

Explain where to store the AAR: as TheHive Task 5 (Lessons Learned) task log entry. Also recommend exporting significant AARs as standalone documents.

**Step 2: Commit**

```bash
git add docs/guides/soc-playbook.md
git commit -m "Add SOC playbook: response procedures and TheHive case management with AAR"
```

---

## Phase 3: SOC Playbook — Operations, Runbooks, and Reference

### Task 8: SOC Playbook — SOAR Workflow Operations

**Files:**
- Modify: `docs/guides/soc-playbook.md`

**Step 1: Write section 8**

**Section 8 — SOAR Workflow Operations:**

For each workflow, document:
- Purpose (one sentence)
- Trigger method (webhook/cron)
- Manual execution command (curl)
- What to look for in output
- Common issues

**WF1 — Threat Enrichment & Auto-Block:**
- Trigger: Automatic (Wazuh level 8+ webhook)
- Manual re-trigger: Paste alert JSON to webhook URL
- Output: Discord alert with scores + TheHive case + optional Cloudflare block
- Honeypot mode: Branch condition HONEYPOT_DISABLED suppresses Cloudflare blocking
- Check: Shuffle -> WF1 -> Executions -> verify evaluate_score node completed

**WF2 — Watch Turnover Digest:**
- Trigger: Cron 0605/1805 EST
- Manual: `curl -X POST http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute -H 'Authorization: Bearer <SHUFFLE_API_KEY>'`
- Output: Two Discord messages (watch data + MITRE analysis + turnover narrative)
- Interpretation: Posture levels (NORMAL/GUARDED/ELEVATED/CRITICAL), action items, MITRE technique assessment

**WF3 — Detection Gap Analyzer:**
- Trigger: Manual webhook POST
- Payload: `{"operation_id": "caldera_op_id", "start_time": "now-24h", "end_time": "now"}`
- Output: Coverage % + gap list + Ollama recommendations + TheHive case
- When to use: After every Caldera campaign

**WF5 — Daily Alert Cluster Triage:**
- Trigger: Cron 0600 EST
- Manual: curl POST (same pattern as WF2)
- Output: Discord report classifying top 10 clusters
- Classifications: CAMPAIGN (expected red team), ROUTINE (normal), INVESTIGATE (needs review), MISCONFIG (rule tuning)
- Action: Check TheHive for auto-created alerts for INVESTIGATE items

**WF6 — Model Drift Detector:**
- Trigger: Cron 0900 EST
- Output: Discord brief (model health + metrics)
- Classifications: STABLE (no action), MINOR_DRIFT (monitor), SIGNIFICANT_DRIFT (investigate retraining)
- If SIGNIFICANT_DRIFT: Check WF6 ELK index `ml-drift` for details, consult ML model card

**WF7 — Honeypot Intel Report:**
- Trigger: Cron Sunday 1200 EST
- Output: Discord intelligence report (credential analysis, network analysis, technique analysis, week-over-week deltas)
- Action: Review for novel TTPs, update honeypot config if needed

**WF8 — LLM Log Anomaly Finder:**
- Trigger: Cron 1500 EST
- Output: Two Discord messages (internal network + honeypot if applicable)
- Classifications: ANOMALOUS (investigate), MISCONFIG (tune rule), TRANSIENT (ignore), BLIND_SPOT (detection gap)
- Key: Complements WF5 — WF5 covers high-volume noise, WF8 covers low-volume rare patterns

**Step 2: Commit**

```bash
git add docs/guides/soc-playbook.md
git commit -m "Add SOC playbook: SOAR workflow operations guide"
```

---

### Task 9: SOC Playbook — Adversary Simulation Operations

**Files:**
- Modify: `docs/guides/soc-playbook.md`

**Step 1: Write section 9**

**Section 9 — Adversary Simulation Operations:**

**9.1 run_attack.sh Usage:**
```bash
# From sear (10.10.20.20):
./run_attack.sh <attack_type> ["optional notes"]
./run_attack.sh --list                        # List all 200+ attacks
./run_attack.sh --campaign-id CAMP-001 sqli_union "DVWA test"
./run_attack.sh --auto-confirm sqli_union     # Skip confirmation (campaigns)
```

Key attack categories (with examples):
- Web: sqli_union, sqli_blind, xss, lfi, cmdi, path_traversal, log4shell
- Credential: login, wordpress, xmlrpc, stuffing
- Recon: syn_scan, full_tcp, udp_scan, version_detection, os_fingerprinting
- Brute force: ssh, ftp, telnet, mysql, postgres
- C2: http_beacon, dns_beacon, http_exfiltration
- AD (VLAN 30, restricted): ldap_enum, kerberoast, password_spray, bloodhound
- Metasploit: vsftpd, distcc, ms17_010, tomcat, java_rmi

Safety: All attacks default to VLAN 40. AD attacks require typing "CONFIRM-AD".

**9.2 Caldera Campaign Execution:**

Via UI:
1. Login: http://10.10.30.21:8888 -> red/<PLATFORM_PASSWORD>
2. Operations -> Create Operation
3. Select adversary profile (29 available)
4. Select agent group: "targets"
5. Settings: auto_close=false, source=basic, planner=atomic
6. Start operation

Via API:
```bash
curl -X POST http://10.10.30.21:8888/api/v2/operations \
  -H 'KEY: <CALDERA_API_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Campaign Name",
    "adversary": {"adversary_id": "FULL_UUID"},
    "source": {"id": "basic"},
    "auto_close": false,
    "group": "targets"
  }'
```

Critical: Use FULL adversary UUIDs (truncated causes 0-link failures).

**9.3 Post-Attack Validation:**
1. Wait 2-5 minutes for Suricata to process traffic
2. Query Wazuh for alerts in attack timeframe (use attack_id timestamp)
3. Check Zeek indices for corresponding network flows
4. Run WF3 detection gap analysis with Caldera operation_id
5. Document coverage gaps -> write new Wazuh/Suricata rules

**9.4 Ground-Truth Log Format:**
```
attack_id,timestamp_start,timestamp_end,category,subcategory,technique_id,tool,source_ip,target_ip,target_port,target_service,success,notes
```
Location: `attack-scripts/attack_log.csv` on sear.

**Step 2: Commit**

```bash
git add docs/guides/soc-playbook.md
git commit -m "Add SOC playbook: adversary simulation operations"
```

---

### Task 10: SOC Playbook — Scenario Runbooks (8 Runbooks)

**Files:**
- Modify: `docs/guides/soc-playbook.md`

**Step 1: Write section 10**

**Section 10 — Scenario Runbooks:**

Each runbook follows the format:
- Trigger (what alert/event initiates this runbook)
- Verify (confirm the alert is real, not false positive)
- Investigate (gather evidence)
- Respond (take action)
- Document (TheHive case + AAR if significant)

**RB-01: SSH Brute Force**
- Trigger: Wazuh rule 5763 (multiple SSH auth failures) or high-frequency `rule.groups: authentication_failed`
- Verify: Query OpenSearch for source IP, count failures, check if source is internal (sear running brute force test) vs external
- Investigate: AbuseIPDB lookup, check if IP appears in other agent alerts, Zeek conn log for full session metadata
- Respond: If external malicious: Cloudflare block. If internal: verify it's authorized testing via attack_log.csv
- Document: TheHive case with source IP, failure count, country, resolution

**RB-02: SQL Injection**
- Trigger: Suricata SID 2006446 (UNION SELECT) or custom SIDs 9000001-9000005
- Verify: Check Zeek HTTP index for actual payload in URL/body. Check if source is sear (authorized) or unknown
- Investigate: Full HTTP request chain in zeek-http. Check for successful injection (HTTP 200 with data exfil patterns). Review DVWA/target access logs
- Respond: Block source if external. Review web app configs if attack succeeded. Document payloads as IOCs
- Document: TheHive case with payloads, response codes, MITRE T1190

**RB-03: Lateral Movement (AD Environment)**
- Trigger: Alerts from DC01/WS01 agents with MITRE techniques T1021 (Remote Services), T1047 (WMI), T1059 (Command Scripting)
- Verify: Check if Caldera campaign is running (query Caldera API for active operations). Check if AD attack was authorized via run_attack.sh
- Investigate: Velociraptor on DC01/WS01 — process listing, network connections, scheduled tasks, recently created accounts. Check for Kerberoasting, Pass-the-Hash, DCSync indicators
- Respond: If unauthorized: isolate WS01, reset compromised credentials, review DC01 event logs for privilege escalation. If Caldera: document detection coverage
- Document: TheHive case with MITRE technique mapping, affected accounts, lateral movement path

**RB-04: Malware/Suspicious Binary**
- Trigger: Wazuh FIM (syscheck) alert for new/modified executable in monitored directory
- Verify: Check syscheck.path, syscheck.md5_after, syscheck.sha256_after. Is it a known system update or scheduled change?
- Investigate: Velociraptor file collection (hash, strings, metadata). Cortex VirusTotal analyzer on file hash. Check process listing for running instance. Check persistence mechanisms
- Respond: If malicious: kill process, quarantine file, check for additional dropped files. Scan other endpoints via Velociraptor hunt
- Document: TheHive case with file hash IOCs, VirusTotal results, affected systems

**RB-05: Honeypot Anomaly**
- Trigger: WF8 classifies gcp-vm pattern as ANOMALOUS (novel TTP, post-auth activity, web shell indicators)
- Verify: Review WF8 Discord output for classification reasoning. Check honeypot-wazuh index for alert details. Compare to baseline (SSH brute force, credential stuffing = expected)
- Investigate: Query honeypot-credentials for credential patterns. Check honeypot-access for unusual paths (admin panels, shell uploads). Review Wazuh agent 009 alerts for MITRE techniques beyond T1078/T1110
- Respond: If sophisticated actor: capture full session data. Update honeypot config if evasion detected. No blocking (research value)
- Document: TheHive case tagged "honeypot". Feed findings to WF7 weekly report

**RB-06: ML Model Drift**
- Trigger: WF6 classifies as SIGNIFICANT_DRIFT (mean shift >0.1, malicious % change >20pp, p95 shift >0.15)
- Verify: Check ELK `ml-drift` index for drift metrics. Compare current distribution vs baseline. Is drift sustained (consecutive days) or one-off?
- Investigate: What changed? New attack campaign? Network topology change? New agents? Zeek enrichment rate change? Sample recent high-scoring alerts manually
- Respond: If sustained drift from new attack types: initiate retraining with new labeled data. If topology change: update feature engineering. If one-off: acknowledge and monitor
- Document: TheHive case documenting drift metrics, root cause, retraining decision

**RB-07: New Vulnerability (CVE)**
- Trigger: Wazuh vulnerability detection alert with CVE identifier
- Verify: Check CVE severity (CVSS). Identify affected agent/package/version
- Investigate: Is the vulnerable service exposed? Check Zeek for exploitation attempts. Check NVD/vendor advisory for exploit availability
- Respond: Patch if critical and exploitable. Update firewall rules if exposure confirmed. Add Suricata rule for exploit signature if available
- Document: TheHive case with CVE, affected systems, patch status, compensating controls

**RB-08: Caldera Campaign Validation**
- Trigger: Completed Caldera operation (manual decision to validate detection)
- Verify: Confirm operation completed in Caldera UI/API. Note operation_id and time range
- Investigate: Run WF3 with operation_id. Review coverage percentage. Identify specific MITRE techniques not detected
- Respond: For each gap: write Wazuh custom rule or Suricata signature. Test new rule against replayed attack. Assess ML retraining if significant new labeled data
- Document: TheHive case with detection gap report. Track rule creation progress

**Step 2: Commit**

```bash
git add docs/guides/soc-playbook.md
git commit -m "Add SOC playbook: 8 scenario runbooks"
```

---

### Task 11: SOC Playbook — Troubleshooting and API Reference

**Files:**
- Modify: `docs/guides/soc-playbook.md`

**Step 1: Write sections 11-12**

**Section 11 — Troubleshooting:**

6 troubleshooting procedures with symptoms, diagnosis commands, and fixes:

1. Agent Offline
2. Shuffle Workflow Failed
3. ELK Containers Down
4. ML Scorer Unhealthy
5. Wazuh Dashboard Unreachable
6. OpenSearch/ELK Query Failures

Each follows: Symptom -> Diagnose (SSH commands, curl checks, docker logs) -> Fix -> Verify

**Section 12 — API & Query Reference:**

Comprehensive copy-paste reference organized by service:

- **Wazuh REST API:** JWT auth flow (get token, use token), then: list agents, get agent by ID, list rules, search alerts, get agent logs, restart agent
- **OpenSearch:** 15+ query templates (consolidate from section 3 + add aggregations, date histograms, composite queries)
- **ELK Elasticsearch:** 10+ queries (consolidate from section 3.4 + add rule alert queries)
- **Shuffle API:** List workflows, trigger workflow, get execution status, get execution results
- **TheHive API:** Create case, list cases, update case status, add observable, create task, create task log, close case, search cases
- **Cortex API:** List analyzers, run analyzer, get job status, get report
- **Velociraptor VQL:** 5+ hunt queries (processes, files, network, persistence, autoruns)
- **Caldera API:** List operations, create operation, list agents, get operation results
- **Cloudflare API:** Block IP, list access rules, delete rule
- **ML Scorer API:** Score alert (POST /score), health check (GET /health), model info

**Step 2: Commit**

```bash
git add docs/guides/soc-playbook.md
git commit -m "Add SOC playbook: troubleshooting and API reference"
```

---

### Task 12: Update README and docs index

**Files:**
- Modify: `docs/README.md`
- Modify: `README.md` (top-level, add link to guides)

**Step 1: Update docs/README.md**

Add guides/ section pointing to both new documents with one-line descriptions.

**Step 2: Update top-level README.md**

Add a "Guides" or "Documentation" section linking to:
- `docs/guides/portfolio-overview.md` — Architecture and capabilities narrative
- `docs/guides/soc-playbook.md` — Operational handbook and runbooks

**Step 3: Commit**

```bash
git add docs/README.md README.md
git commit -m "Add links to SOC analyst guides in README and docs index"
```
