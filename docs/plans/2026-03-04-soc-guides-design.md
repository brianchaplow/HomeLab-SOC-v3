# SOC Analyst Guides — Design Document

**Date:** 2026-03-04
**Author:** Brian Chaplow
**Status:** Approved

---

## Overview

Two comprehensive reference documents for the HomeLab SOC v3, each serving a distinct audience:

1. **Portfolio Overview** (`docs/guides/portfolio-overview.md`) — Narrative-driven guide for hiring managers, interviewers, and peers evaluating SOC competence
2. **SOC Playbook** (`docs/guides/soc-playbook.md`) — Operational handbook for someone sitting down to operate this SOC day-to-day

---

## Document 1: Portfolio Overview

**Audience:** Portfolio reviewers (hiring managers, interviewers, peers)
**Tone:** Narrative, demonstrates competence, explains "why" alongside "what"
**Length:** ~800-1200 lines

### Sections

1. **SOC Architecture at a Glance**
   - C4-style narrative with data flow overview
   - Key metrics table (10 agents, 214 rules, PR-AUC 0.9998, 7 DFIR clients, 8 workflows)
   - Technology stack summary
   - Hardware inventory (176 GB RAM, 12 GB GPU VRAM across 8 hosts)

2. **The Alert Lifecycle (End-to-End)**
   - Detection: Suricata/Zeek on SPAN -> Wazuh Manager -> OpenSearch indexing
   - Automated enrichment: Shuffle WF1 -> AbuseIPDB + ML Scorer + Ollama triage
   - Scoring decision: combined_score = max(abuse_norm, ml_score)
   - Case creation: TheHive auto-case with NIST 800-61 lifecycle
   - Investigation: Velociraptor artifact collection, Zeek flow correlation
   - Response: Cloudflare block, endpoint isolation, case documentation
   - Closure: After-action report, detection rule updates, metrics (MTTD/MTTR)
   - Intelligence loop: WF2 watch digest, WF5 cluster triage, WF8 anomaly hunting

3. **Detection Engineering**
   - Dual-SIEM architecture (Wazuh integrated vs Elastic flexible)
   - Custom Suricata rules (SIDs 9000001-9000021)
   - Zeek network telemetry (7 indices: conn, dns, http, ssl, files, notice, weird)
   - 214 Elastic detection rules mapped to MITRE ATT&CK
   - Custom Wazuh rules and decoders

4. **SOAR & LLM Automation**
   - 8 Shuffle workflows with scheduling architecture
   - Ollama qwen3:8b integration patterns (/no_think, temperature 0.3)
   - Workflow variable convention (no hardcoded secrets)
   - GPU scheduling (3-hour stagger between Ollama-heavy runs)
   - Real-time response (WF1) vs scheduled intelligence (WF2/WF5/WF6/WF7/WF8)

5. **ML Threat Scoring**
   - 102 behavioral features (no IP-based to avoid topology bias)
   - Temporal train/test split (prevent data leakage)
   - Hybrid scoring: XGBoost supervised + IsolationForest anomaly
   - PR-AUC 0.9998 (rationale: imbalanced dataset, precision-recall over ROC)
   - Drift monitoring via WF6

6. **Incident Response & Case Management**
   - TheHive 4 case lifecycle (NIST 800-61 aligned)
   - Cortex 3 analyzers (5 deployed: AbuseIPDB, VirusTotal, Shodan, Abuse Finder, GoogleDNS)
   - Velociraptor DFIR (7 clients, VQL artifact collection)
   - After-action report process and metrics

7. **Adversary Emulation & Validation**
   - Caldera v5.3.0 (29 MITRE ATT&CK profiles, 4 Sandcat agents)
   - Ground-truth logging via run_attack.sh (200+ attack types)
   - WF3 detection gap analysis (coverage percentage computation)
   - Purple team closed loop: execute -> detect -> measure -> improve -> retrain

8. **Honeypot Research**
   - GCP WordPress honeypot architecture
   - Tailscale connectivity (no inbound port exposure)
   - 3 ELK indices (credentials ~3,140, access ~737, wazuh ~5,925)
   - INST 570 research pipeline
   - WF7 weekly intelligence reports

9. **Network Security Design**
   - 5 VLANs with inter-VLAN firewall policy
   - VLAN 40 complete isolation model
   - MokerLink ACL micro-segmentation (9-rule stateless ACL on sear)
   - Defense-in-depth layers (perimeter -> segmentation -> ACL -> host -> detection -> AI/ML)
   - Tailscale overlay for external connectivity

---

## Document 2: SOC Playbook

**Audience:** Analyst operating the SOC hands-on
**Tone:** Procedural, copy-paste commands, step-by-step, no narrative
**Length:** ~2000-3000 lines

### Sections

1. **Quick Access Reference**
   - Every service URL, port, credential in one table
   - SSH commands (LAN and Tailscale)
   - Web UI bookmark list

2. **Daily Operations Checklist**
   - Shift start procedure
   - Agent health verification (Wazuh + Velociraptor + Elastic Fleet)
   - Shuffle workflow status check
   - Open TheHive cases review
   - Grafana dashboard review
   - ELK container status verification
   - Discord channel review

3. **Working with Alerts**
   - Wazuh Dashboard navigation (filters, severity levels 0-15)
   - OpenSearch query templates (15+ copy-paste queries)
   - ELK Elasticsearch query templates (10+ queries)
   - Alert severity scale and routing (3-7 logged, 8+ SOAR, 12+ critical)
   - Reading Shuffle WF1 execution history

4. **Triaging & Escalating Alerts**
   - Interpreting ML scores (0-1 scale, 0.7 threshold, 0.9 high-threat)
   - Interpreting AbuseIPDB enrichment (confidence, reports, country)
   - Reading Ollama triage summaries and ML feature explanations
   - Escalation decision matrix (score + rule level + MITRE technique)
   - Creating TheHive cases (manual API + UI procedures)
   - Promoting TheHive alerts to cases

5. **Investigating Alerts**
   - Zeek flow correlation (zeek-conn, zeek-http, zeek-dns, zeek-ssl queries)
   - Packet-level inspection via Zeek metadata
   - Velociraptor hunts (VQL: processes, file hashes, network, persistence, autoruns)
   - Cortex analyzer execution (per-analyzer procedures)
   - Wazuh FIM/syscheck correlation
   - ELK detection rule cross-reference

6. **Responding to Alerts**
   - Cloudflare IP blocking (manual API + WF1 auto-block conditions)
   - Endpoint isolation procedures
   - TheHive response documentation (tasks, observables, IOCs)
   - Cortex responder execution

7. **TheHive Case Management (NIST 800-61 Aligned)**
   - **Case Creation**
     - Severity classification (1=Low, 2=Medium, 3=High, 4=Critical)
     - TLP marking (WHITE/GREEN/AMBER/RED)
     - PAP marking (WHITE/GREEN/AMBER/RED)
     - Initial observable entry (IPs, hashes, domains, URLs)
     - Tag taxonomy (auto-enriched, manual, campaign, honeypot)
   - **Case Workflow**
     - Status progression: New -> InProgress -> Resolved
     - Resolution status: TruePositive / FalsePositive / Indeterminate / Other
     - Impact assessment (None/Low/Medium/High/Critical)
   - **Task Management (IR Phase Tasks)**
     - Task 1: Identification — Confirm incident, gather initial evidence
     - Task 2: Containment — Short-term (isolate) + long-term (patch/harden)
     - Task 3: Eradication — Remove threat artifacts, clean compromised systems
     - Task 4: Recovery — Restore operations, verify clean state
     - Task 5: Lessons Learned — After-action analysis
   - **Observable Management**
     - IOC types: ip, domain, fqdn, url, hash, filename, mail, registry, user-agent
     - Analyzer execution per observable type
     - Tagging and TLP marking per observable
     - Bulk observable import
   - **Escalation Procedures**
     - When to increase severity
     - When to merge related cases
     - When to create child/linked cases
     - Notification chain (Discord channels)
   - **Case Closure Checklist**
     - [ ] Root cause identified and documented
     - [ ] All IOCs documented as observables
     - [ ] Containment actions verified effective
     - [ ] Eradication confirmed (no persistence)
     - [ ] Recovery verified (services restored)
     - [ ] Detection rules created/updated for this attack pattern
     - [ ] ML model retraining assessed (if new attack type)
     - [ ] Case summary written
     - [ ] Resolution status set (TP/FP/Indeterminate)
     - [ ] After-action report completed
   - **After-Action Report (AAR)**
     - Template based on NIST 800-61 Section 3.4:
       - Incident ID and classification
       - Executive summary (1-2 paragraphs)
       - Timeline of events (detection -> containment -> eradication -> recovery)
       - Root cause analysis
       - Impact assessment (systems affected, data exposed, duration)
       - What worked well (detection coverage, response time, automation)
       - Areas for improvement (detection gaps, process gaps, tool gaps)
       - Action items (owner, deadline, status)
       - Detection engineering updates (new rules, tuned thresholds)
       - Metrics: MTTD, MTTR, dwell time
     - AAR stored as TheHive case task (Task 5: Lessons Learned)
     - Key findings fed back into: Wazuh rules, Elastic rules, Suricata rules, ML retraining, Shuffle workflow updates

8. **SOAR Workflow Operations**
   - Per-workflow: purpose, trigger method, manual execution command, output interpretation
   - WF1: Enrichment results, manual re-trigger, honeypot mode toggle
   - WF2: Watch turnover interpretation, manual trigger
   - WF3: Detection gap webhook payload, reading coverage %
   - WF5: Cluster triage classifications (CAMPAIGN/ROUTINE/INVESTIGATE/MISCONFIG)
   - WF6: Model drift alert response procedure
   - WF7: Honeypot intel report interpretation
   - WF8: Anomaly classifications (ANOMALOUS/MISCONFIG/TRANSIENT/BLIND_SPOT)

9. **Adversary Simulation Operations**
   - run_attack.sh syntax, options, VLAN safety (--auto-confirm, --campaign-id)
   - Caldera campaign execution (UI + API, config requirements)
   - Post-attack validation (2-5 min Suricata processing window)
   - WF3 detection gap analysis post-campaign
   - Ground-truth logging format and correlation

10. **Scenario Runbooks**
    - RB-01: SSH Brute Force (detect -> verify -> block -> case -> close)
    - RB-02: SQL Injection (Suricata alert -> Zeek HTTP -> DVWA context -> response)
    - RB-03: Lateral Movement (AD alerts DC01/WS01 -> Velociraptor -> containment)
    - RB-04: Malware/Suspicious Binary (FIM alert -> Velociraptor -> Cortex VirusTotal)
    - RB-05: Honeypot Anomaly (WF8 ANOMALOUS -> credential analysis -> intel report)
    - RB-06: ML Model Drift (WF6 SIGNIFICANT_DRIFT -> investigate -> retrain decision)
    - RB-07: New Vulnerability/CVE (Wazuh vuln detection -> patch assessment -> case)
    - RB-08: Caldera Campaign Validation (execute -> wait -> WF3 -> analyze -> write rules)

11. **Troubleshooting**
    - Agent offline (connectivity, restart, firewall)
    - Shuffle workflow failed (execution logs, Orborus restart, variable resolution)
    - ELK containers down (manual restart, LXC reboot quirk)
    - ML Scorer unhealthy (health endpoint, GPU contention)
    - Wazuh Dashboard unreachable (certs, indexer health)
    - Query failures (index patterns, field type mismatches)

12. **API & Query Reference**
    - Wazuh REST API (JWT auth flow + agent/rule/alert endpoints)
    - OpenSearch queries (15+ templates)
    - ELK Elasticsearch queries (10+ templates)
    - Shuffle API (trigger, execution status)
    - TheHive API (CRUD cases, alerts, observables, tasks)
    - Cortex API (run analyzer, get report)
    - Velociraptor VQL (5+ hunt queries)
    - Caldera API (operations, results)
    - Cloudflare API (block IP, list rules)
    - ML Scorer API (score, health)

---

## Implementation Phases

Given the scale (~3000-4000 total lines across both docs), implementation will be phased:

**Phase 1:** Portfolio Overview (Document 1) — complete narrative guide
**Phase 2:** SOC Playbook sections 1-7 — access reference, alerts, triage, investigation, response, TheHive/AAR
**Phase 3:** SOC Playbook sections 8-12 — SOAR operations, adversary sim, runbooks, troubleshooting, API reference

Each phase produces a committable deliverable.

---

## Conventions

- Real IP addresses, ports, and credentials from CLAUDE.md (this is a portfolio repo, creds are already documented)
- Copy-paste curl commands with actual endpoints
- OpenSearch/ELK queries in full JSON format
- VQL examples for common Velociraptor operations
- TheHive AAR template follows NIST 800-61 Section 3.4
- No emojis unless in classification labels (as used by Shuffle workflows)
