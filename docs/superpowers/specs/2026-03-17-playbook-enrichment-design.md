# SOC Analyst Playbook Enrichment — Design Spec

**Date:** 2026-03-17
**Author:** Brian Chaplow
**Status:** Approved

## Problem Statement

The SOC analyst HTML handbook (`~/.soc-playbook/soc-playbook.md`) is an effective operational reference with 150+ copy-paste-ready commands, but has three gaps:

1. **Tools are used but not explained.** An intern familiar with cybersecurity concepts but new to this stack would not understand what Wazuh, TheHive, Velociraptor, etc. actually are, how they work, or how they fit together.
2. **Commands lack result interpretation.** Queries return data, but there is no guidance on what the output means, what to do next, or what to try when results are empty.
3. **GUI tools are underserved.** The playbook is bash-heavy. Tools with significant GUI interfaces (Wazuh Dashboard, Kibana, TheHive, Velociraptor, Shuffle, Grafana, etc.) lack navigation walkthroughs.

## Target Audience

- **Primary:** An intern who knows security fundamentals (MITRE ATT&CK, NIST, what a SIEM is conceptually) but has never operated this specific stack. They need to understand what each tool does, why it is in the pipeline, and what to do with results.
- **Secondary:** The SOC owner as a daily driver. Operational speed and copy-paste efficiency must not be sacrificed for verbosity.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Tool explanation placement | Standalone section + inline references | Intern gets full mental model before operations; daily driver skips ahead |
| GUI walkthroughs | Precise step-by-step navigation text (no embedded screenshots) | Written as prompts for Chrome Claude extension to execute |
| Result interpretation depth | Scaled to decision weight | Simple queries get interpretation blocks; critical decisions get mini decision trees |
| Dead-end recovery | On every query | Intern should never hit a wall with no next step |
| Appendix | Yes, full reference tables | "Flip to the back" lookup for codes, IDs, terminology |

## Structural Changes

The playbook restructures from 12 sections to 15:

```
Prerequisites                        (existing, unchanged)
1.  Quick Access Reference            (existing, unchanged)
2.  SOC Architecture & Data Flow      (NEW)
3.  Your SOC Stack                    (NEW — 22 tool entries)
4.  Daily Operations Checklist        (was 2, enriched)
5.  Working with Alerts               (was 3, + interpretation blocks)
6.  Triaging and Escalating Alerts    (was 4, + decision trees)
7.  Investigating Alerts              (was 5, + dead-end recovery)
8.  Responding to Alerts              (was 6, + decision guidance)
9.  TheHive Case Management           (was 7, + interpretation)
10. SOAR Workflow Operations          (was 8, + result guidance)
11. Adversary Simulation Operations   (was 9, + interpretation)
12. Scenario Runbooks                 (was 10, + tool cross-refs)
13. Troubleshooting                   (was 11, + dead-end recovery)
14. API & Query Reference             (was 12, unchanged)
15. Appendix — SOC Analyst Reference  (NEW)
```

### Section Renumbering Map

| Old # | Old Title | New # |
|-------|-----------|-------|
| 1 | Quick Access Reference | 1 (unchanged) |
| — | SOC Architecture & Data Flow | 2 (NEW) |
| — | Your SOC Stack | 3 (NEW) |
| 2 | Daily Operations Checklist | 4 |
| 3 | Working with Alerts | 5 |
| 4 | Triaging and Escalating Alerts | 6 |
| 5 | Investigating Alerts | 7 |
| 6 | Responding to Alerts | 8 |
| 7 | TheHive Case Management | 9 |
| 8 | SOAR Workflow Operations | 10 |
| 9 | Adversary Simulation Operations | 11 |
| 10 | Scenario Runbooks | 12 |
| 11 | Troubleshooting | 13 |
| 12 | API & Query Reference | 14 |
| — | Appendix — SOC Analyst Reference | 15 (NEW) |

All cross-references in the spec (and in enrichment block examples) use the **new** numbering. During implementation, every internal cross-reference in the existing playbook must be updated per this table.

## Section 2: SOC Architecture & Data Flow

Gives the intern the 30,000-foot view before they touch anything.

### 2.1 — Architecture Diagram (Mermaid)

C4-style container diagram showing:

- **External perimeter:** GCP VM, Cloudflare (WAF/DNS)
- **Detection layer:** Wazuh agents (12), Zeek, Suricata, Fleet agents
- **Data pipeline:** Fluent Bit to Wazuh Indexer / haccp ELK Elasticsearch
- **PCAP capture:** Arkime on haccp (full packet capture + session analysis)
- **Enrichment:** ML Scorer, Ollama, AbuseIPDB, OpenCTI
- **Orchestration:** Shuffle SOAR (WF1-WF9)
- **Response:** TheHive cases, Cortex analyzers, Cloudflare blocks, Wazuh Active Response
- **Purple team:** Caldera, Velociraptor
- **Infrastructure:** OPNsense, Proxmox, Docker, Tailscale
- **Monitoring:** Prometheus + Grafana

Arrows show data flow direction. Grouped by VLAN where relevant.

### 2.2 — Alert Lifecycle Phase Table

| Phase | What Happens | Tools |
|-------|-------------|-------|
| Collection | Agents ship logs, network sensors capture traffic | Wazuh agents, Zeek, Suricata, Fluent Bit, Fleet |
| Detection | Rules fire, alerts generated | Wazuh rules, ELK detection rules |
| Enrichment | Threat intel, ML scoring, LLM triage | Shuffle, ML Scorer, Ollama, AbuseIPDB, OpenCTI |
| Triage | Classification, dedup, severity assessment | Shuffle WF1/WF5, escalation matrix |
| Investigation | Correlate network/endpoint/logs/PCAP | Zeek indices, Arkime, Velociraptor, Cortex, Wazuh FIM |
| Response | Block, isolate, document | Cloudflare, OPNsense, Wazuh Active Response, TheHive |
| Closure | Case resolution, after-action report | TheHive, NIST 800-61 workflow |
| Emulation | Validate detections, test gaps | Caldera, run_attack.sh |

### 2.3 — Network Context

Brief VLAN overview with emphasis on what the intern needs to know:

- VLAN 40 is isolated targets — all attacks go there
- VLAN 20 is SOC infrastructure — never attack it
- VLAN 30 is lab/Proxmox
- VLAN 10 is management
- VLAN 50 is IoT
- Family DMZ/LAN is out of scope

Quick mental model, not a full network doc.

### 2.4 — External Perimeter

Explains GCP VM and Cloudflare roles in the SOC:

- GCP VM hosts public-facing sites (brianchaplow.com, bytesbourbonbbq.com), runs Wazuh agent 009 reporting to brisket, was the honeypot research platform (campaign ended 2026-03-12)
- Cloudflare provides WAF/DNS and is the enforcement point for Shuffle WF1 auto-blocks
- Both are monitored by the SOC and generate alerts that flow through the standard pipeline

## Section 3: Your SOC Stack

### Entry Template

Every tool gets a consistent 6-point treatment:

```
### 3.X — [Tool Name]

**What it is:** One-liner definition.

**What it does in this SOC:** 2-3 sentences on its specific role, what data
it ingests, what it produces. Specific to this lab's configuration, not generic.

**Where it runs:** Host, IP, port, access method (URL, SSH, GUI).

**How it fits in the pipeline:** What feeds into it, what it feeds out to.
References the Section 2 phase table.

**GUI Walkthrough:** Step-by-step navigation instructions, specific enough
for Chrome extension prompting. Key screens, what to look for, how to filter.
For CLI-only tools, this becomes "Key Commands" instead.

**Key Concepts:** Tool-specific terminology the intern needs. Definitions,
not just terms.
```

### Tool Inventory (22 tools, grouped by lifecycle phase)

**Detection & Collection (3.1-3.6)**

| # | Tool | GUI Walkthrough | Notes |
|---|------|----------------|-------|
| 3.1 | Wazuh (SIEM/XDR) | Heavy — Dashboard, Modules, Agents, Rules | Manager + Indexer + Dashboard as one entry |
| 3.2 | Elastic Stack | Heavy — Kibana Discover, Dashboards, Fleet, Detection Rules, ML Jobs | ES + Kibana + Fleet on haccp bare metal (10.10.30.25); includes Elastic ML anomaly detection (trial license) |
| 3.3 | Zeek (Network Metadata) | CLI — Key Commands | Runs on smokehouse, data queried via OpenSearch/ELK |
| 3.4 | Suricata (Network IDS) | CLI — Key Commands | Runs on smokehouse, eve.json shipped by Wazuh agent |
| 3.5 | Fluent Bit (Log Shipping) | CLI — Key Commands | Config-driven, runs on smokehouse + GCP |
| 3.6 | OpenCTI (Threat Intelligence) | Heavy — Platform, Connectors, Indicators, Reports | LXC 202 on pitcrew; IOC sync pipeline pushes to Wazuh CDB (every 6h) + haccp ELK (every 6h offset 15min) |

**Enrichment & Orchestration (3.7-3.10)**

| # | Tool | GUI Walkthrough | Notes |
|---|------|----------------|-------|
| 3.7 | Shuffle (SOAR) | Heavy — Workflow Editor, Execution History, Variables | 9 active workflows |
| 3.8 | ML Scorer (XGBoost) | CLI — Key Commands (API health, score requests) | REST API on brisket:5002 |
| 3.9 | Ollama / qwen3 (LLM) | CLI — Key Commands (model list, generate, health) | Host process on brisket:11434 |
| 3.10 | Cortex (Automated Analysis) | Heavy — Analyzers, Jobs, Reports | On TheHive LXC 200 |

**Investigation & Response (3.11-3.14)**

| # | Tool | GUI Walkthrough | Notes |
|---|------|----------------|-------|
| 3.11 | Velociraptor (DFIR) | Heavy — Clients, Hunts, Notebooks, VQL | brisket:8889 |
| 3.12 | TheHive (Case Management) | Heavy — Cases, Tasks, Observables, Dashboards | LXC 200 on pitcrew |
| 3.13 | Caldera (Adversary Emulation) | Heavy — Operations, Agents, Abilities, Adversaries | smoker:8888 |
| 3.14 | Arkime (Full PCAP) | Heavy — Sessions, SPI Graph, SPI View, Connections | haccp:8005, reads SPAN capture from SFP+ |

**Monitoring (3.15-3.16)**

| # | Tool | GUI Walkthrough | Notes |
|---|------|----------------|-------|
| 3.15 | Prometheus (Metrics) | Light — Targets, Graph, Alerts | brisket:9090 |
| 3.16 | Grafana (Dashboards) | Heavy — SOC v3 Overview, Data Sources, Panels | brisket:3000 |

**Infrastructure (3.17-3.22)**

| # | Tool | GUI Walkthrough | Notes |
|---|------|----------------|-------|
| 3.17 | OPNsense (Firewall) | Heavy — Dashboard, Rules, Aliases, Logs | 10.10.10.1 |
| 3.18 | Docker (Container Runtime) | CLI — Key Commands | Runs on brisket, smokehouse, smoker, haccp |
| 3.19 | Proxmox (Virtualization) | Heavy — VMs, LXCs, Storage, Backups | pitcrew + smoker |
| 3.20 | Tailscale (VPN) | Light — CLI + admin console | Mesh VPN for remote access |
| 3.21 | GCP VM (External Presence) | Light — Console overview, Wazuh agent status | External, Tailscale-connected |
| 3.22 | Cloudflare (WAF/DNS/Enforcement) | Heavy — Firewall Rules, WAF, DNS, Access Rules | WF1 auto-block target |

## Inline Enrichment (Sections 4-14)

Three types of enrichment blocks added to existing operational sections:

### Type 1: Interpretation Block

Used after simple queries. Explains what the output fields mean and where to go next.

```
> **Reading the output:**
> - `conn_state: S0` = connection attempt with no reply — likely a port scan
> - `conn_state: SF` = normal completed connection
> - High `orig_bytes` with low `resp_bytes` = possible data exfiltration
>
> **Next:** If you see S0 patterns from the same source, check for
> brute force — Section 7.X (SSH Brute Force query)
```

### Type 2: Decision Tree

Used at critical triage and escalation points. Structured if/then guidance.

```
> **Decision: Escalate or close?**
>
> ML Score >= 0.7 AND AbuseIPDB >= 80 -> External threat confirmed
>   -> Block IP (Section 8.1), create TheHive case (Section 9.5)
>
> ML Score >= 0.7 AND AbuseIPDB < 30 -> Possible internal/novel threat
>   -> Velociraptor hunt (Section 7.2), do NOT auto-block
>
> ML Score < 0.4 AND rule_level < 8 -> Likely routine/noise
>   -> Log and close, review in next WF5 cluster triage
>
> ML Score 0.4-0.7 -> Gray zone
>   -> Run Cortex analyzers (Section 7.3), check Zeek flows (Section 7.1)
```

### Type 3: Dead-End Recovery

Used after every query that might return empty results.

```
> **No results?**
> - Widen the time range to 24h and re-run
> - Check if the agent was online: Section 4 daily checklist, step 2
> - If the IP is external, it may not cross the SPAN — try Suricata
>   instead (Section 7.X)
> - If neither Zeek nor Suricata has hits, pivot to endpoint:
>   Velociraptor process listing (Section 7.2)
```

### Enrichment Placement Map

| Section | Enrichment Types | Focus |
|---------|-----------------|-------|
| 4 (Daily Ops) | Interpretation | "Why" behind each checklist step |
| 5 (Alerts) | Interpretation, Dead-end | After OpenSearch and ELK queries |
| 6 (Triage) | Decision trees | Escalation matrix, ML/AbuseIPDB interpretation |
| 7 (Investigation) | All three | After every Zeek, Velociraptor, FIM, ELK query |
| 8 (Response) | Decision trees | Which response method to use |
| 9 (TheHive) | Interpretation | Case field guidance |
| 10 (SOAR) | Interpretation | Workflow output meaning, when to act |
| 11 (Adversary Sim) | Interpretation, Dead-end | Post-attack validation results |
| 12 (Runbooks) | Cross-references | Links to Section 3 tool entries + Section 15 appendix |
| 13 (Troubleshooting) | Dead-end recovery | Every diagnostic step |

## Section 15: Appendix — SOC Analyst Reference

Fourteen reference tables for quick lookup:

### A. HTTP Status Codes

Common codes seen in SOC logs with security context:
- 200, 201, 204 (success), 301, 302 (redirect), 400, 401, 403, 404, 405, 429 (client errors), 500, 502, 503 (server errors)
- SOC interpretation: e.g., "401 in clusters = brute force indicator, 403 from Cloudflare = WAF block, 429 = rate limiting triggered"

### B. Wazuh Rule Levels & IDs

- Level scale 0-15 with meaning and examples
- Key custom rule IDs (9000001+) mapped to detections
- Common built-in rule IDs that fire frequently in this environment

### C. MITRE ATT&CK Techniques

Techniques active in this stack:
- Technique IDs seen in Wazuh/ELK/Caldera alerts
- Mapped to plain-English descriptions
- Which tool detects each technique

### D. Zeek Connection States

Full `conn_state` table:
- S0, S1, SF, REJ, S2, S3, RSTO, RSTR, RSTOS0, RSTRH, SH, SHR, OTH
- Meaning, normal vs. suspicious, threat relevance

### E. Suricata Severity & Action Codes

- Alert, drop, pass, reject — meaning in this config
- Severity levels and priority mapping

### F. Syslog Facility & Severity Codes

- Severity 0-7 (Emergency through Debug)
- Facility 0-23
- Which ones OPNsense and Wazuh syslog actually use

### G. Windows Event IDs

Key Security log IDs:
- 4624/4625 (logon success/failure), 4634 (logoff), 4648 (explicit creds), 4672 (special privs)
- 4688 (process creation), 4697/4698 (service/scheduled task), 4720 (account created), 4732 (group membership)
- 7045 (service installed)
- Logon types: 2 (interactive), 3 (network), 7 (unlock), 10 (RDP), 11 (cached)

### H. Linux Auth Log Patterns

- sshd accepted/failed patterns
- sudo success/failure
- su session patterns
- PAM authentication messages
- What each looks like in logs and what it means

### I. Network Protocol & Port Reference

- Common ports seen in Zeek/Suricata data
- Mapped to services
- Whether expected on each VLAN (unexpected = investigate)

### J. TheHive Severity / TLP / PAP Scales

- Severity 1-4 with guidance on when to use each
- TLP:WHITE through TLP:RED — data sharing restrictions
- PAP:WHITE through PAP:RED — permitted actions

### K. Glossary

SOC terminology appearing in the playbook:
- IOC, TTP, DFIR, FIM, CDB list, decoder, active response, observable, artifact, SPAN, PCAP, VQL, etc.
- Short operational definitions, not textbook entries

### L. AbuseIPDB Confidence Score Interpretation

- Score ranges (0-25 low, 25-50 moderate, 50-80 high, 80-100 critical)
- Report count thresholds
- ISP/ASN pattern interpretation (bulletproof hosting, cloud providers, residential)

### M. ML Scorer Output Reference

- Feature names and what they represent
- Score thresholds (0.4 noise floor, 0.7 escalation, 0.9 critical)
- What drives high vs. low scores
- Known false positive patterns

### N. TCP/IP Reference

- **TCP flags:** SYN, SYN-ACK, ACK, FIN, RST, PSH, URG — meaning and combinations
- **TCP handshake/teardown:** Normal three-way handshake vs. scan signatures (SYN scan, XMAS scan, NULL scan, FIN scan)
- **IP header fields:** TTL (OS fingerprinting), protocol numbers, fragmentation (evasion indicator)
- **ICMP types:** Echo request/reply, destination unreachable, time exceeded — normal vs. recon
- **Protocol numbers:** 6=TCP, 17=UDP, 1=ICMP, 47=GRE
- **IPv4 private ranges (RFC 1918):** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — mapped to SOC VLANs
- **Subnet notation:** /24 (256 hosts), /16 (65,536), /8 (16M) — quick reference

## What Does Not Change

- **Section 1 (Quick Access)** — Reference table, no enrichment needed
- **Section 14 (API Reference)** — Raw reference, interpretation lives in operational sections
- **Prerequisites section** — Already covers Git Bash, Python, SSH context
- **All existing commands/queries** — Preserved as-is, wrapped with guidance blocks

## Build Pipeline Changes

The current `build-playbook.py` uses `python-markdown` with extensions (`tables`, `fenced_code`, `codehilite`, `toc`, `attr_list`, `md_in_html`). One change is required:

- **Mermaid rendering:** Add a client-side `<script src="mermaid.min.js">` include in the HTML template so that fenced `mermaid` code blocks render as diagrams. This is a template change, not a pipeline logic change. Without this, the Section 2 architecture diagram renders as a raw code block.

No other pipeline changes are needed.

## Implementation Notes

- The private playbook at `~/.soc-playbook/soc-playbook.md` is the source of truth; the repo copy has placeholders
- See the Section Renumbering Map above for the old-to-new mapping; all internal cross-references must be updated per that table
- Enrichment blocks use blockquote formatting (>) to visually distinguish from operational content
- The Mermaid diagram in Section 2 follows C4 conventions
- GUI walkthroughs are written as precise navigation instructions suitable for Chrome Claude extension prompting
- Tool entries in Section 3 reference the specific IPs, ports, and credentials from Section 1
- **ELK runs on haccp bare metal** (10.10.30.25), not LXC 201 (destroyed). All ELK references must use haccp.
- **Code block headings:** The AAR template in Section 9 (new numbering) contains markdown headings inside a fenced code block. During renumbering, do NOT renumber headings inside code blocks — they are template content, not playbook sections.
- **Decommissioned items:** WF7 (Honeypot Intel Report) and RB-05 (Honeypot Anomaly) are historical. Mark these with a `> **DECOMMISSIONED** — Honeypot campaign ended 2026-03-12. Preserved for reference.` callout block. They still get interpretation blocks but no dead-end recovery (since they cannot be run).
- **WF9 and WF4:** WF9 (5-minute cron) exists in production and needs a subsection added in Section 10 (SOAR Operations). WF4 (Velociraptor triage) is a planned but unimplemented workflow — mention it as a roadmap item in the Shuffle tool entry (3.7), not as an operational section.
- **Capitol Signals (WF-CS1):** Out of scope for this playbook — it is a separate project. Not covered here.

## Scope

- **22 tool entries** in Section 3 (was 21 — Arkime added)
- **14 appendix tables** (A through N)
- **3 enrichment block types** across Sections 4-13
- **1 build pipeline change** (Mermaid JS include)
