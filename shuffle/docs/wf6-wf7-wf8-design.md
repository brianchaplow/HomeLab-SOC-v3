# AI/ML Workflow Suite Design

**Date:** 2026-02-18
**Author:** Brian Chaplow
**Status:** Approved

## Overview

Three new Shuffle SOAR workflows extending the SOC platform with AI/ML-powered analysis capabilities. All follow the same architectural pattern: query data, analyze/score, Ollama summarize, write to ELK, notify Discord.

## Suite Schedule

All triggered via system cron on brisket (same proven pattern as WF2/WF5).

| Workflow | Cadence | Schedule (EST) | Cron (UTC) | Purpose |
|----------|---------|---------------|------------|---------|
| WF6 — Model Drift Detector | Daily | 0900 | `0 14 * * *` | Is the ML scorer still accurate? |
| WF7 — Honeypot Intel Report | Weekly (Sun) | 1200 | `0 17 * * 0` | What are attackers doing to the honeypot? |
| WF8 — LLM Log Anomaly Finder | Daily | 1500 | `0 20 * * *` | What are the rules missing? |

Full daily Ollama schedule with new workflows:
- 0600: WF5 (cluster triage)
- 0605: WF2 (watch digest)
- 0900: WF6 (drift detection)
- 1200: WF7 (honeypot intel, Sundays only)
- 1500: WF8 (anomaly finder)
- 1805: WF2 (evening digest)

Minimum 3-hour gap between Ollama-heavy runs. No contention risk.

## Shared Infrastructure

- All use workflow variables (`$opensearch_url`, `$ollama_url`, etc.) per established convention
- New shared variables: `$elk_url` (https://10.10.30.23:9200), `$elk_user`, `$elk_pass` for writing to ELK indices
- New ELK indices: `ml-drift`, `honeypot-intel`, `log-anomalies`
- All post to `$discord_webhook`
- All triggered via system cron on brisket with trigger scripts in `/home/bchaplow/`

## Output Strategy

Discord for immediate notification, ELK for structured historical data enabling Kibana dashboards and trend analysis over time.

---

## WF6: Model Drift Detector

**Goal:** Compare daily ML score distributions against a baseline to detect model drift.

### Actions (4 nodes)

**1. `sample_and_score`** (execute_python)
- Query OpenSearch for ~200 random alerts from last 24h (stratified: some high-level, some low-level)
- POST each to `$ml_scorer_url/score`
- Collect distribution: mean, median, p95, % above 0.7 threshold, % labeled malicious
- Fetch stored baseline from ELK `ml-drift` index (most recent doc with `type: baseline`)
- If no baseline exists, save current as baseline and exit early

**2. `detect_drift`** (execute_python)
- Compare current vs baseline using statistical checks:
  - Mean score shift > 0.1
  - Malicious % change > 20 percentage points
  - p95 shift > 0.15
- Classify as `STABLE`, `MINOR_DRIFT`, or `SIGNIFICANT_DRIFT`
- If `SIGNIFICANT_DRIFT`, call Ollama to explain potential causes and whether retraining is warranted

**3. `write_elk`** (execute_python)
- Write structured result to ELK `ml-drift` index: timestamp, all metrics, drift classification, LLM explanation
- Builds time series for Kibana dashboarding

**4. `discord_notify`** (HTTP POST)
- Brief for STABLE days ("Model stable, mean=0.12, 2.1% malicious")
- Detailed for drift days with LLM explanation

### Baseline Management
- First run seeds the baseline
- Baseline auto-updates after 7 consecutive STABLE days
- SIGNIFICANT_DRIFT freezes baseline updates until manually acknowledged

---

## WF7: Honeypot Intel Report

**Goal:** Weekly structured intelligence report on GCP honeypot activity — credential trends, attacker geography, technique evolution. Feeds INST570 research.

### Actions (4 nodes)

**1. `query_honeypot_data`** (execute_python)
- Query ELK indices for past 7 days:
  - `honeypot-credentials`: top usernames, top passwords, new credentials not seen in prior weeks
  - `honeypot-access`: volume trend, top source IPs, top user-agents, HTTP method breakdown
  - `honeypot-wazuh`: top Wazuh rules, top MITRE techniques, top source countries
- Query previous week's `honeypot-intel` doc for week-over-week deltas
- Compute: total attempts, unique IPs, unique credential pairs, new-vs-returning IP ratio

**2. `generate_intel_report`** (execute_python)
- Feed aggregated stats to Ollama with structured CTI analyst prompt
- Sections: Executive Summary, Credential Analysis, Network Analysis, Technique Analysis, Week-over-Week Changes, Collection Gaps
- System prompt includes honeypot context (WordPress login lure, GCP VM, baseline traffic)
- `num_predict: 3000` for longer report format

**3. `write_elk`** (execute_python)
- Write to ELK `honeypot-intel` index: raw stats, LLM report text, week identifier, comparison deltas
- Becomes "previous week" baseline for next run

**4. `discord_report`** (HTTP POST)
- Post LLM-generated report to Discord
- If over 2000 chars, split into two messages (data + analysis, same as WF2)

---

## WF8: LLM Log Anomaly Finder

**Goal:** Hunt the long tail of rare, unusual log patterns that never trigger enough volume for attention but might be genuinely interesting. Complement to WF5 which covers the noisiest clusters.

**Architecture note (2026-02-20):** Candidates are split into internal network (PITBOSS, DC01, WS01, smokehouse, sear) and honeypot (gcp-vm) groups. Each group gets a tailored Ollama system prompt and its own Discord channel, preventing honeypot SSH brute force noise from drowning internal findings.

```
query_rare_patterns -> classify_anomalies -> write_elk -> discord_internal (unconditional)
                                                      \-> discord_honeypot (conditional: has_honeypot=="true")
```

### Actions (5 nodes)

**1. `query_rare_patterns`** (execute_python)
- Query OpenSearch for last 24h, targeting the unusual:
  - **Rare rules:** Bottom 20 rules by count (fired 1-5 times)
  - **Off-hours:** Alerts 0100-0500 EST on non-server agents (PITBOSS, WS01, DC01)
  - **New rules:** Rules that fired today with zero hits in prior 7 days
- Pull sample alert with full `_source` for each candidate
- Cap at 15 candidates total
- Split into `internal_candidates` and `honeypot_candidates` based on agent name (gcp-vm = honeypot)

**2. `classify_anomalies`** (execute_python)
- Two sequential Ollama calls with different system prompts:
  - **Internal prompt:** SOC analyst context — smokehouse SPAN noise, PITBOSS WiFi/T1092, AD lab VMs. Focus on lateral movement, privilege escalation, persistence.
  - **Honeypot prompt:** Internet-facing WordPress honeypot context — SSH brute force and scanning are EXPECTED baseline (classify as TRANSIENT). Only flag ANOMALOUS for novel TTPs, post-auth activity, web shells, or targeted enumeration.
- Classification categories: `ANOMALOUS`, `MISCONFIG`, `TRANSIENT`, `BLIND_SPOT`
- Builds separate Discord reports for each group
- Outputs `has_honeypot` flag for conditional branching

**3. `write_elk`** (execute_python)
- Write all classifications to ELK `log-anomalies` index with `source_group` field (`"internal"` or `"honeypot"`)
- Two SUMMARY docs (one per group)
- Passes through both Discord reports and `has_honeypot` flag

**4. `discord_internal`** (HTTP POST)
- Posts internal network findings to `$discord_webhook` (main SOC channel)
- Always fires (unconditional branch from write_elk)

**5. `discord_honeypot`** (HTTP POST)
- Posts honeypot findings to `$discord_webhook_honeypot` (dedicated honeypot channel)
- Conditional: only fires when `has_honeypot == "true"` (gcp-vm had rare patterns)

---

## Key Differences Between WF5 and WF8

| | WF5 (Cluster Triage) | WF8 (Anomaly Finder) |
|---|---|---|
| **Looks at** | Top 10 noisiest clusters | Bottom 20 rarest patterns |
| **Signal** | Volume | Novelty |
| **Question** | What's generating the most noise? | What's hiding in the quiet? |
| **Together** | Cover both ends of the alert spectrum |
