# HomeLab SOC Operational Playbook

**Author:** Brian Chaplow
**Last Updated:** 2026-03-04
**Scope:** Day-to-day SOC operations for HomeLab SOC v3

This playbook is the single operational reference for anyone sitting down to operate this SOC. Every command is copy-paste ready. Every procedure is step-by-step.

---

## Table of Contents

- [1. Quick Access Reference](#1-quick-access-reference)
- [2. Daily Operations Checklist](#2-daily-operations-checklist)
- [3. Working with Alerts](#3-working-with-alerts)
- [4. Triaging and Escalating Alerts](#4-triaging-and-escalating-alerts)
- [5. Investigating Alerts](#5-investigating-alerts)
- [6. Responding to Alerts](#6-responding-to-alerts)
- [7. TheHive Case Management (NIST 800-61 Aligned)](#7-thehive-case-management-nist-800-61-aligned)
- [8. SOAR Workflow Operations](#8-soar-workflow-operations)
- [9. Adversary Simulation Operations](#9-adversary-simulation-operations)
- [10. Scenario Runbooks](#10-scenario-runbooks)
- [11. Troubleshooting](#11-troubleshooting)
- [12. API & Query Reference](#12-api--query-reference)

---

## 1. Quick Access Reference

### 1.1 Service URLs and Credentials

| Service | URL | User | Password |
|---------|-----|------|----------|
| Wazuh Dashboard | https://10.10.20.30:5601 | admin | <PLATFORM_PASSWORD> |
| Wazuh API | https://10.10.20.30:55000 | wazuh-wui | <WAZUH_API_PASSWORD> |
| OpenSearch (Wazuh Indexer) | https://10.10.20.30:9200 | admin | (in .env on brisket) |
| Shuffle SOAR | https://10.10.20.30:3443 | admin | <PLATFORM_PASSWORD> |
| Shuffle API | http://10.10.20.30:5001 | -- | API key: <SHUFFLE_API_KEY> |
| TheHive | http://10.10.30.22:9000 | socadmin@thehive.local | <PLATFORM_PASSWORD> |
| Cortex | http://10.10.30.22:9001 | socadmin@SOC | <PLATFORM_PASSWORD> |
| Velociraptor | https://10.10.20.30:8889 | admin | <PLATFORM_PASSWORD> |
| Caldera | http://10.10.30.21:8888 | red / blue | <PLATFORM_PASSWORD> |
| ELK Kibana | http://10.10.30.23:5601 | elastic | <PLATFORM_PASSWORD> |
| ELK Elasticsearch | https://10.10.30.23:9200 | elastic | <PLATFORM_PASSWORD> |
| Grafana (brisket) | http://10.10.20.30:3000 | admin | (same as OpenSearch .env) |
| Grafana (smokehouse) | http://10.10.20.10:3000 | admin | (same as OpenSearch .env) |
| Prometheus | http://10.10.20.30:9090 | -- | -- |
| ML Scorer | http://10.10.20.30:5002 | -- | -- |
| Ollama | http://10.10.20.30:11434 | -- | -- |
| PBS | https://10.10.30.24:8007 | root@pam | <PLATFORM_PASSWORD> |

### 1.2 API Keys

| Key | Value | Used By |
|-----|-------|---------|
| TheHive API Key | <THEHIVE_API_KEY> | Shuffle workflows (WF1, WF2, WF3, WF5) |
| Cortex API Key | <CORTEX_API_KEY> | Cortex REST API (socadmin@SOC org-admin) |
| Shuffle API Key | <SHUFFLE_API_KEY> | External API calls to Shuffle |
| Caldera API Key | <CALDERA_API_KEY> | Header: `KEY: <CALDERA_API_KEY>` |

### 1.3 SSH Access

**From PITBOSS (LAN):**

```bash
ssh bchaplow@10.10.20.30            # brisket
ssh root@10.10.30.21                # smoker (passwordless)
ssh butcher@10.10.20.20             # sear
ssh -p 2222 bchaplow@10.10.20.10   # smokehouse QNAP
ssh root@10.10.30.20                # pitcrew (passwordless)
```

**From PITBOSS (Tailscale -- remote/travel):**

```bash
ssh bchaplow@100.124.139.56         # brisket
ssh butcher@100.86.67.91            # sear
ssh -p 2222 bchaplow@100.110.112.98 # smokehouse QNAP
```

### 1.4 VLAN Map

| VLAN | Subnet | Purpose |
|------|--------|---------|
| 10 | 10.10.10.0/24 | Management (OPNsense, MokerLink, PITBOSS) |
| 20 | 10.10.20.0/24 | SOC infrastructure (brisket, smokehouse, sear) |
| 30 | 10.10.30.0/24 | Lab (pitcrew, smoker, TheHive, ELK, AD) |
| 40 | 10.10.40.0/24 | Targets -- FULLY ISOLATED |
| 50 | 10.10.50.0/24 | IoT -- internet only |

### 1.5 Wazuh Agent Inventory

| Agent ID | Host | IP | VLAN | OS |
|----------|------|----|------|----|
| 001 | brisket | 10.10.20.30 | 20 | Ubuntu 24.04 |
| 002 | smokehouse | 10.10.20.10 | 20 | QTS (QNAP) |
| 003 | sear | 10.10.20.20 | 20 | Kali Linux |
| 004 | PITBOSS | 10.10.10.100 | 10 | Windows 11 |
| 005 | DC01 | 10.10.30.40 | 30 | Windows Server 2022 |
| 006 | WS01 | 10.10.30.41 | 30 | Windows 10 |
| 007 | DVWA | 10.10.40.10 | 40 | Debian |
| 008 | smoker | 10.10.30.21 | 30 | Proxmox VE |
| 009 | GCP VM | (external) | -- | Ubuntu (GCP) |
| -- | OPNsense | 10.10.10.1 | 10 | Syslog (514/UDP) |

---

## 2. Daily Operations Checklist

Run these 8 checks at the start of every shift. Total time: ~10 minutes.

### Step 1: Check Discord Notifications

Open the SOC Discord channels. Review any alerts posted by Shuffle workflows since the last shift. Note any WF1 threat enrichment alerts, WF2 watch turnover digests, WF5 daily triage summaries, or WF8 anomaly findings.

### Step 2: Verify Wazuh Agent Health

```bash
# Get JWT token
TOKEN=$(curl -s -u wazuh-wui:'<WAZUH_API_PASSWORD>' -k -X POST \
  "https://10.10.20.30:55000/security/user/authenticate" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# List all agents with status
curl -s -k -X GET "https://10.10.20.30:55000/agents?pretty=true&select=id,name,status,ip,os.name,lastKeepAlive" \
  -H "Authorization: Bearer $TOKEN"
```

Expected: All 10 agents show `status: active`. If any show `disconnected`, check the host and restart the agent:

```bash
# On the disconnected host (Linux)
sudo systemctl restart wazuh-agent

# On the disconnected host (Windows, from admin PowerShell)
Restart-Service WazuhSvc
```

### Step 3: Verify Shuffle Workflow Status

Open https://10.10.20.30:3443 and navigate to Workflows. Confirm all 7 workflows show as enabled (green toggle). Check the execution history for the last 24 hours:

- WF1: Should have executions for every level 8+ alert
- WF2: Should have 2 executions (06:05 and 18:05 EST)
- WF5: Should have 1 execution (06:00 EST)
- WF6: Should have 1 execution (09:00 EST)
- WF7: Should have 1 execution (Sunday 12:00 EST only)
- WF8: Should have 1 execution (15:00 EST)

If a cron workflow did not fire, check the brisket crontab:

```bash
ssh bchaplow@10.10.20.30
crontab -l
```

### Step 4: Review TheHive Open Cases

Open http://10.10.30.22:9000. Log in as socadmin@thehive.local. Check the case list filtered by status `New` and `InProgress`. Prioritize any severity 3 (High) or 4 (Critical) cases.

API alternative:

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/_search" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "_and": [
        {"_in": {"_field": "status", "list": ["New", "InProgress"]}}
      ]
    },
    "range": "0-50",
    "sort": ["-severity", "-createdAt"]
  }'
```

### Step 5: Check Grafana SOC Dashboard

Open http://10.10.20.30:3000 and load the "SOC v3 Overview" dashboard. Verify:

- All Prometheus scrape targets are UP (6 targets)
- No anomalous CPU/memory spikes on brisket
- GPU utilization is reasonable (Ollama + ML Scorer)
- Disk usage is below 80% on all hosts

### Step 6: Verify ELK Stack Containers

ELK containers on LXC 201 do NOT auto-start on reboot. Verify they are running:

```bash
ssh root@10.10.30.20   # SSH to pitcrew
pct exec 201 -- bash -c "cd /opt/elk && docker compose ps"
```

Expected: elasticsearch, kibana, fleet-server, and logstash all show as `running`. If not:

```bash
pct exec 201 -- bash -c "cd /opt/elk && docker compose up -d"
```

### Step 7: Check ML Scorer Health

```bash
curl -s http://10.10.20.30:5002/health
```

Expected response: `{"status": "healthy"}` (or equivalent). If the scorer is down:

```bash
ssh bchaplow@10.10.20.30
cd /path/to/ml-scorer && docker compose restart ml-scorer
```

### Step 8: Verify Velociraptor Client Count

Open https://10.10.20.30:8889. Navigate to the client search page. Verify 7 clients are enrolled and showing recent check-in times (<15 minutes). Clients: brisket, smokehouse, sear, DC01, WS01, DVWA, GCP VM.

---

## 3. Working with Alerts

### 3.1 Alert Severity Scale

Wazuh uses a 0-15 severity scale. The ossec.conf on this SOC is configured with `log_alert_level` at 3 (alerts below 3 are not stored) and Shuffle webhook at level 8+.

| Level | Classification | Stored | Forwarded to Shuffle | Action |
|-------|---------------|--------|---------------------|--------|
| 0-2 | System/debug | No | No | Ignored |
| 3-4 | Low | Yes | No | Logged only |
| 5-7 | Medium | Yes | No | Logged, review in daily triage |
| 8-9 | High | Yes | Yes (WF1) | Auto-enriched, Discord alert |
| 10-11 | High | Yes | Yes (WF1) | Auto-enriched, potential TheHive case |
| 12-13 | Critical | Yes | Yes (WF1) | Auto-enriched, TheHive case, potential auto-block |
| 14-15 | Critical | Yes | Yes (WF1) | Immediate response required |

### 3.2 Wazuh Dashboard Navigation

1. Open https://10.10.20.30:5601 and log in (admin / <PLATFORM_PASSWORD>)
2. Navigate to **Wazuh > Security Events** for the primary alert view
3. Use the time picker (top right) to set the window (default: last 24 hours)
4. Key filter fields:
   - `rule.level` -- filter by severity (e.g., >= 8 for high/critical)
   - `agent.name` -- filter by specific host
   - `rule.id` -- filter by specific rule
   - `rule.mitre.id` -- filter by MITRE ATT&CK technique
   - `data.srcip` -- filter by source IP
5. Click any alert row to expand full details
6. The **MITRE ATT&CK** module shows technique coverage across agents
7. The **Integrity Monitoring** module shows FIM alerts (syscheck)
8. The **Vulnerability Detection** module shows CVE findings per agent

### 3.3 OpenSearch Query Templates (Wazuh Alerts)

All queries target `https://10.10.20.30:9200`. Replace `PASSWORD` with the OpenSearch admin password from the .env file on brisket.

**Query 1: Last Hour Alerts**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-1h",
        "lte": "now"
      }
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip", "data.dstip"]
}'
```

**Query 2: Alerts by Source IP**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "term": {"data.srcip": "10.10.20.20"}
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip", "data.dstip"]
}'
```

**Query 3: Alerts by Destination IP**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "term": {"data.dstip": "10.10.40.10"}
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip", "data.dstip"]
}'
```

**Query 4: Alerts by Rule ID**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "term": {"rule.id": "9000001"}
  },
  "_source": ["@timestamp", "rule.level", "rule.description", "agent.name", "data.srcip", "full_log"]
}'
```

**Query 5: Alerts by Agent Name**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "term": {"agent.name": "PITBOSS"}
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "data.srcip"]
}'
```

**Query 6: Critical Alerts (Level 12+)**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "range": {
      "rule.level": {"gte": 12}
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip", "rule.mitre.id"]
}'
```

**Query 7: High Alerts (Level 8+)**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 100,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "range": {
      "rule.level": {"gte": 8}
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip"]
}'
```

**Query 8: MITRE ATT&CK Technique Aggregation**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  },
  "aggs": {
    "mitre_techniques": {
      "terms": {
        "field": "rule.mitre.id",
        "size": 30,
        "order": {"_count": "desc"}
      },
      "aggs": {
        "tactic": {
          "terms": {"field": "rule.mitre.tactic", "size": 5}
        }
      }
    }
  }
}'
```

**Query 9: Top 20 Source IPs (Last 24h)**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  },
  "aggs": {
    "top_src_ips": {
      "terms": {
        "field": "data.srcip",
        "size": 20,
        "order": {"_count": "desc"}
      }
    }
  }
}'
```

**Query 10: Top 20 Rules Fired (Last 24h)**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  },
  "aggs": {
    "top_rules": {
      "terms": {
        "field": "rule.id",
        "size": 20,
        "order": {"_count": "desc"}
      },
      "aggs": {
        "description": {
          "terms": {"field": "rule.description", "size": 1}
        }
      }
    }
  }
}'
```

**Query 11: Authentication Failures (Last 24h)**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"bool": {
          "should": [
            {"match_phrase": {"rule.description": "authentication fail"}},
            {"match_phrase": {"rule.description": "login fail"}},
            {"terms": {"rule.groups": ["authentication_failed", "invalid_login"]}}
          ]
        }}
      ]
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip", "data.dstuser"]
}'
```

**Query 12: File Integrity Monitoring (Syscheck) Events**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"term": {"rule.groups": "syscheck"}}
      ]
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "syscheck.path", "syscheck.event", "syscheck.md5_after"]
}'
```

**Query 13: Vulnerability Detections**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-7d"}}},
        {"term": {"rule.groups": "vulnerability-detector"}}
      ]
    }
  },
  "_source": ["@timestamp", "agent.name", "data.vulnerability.cve", "data.vulnerability.severity", "data.vulnerability.package.name", "data.vulnerability.title"]
}'
```

**Query 14: Zeek HTTP Requests by Source IP**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-http/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "term": {"id.orig_h": "10.10.20.20"}
  },
  "_source": ["@timestamp", "id.orig_h", "id.resp_h", "id.resp_p", "method", "host", "uri", "status_code", "user_agent"]
}'
```

**Query 15: Zeek DNS Queries by Domain**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-dns/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "wildcard": {"query": "*example.com"}
  },
  "_source": ["@timestamp", "id.orig_h", "query", "qtype_name", "answers", "rcode_name"]
}'
```

**Query 16: Zeek Connections Between Two IPs**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-conn/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"id.orig_h": "10.10.20.20"}},
        {"term": {"id.resp_h": "10.10.40.10"}}
      ]
    }
  },
  "_source": ["@timestamp", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "history"]
}'
```

**Query 17: Alerts by MITRE Technique ID**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "term": {"rule.mitre.id": "T1190"}
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip", "rule.mitre.tactic"]
}'
```

### 3.4 ELK Elasticsearch Queries

All queries target `https://10.10.30.23:9200` with user `elastic` and password `<PLATFORM_PASSWORD>`.

**Query 1: Detection Rule Alerts (Last 24h)**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/.alerts-security.alerts-default/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  },
  "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity", "host.name", "source.ip", "destination.ip"]
}'
```

**Query 2: Alerts by MITRE Tactic**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/.alerts-security.alerts-default/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "range": {"@timestamp": {"gte": "now-7d"}}
  },
  "aggs": {
    "mitre_tactics": {
      "terms": {
        "field": "kibana.alert.rule.threat.tactic.name",
        "size": 20
      }
    }
  }
}'
```

**Query 3: Alerts by Agent Hostname**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/.alerts-security.alerts-default/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "term": {"host.name": "DC01"}
  },
  "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity", "source.ip", "event.action"]
}'
```

**Query 4: Windows EventID Search**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/logs-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "4625"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "host.name", "event.code", "event.action", "source.ip", "user.name"]
}'
```

**Query 5: Linux Authentication Events**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/logs-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"event.dataset": "system.auth"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "host.name", "event.action", "user.name", "source.ip"]
}'
```

**Query 6: Fleet Agent Status**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/.fleet-agents/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "_source": ["local_metadata.host.hostname", "status", "last_checkin", "policy_id"]
}'
```

**Query 7: Honeypot Credential Captures**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/honeypot-credentials/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  }
}'
```

**Query 8: Honeypot Top Source IPs by Country**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/honeypot-access/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "range": {"@timestamp": {"gte": "now-7d"}}
  },
  "aggs": {
    "by_country": {
      "terms": {
        "field": "geoip.country_name",
        "size": 20,
        "order": {"_count": "desc"}
      }
    }
  }
}'
```

**Query 9: Honeypot Wazuh MITRE Aggregation**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/honeypot-wazuh/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "range": {"@timestamp": {"gte": "now-7d"}}
  },
  "aggs": {
    "mitre_techniques": {
      "terms": {
        "field": "rule.mitre.id",
        "size": 20
      }
    }
  }
}'
```

**Query 10: Events by Dataset (Last 24h)**

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/logs-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  },
  "aggs": {
    "by_dataset": {
      "terms": {
        "field": "event.dataset",
        "size": 30,
        "order": {"_count": "desc"}
      }
    }
  }
}'
```

### 3.5 Reading Shuffle WF1 Execution History

1. Open https://10.10.20.30:3443, navigate to Workflows, open WF1
2. Click the clock icon (execution history) in the top right
3. Each execution shows:
   - **Trigger:** The Wazuh alert JSON that initiated the workflow
   - **AbuseIPDB result:** IP reputation score (0-100 confidence)
   - **ML Scorer result:** XGBoost threat probability (0.0-1.0)
   - **Ollama result:** LLM-generated triage narrative
   - **Combined score:** `max(abuseipdb_normalized, ml_xgboost_score)`
   - **Actions taken:** Discord notification, TheHive case creation, Cloudflare block
4. Failed executions show a red indicator. Click to see which action failed and the error message
5. Common failures: Ollama timeout (GPU contention), TheHive unreachable (LXC stopped), ML Scorer down

---

## 4. Triaging and Escalating Alerts

### 4.1 ML Score Interpretation

The XGBoost ML Scorer (brisket:5002) returns a threat probability between 0.0 and 1.0. The model was trained on labeled attack data from Caldera campaigns with a PR-AUC of 0.9998.

| Score Range | Classification | Meaning |
|-------------|---------------|---------|
| 0.0 - 0.3 | Low | Normal traffic pattern. Likely benign. |
| 0.3 - 0.7 | Moderate | Unusual pattern. May warrant investigation. |
| 0.7 - 0.9 | High | Strong match to known attack patterns. Investigate promptly. |
| 0.9 - 1.0 | Critical | Near-certain match to attack behavior. Immediate response. |

Manual scoring (for alerts not auto-scored by WF1):

```bash
curl -s -X POST "http://10.10.20.30:5002/score" \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "10.10.20.20",
    "dst_ip": "10.10.40.10",
    "dst_port": 80,
    "protocol": "TCP",
    "rule_level": 12,
    "rule_id": "9000001"
  }'
```

### 4.2 AbuseIPDB Interpretation

WF1 queries AbuseIPDB for external IP reputation. The confidence score indicates how likely the IP is malicious based on community reports.

| Score Range | Classification | Action |
|-------------|---------------|--------|
| 0 - 25 | Clean | No reputation issues. Likely benign. |
| 25 - 50 | Suspicious | Some reports exist. Investigate context. |
| 50 - 75 | Likely malicious | Multiple abuse reports. Escalate. |
| 75 - 90 | High confidence malicious | Strong evidence. Block candidate. |
| 90 - 100 | Confirmed malicious | Known bad actor. Auto-block threshold. |

Note: AbuseIPDB only applies to external (public) IPs. Internal lab IPs (10.10.x.x) will return 0 or not found.

### 4.3 Reading Ollama Triage Summaries

WF1 sends alert context to Ollama (qwen3:8b) with a `/no_think` prefix to suppress reasoning tokens. The LLM returns a structured triage summary containing:

- **Alert classification:** What type of activity this represents
- **Risk assessment:** Contextual severity given the source, target, and technique
- **Recommended next steps:** Suggested investigation or response actions

Interpret LLM summaries as analyst-assistance, not ground truth. The model may hallucinate context. Always verify claims against actual alert data and Zeek logs.

### 4.4 Escalation Decision Matrix

Use this matrix to decide the response action based on the combined enrichment score and the original Wazuh rule level.

| Combined Score | Rule Level 8-9 | Rule Level 10-11 | Rule Level 12-13 | Rule Level 14-15 |
|---------------|----------------|-------------------|-------------------|-------------------|
| 0.0 - 0.3 | Log only | Log only | Review within 4h | Review within 1h |
| 0.3 - 0.5 | Log only | Review within 4h | Review within 1h | Investigate immediately |
| 0.5 - 0.7 | Review within 4h | Review within 1h | Investigate immediately | Investigate + escalate |
| 0.7 - 0.9 | Review within 1h | Investigate immediately | Investigate + TheHive case | Investigate + block + case |
| 0.9 - 1.0 | Investigate immediately | Investigate + TheHive case | Block + TheHive case | Block + case + page on-call |

**Actions defined:**

- **Log only:** No immediate action. Appears in WF5 daily triage cluster.
- **Review within Xh:** Manually review in Wazuh Dashboard during the specified window.
- **Investigate immediately:** Open Zeek logs, check related alerts, assess scope.
- **Investigate + TheHive case:** Create a case with all enrichment context.
- **Block:** Cloudflare WAF rule (external) or OPNsense/active-response (internal).
- **Page on-call:** For production environments. In this lab, treat as highest priority.

### 4.5 Creating TheHive Cases Manually

**Via API:**

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious SQL Injection from 10.10.20.20 to DVWA",
    "description": "## Alert Summary\n\nWazuh rule 9000001 fired at 2026-01-09T14:30:46Z.\nSource: 10.10.20.20 (sear)\nTarget: 10.10.40.10 (DVWA) port 80\nML Score: 0.92\nAbuseIPDB: N/A (internal IP)\n\n## Raw Alert\n\nUNION SELECT username,password FROM users",
    "severity": 3,
    "tlp": 2,
    "pap": 2,
    "flag": false,
    "tags": ["sql-injection", "vlan40", "purple-team", "T1190"],
    "status": "New"
  }'
```

**Via UI:**

1. Open http://10.10.30.22:9000 and log in
2. Click "New Case" (+ button)
3. Fill in: Title, Severity (1-4), TLP, PAP, Description, Tags
4. Click Create
5. Add observables (IPs, hashes, URLs) under the Observables tab
6. Create IR tasks under the Tasks tab (see Section 7.3)

### 4.6 Promoting Alerts to Cases

When Shuffle WF1 auto-creates a TheHive case, it includes:

- Alert JSON from Wazuh
- AbuseIPDB reputation data
- ML Scorer threat probability
- LLM triage summary

To manually promote a Wazuh alert to a TheHive case:

1. Find the alert in the Wazuh Dashboard
2. Copy the key fields: timestamp, rule ID, rule description, source IP, destination IP, agent name, MITRE technique
3. Create the case using the API command in Section 4.5 or the UI
4. Add all relevant IPs and hashes as observables
5. Set severity based on the escalation matrix (Section 4.4)
6. Assign to yourself or the appropriate analyst

---

## 5. Investigating Alerts

### 5.1 Zeek Flow Correlation

When investigating an alert, correlate with Zeek network metadata. Zeek indices on brisket OpenSearch provide protocol-level visibility.

**zeek-conn (Connection logs):**

Key fields: `id.orig_h` (source IP), `id.orig_p` (source port), `id.resp_h` (dest IP), `id.resp_p` (dest port), `proto`, `service` (DPI-detected protocol), `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`.

`conn_state` values:
- `S0` -- Connection attempt, no reply (scan)
- `S1` -- Connection established, no data
- `SF` -- Normal established and terminated
- `REJ` -- Connection rejected
- `RSTO` -- Connection reset by originator
- `RSTOS0` -- Reset after SYN, no SYN-ACK seen

```bash
# All connections from a suspect IP in the last hour
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-conn/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 100,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"id.orig_h": "10.10.20.20"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "history"]
}'
```

**zeek-http (HTTP requests):**

Key fields: `method`, `host`, `uri`, `status_code`, `user_agent`, `resp_mime_types`, `orig_fuids` (file UID link).

```bash
# HTTP requests to a target in the last hour
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-http/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 100,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"id.resp_h": "10.10.40.10"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "id.orig_h", "method", "host", "uri", "status_code", "user_agent", "resp_mime_types"]
}'
```

**zeek-dns (DNS queries):**

Key fields: `query` (domain queried), `qtype_name` (A, AAAA, MX, TXT, etc.), `answers`, `rcode_name` (NOERROR, NXDOMAIN, SERVFAIL).

```bash
# DNS queries from a host
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-dns/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"id.orig_h": "10.10.20.20"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "id.orig_h", "query", "qtype_name", "answers", "rcode_name"]
}'
```

**zeek-ssl (TLS connections):**

Key fields: `server_name` (SNI), `version`, `cipher`, `validation_status`, `ja3` (client fingerprint), `ja3s` (server fingerprint).

```bash
# TLS connections from a host
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-ssl/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "term": {"id.orig_h": "10.10.20.20"}
  },
  "_source": ["@timestamp", "id.orig_h", "id.resp_h", "id.resp_p", "server_name", "version", "cipher", "ja3", "validation_status"]
}'
```

**zeek-files (File transfers):**

Key fields: `source` (HTTP, FTP, etc.), `mime_type`, `filename`, `total_bytes`, `md5`, `sha1`, `sha256`.

```bash
# Files transferred involving a host
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-files/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "should": [
        {"term": {"tx_hosts": "10.10.20.20"}},
        {"term": {"rx_hosts": "10.10.20.20"}}
      ]
    }
  },
  "_source": ["@timestamp", "tx_hosts", "rx_hosts", "source", "mime_type", "filename", "total_bytes", "md5", "sha256"]
}'
```

### 5.2 Velociraptor Hunts

Open https://10.10.20.30:8889 and navigate to the target client. Use the notebook interface or VQL query bar for these investigations.

**List running processes:**

```sql
SELECT Pid, Name, Exe, CommandLine, Username, CreateTime
FROM process_tracker_pslist()
ORDER BY CreateTime DESC
LIMIT 100
```

**Network connections:**

```sql
SELECT Pid, Name, Status, Laddr, Raddr, Type
FROM connections()
WHERE Status = "ESTABLISHED"
```

**Search for suspicious files by hash:**

```sql
SELECT OSPath, Size, Mtime, hash(path=OSPath, hashselect="SHA256") AS SHA256
FROM glob(globs="/tmp/**")
WHERE SHA256.SHA256 = "SUSPECT_HASH_HERE"
```

**Startup items (persistence):**

```sql
SELECT Name, Source, Command, Location
FROM Artifact.Windows.Sys.StartupItems()
```

For Linux:

```sql
SELECT * FROM Artifact.Linux.Sys.Cron()
```

**Scheduled tasks (Windows):**

```sql
SELECT Name, Path, Actions, Triggers, Enabled, LastRunTime
FROM Artifact.Windows.System.TaskScheduler()
WHERE Enabled = true
```

**Recently modified files (last 24h):**

```sql
SELECT OSPath, Size, Mtime, Atime
FROM glob(globs="/etc/**")
WHERE Mtime > now() - 86400
ORDER BY Mtime DESC
```

**Running a hunt across all clients:**

1. Navigate to Hunt Manager (left sidebar)
2. Click "New Hunt"
3. Select the artifact (e.g., `Generic.Client.Info` for basic sweep)
4. Choose target clients (All or specific labels)
5. Launch the hunt
6. Results populate as clients check in and execute the VQL

### 5.3 Running Cortex Analyzers

Cortex (http://10.10.30.22:9001) provides automated observable analysis. Five analyzers are configured.

**Available analyzers and when to use them:**

| Analyzer | Input Type | When to Use |
|----------|-----------|-------------|
| AbuseIPDB_1_0 | IP | Any external IP in an alert |
| VirusTotal_GetReport_3_1 | Hash, URL, domain | Suspicious files, URLs, or domains (requires API key) |
| Shodan_DNSResolve_2_0 | Domain | External domains for exposed services (requires API key) |
| Abuse_Finder_3_0 | IP, domain | Find abuse contact for reporting |
| GoogleDNS_resolve_1_0_0 | Domain | Basic DNS resolution check |

**Running an analyzer via API:**

```bash
# Run AbuseIPDB analyzer on an IP
curl -s -X POST "http://10.10.30.22:9001/api/analyzer/AbuseIPDB_1_0/run" \
  -H "Authorization: Bearer <CORTEX_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "203.0.113.50",
    "dataType": "ip",
    "tlp": 2,
    "message": "Checking reputation for alert source IP"
  }'
```

The response includes a job ID. Poll for results:

```bash
# Get job result (replace JOB_ID)
curl -s "http://10.10.30.22:9001/api/job/JOB_ID/waitreport?atMost=5minutes" \
  -H "Authorization: Bearer <CORTEX_API_KEY>"
```

**Running analyzers from TheHive UI:**

1. Open the case in TheHive
2. Navigate to the Observables tab
3. Click on the observable (IP, hash, domain)
4. Click "Run Analyzers"
5. Select the relevant analyzers from the list
6. Results appear in the observable's Analyzer Reports section

### 5.4 Wazuh FIM (Syscheck) Correlation

When a syscheck alert fires, correlate the file change with other activity on that host.

1. Note the `syscheck.path` from the alert (the file that changed)
2. Note the `agent.name` and timestamp
3. Query for all alerts from that agent in the surrounding time window (+-30 min):

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 100,
  "sort": [{"@timestamp": {"order": "asc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"agent.name": "AGENT_NAME"}},
        {"range": {"@timestamp": {"gte": "ALERT_TIME||-30m", "lte": "ALERT_TIME||+30m"}}}
      ]
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "data.srcip", "syscheck.path"]
}'
```

4. Check if there were login events, process executions, or network connections around the same time
5. Use Velociraptor to inspect the changed file on the endpoint
6. Compare the `syscheck.md5_after` hash against VirusTotal (via Cortex)

### 5.5 ELK Detection Rule Cross-Reference

When a Wazuh alert fires, check if ELK detection rules also triggered for the same activity. This provides corroboration across two independent detection engines.

1. Note the timestamp, source IP, and target from the Wazuh alert
2. Query ELK for detection alerts in the same time window:

```bash
curl -k -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/.alerts-security.alerts-default/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "ALERT_TIME||-15m", "lte": "ALERT_TIME||+15m"}}},
        {"term": {"host.name": "TARGET_HOSTNAME"}}
      ]
    }
  },
  "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity", "source.ip", "event.action"]
}'
```

3. If both Wazuh and ELK detect the same activity, increase confidence in the alert
4. Note which MITRE techniques each engine mapped to -- they may provide complementary coverage

---

## 6. Responding to Alerts

### 6.1 Blocking IPs via Cloudflare

**Automated (WF1):**

Shuffle WF1 automatically blocks external IPs via Cloudflare WAF when the combined score exceeds the threshold. This is currently **disabled for honeypot mode** (branch condition `HONEYPOT_DISABLED` in WF1). When enabled, WF1 creates a Cloudflare WAF rule using the `$cf_api_token` and `$cf_account_id` workflow variables.

**Manual Cloudflare block:**

```bash
# Block a single IP via Cloudflare WAF (replace with your token and account ID)
curl -s -X POST \
  "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/firewall/access_rules/rules" \
  -H "Authorization: Bearer CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "block",
    "configuration": {
      "target": "ip",
      "value": "203.0.113.50"
    },
    "notes": "Blocked by SOC analyst - TheHive Case #XXX - AbuseIPDB score 95"
  }'
```

**Note:** Cloudflare blocks only apply to traffic routed through Cloudflare (the GCP VM hosting brianchaplow.com and bytesbourbonbbq.com). Internal lab traffic is not affected by Cloudflare rules.

### 6.2 Endpoint Isolation

**Option A: Velociraptor quarantine**

Use Velociraptor to collect forensic artifacts from a compromised endpoint before isolation:

1. Open https://10.10.20.30:8889
2. Navigate to the target client
3. Open a VQL notebook and run collection artifacts:

```sql
-- Collect process list, network connections, and recent files
SELECT * FROM Artifact.Windows.System.Pslist()
SELECT * FROM connections()
SELECT OSPath, Size, Mtime FROM glob(globs="C:/Users/*/Downloads/**")
```

4. After collection, use VQL to disable network (Windows):

```sql
SELECT * FROM execve(argv=["netsh", "interface", "set", "interface", "Ethernet", "admin=disable"])
```

**Option B: OPNsense firewall isolation**

For immediate network isolation, add a firewall rule on OPNsense to block all traffic to/from the compromised host.

1. SSH to OPNsense or use the web UI (https://10.10.10.1)
2. Add a block rule on the relevant VLAN interface:
   - Source: the compromised host IP
   - Destination: any
   - Action: Block
3. Place the rule at the top of the interface rule list

**Option C: Wazuh Active Response**

Wazuh has active response commands configured in ossec.conf. Available commands:

| Command | Effect | Timeout Support |
|---------|--------|----------------|
| `firewall-drop` | iptables DROP rule on the agent host | Yes |
| `host-deny` | Adds IP to /etc/hosts.deny | Yes |
| `route-null` | Null-routes the IP on the agent | Yes |
| `disable-account` | Disables a user account | Yes |

Trigger active response via the Wazuh API:

```bash
TOKEN=$(curl -s -u wazuh-wui:'<WAZUH_API_PASSWORD>' -k -X POST \
  "https://10.10.20.30:55000/security/user/authenticate" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# Run firewall-drop on agent 001 (brisket) for IP 203.0.113.50
curl -s -k -X PUT \
  "https://10.10.20.30:55000/active-response?pretty=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "firewall-drop0",
    "arguments": ["203.0.113.50"],
    "custom": false
  }'
```

### 6.3 TheHive Response Documentation

Every response action must be documented in the corresponding TheHive case.

**Adding observables:**

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/artifact" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "ip",
    "data": "203.0.113.50",
    "message": "Source IP of SQL injection attack",
    "tlp": 2,
    "ioc": true,
    "tags": ["malicious", "sql-injection"]
  }'
```

**Adding a task:**

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/task" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Containment: Block source IP",
    "status": "InProgress",
    "description": "Block 203.0.113.50 via Cloudflare WAF and OPNsense firewall rule.",
    "owner": "socadmin"
  }'
```

**Adding a task log (evidence/notes):**

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/task/TASK_ID/log" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Cloudflare WAF rule created at 2026-01-09T15:00:00Z. Rule ID: cf-rule-12345. IP 203.0.113.50 now returns 403 on all Cloudflare-fronted properties."
  }'
```

**Closing a task:**

```bash
curl -s -X PATCH "http://10.10.30.22:9000/api/case/task/TASK_ID" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"status": "Completed"}'
```

---

## 7. TheHive Case Management (NIST 800-61 Aligned)

This section defines the full case management lifecycle aligned with NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide). Every confirmed security event follows this workflow.

### 7.1 Case Creation

**Severity levels:**

| Severity | Level | Description | Example |
|----------|-------|-------------|---------|
| Low | 1 | Informational event or minor policy violation | Failed login attempts below threshold |
| Medium | 2 | Suspicious activity requiring investigation | Unusual outbound DNS queries |
| High | 3 | Confirmed malicious activity with limited impact | SQL injection against isolated DVWA |
| Critical | 4 | Active compromise or data exfiltration | Ransomware execution on domain controller |

**TLP (Traffic Light Protocol):**

| TLP | Color | Sharing |
|-----|-------|---------|
| 0 | WHITE | Unlimited sharing |
| 1 | GREEN | Community sharing (sector peers) |
| 2 | AMBER | Limited sharing (organization + need-to-know) |
| 3 | RED | Restricted (named recipients only) |

Default for this lab: TLP:AMBER (2) for most cases. Use TLP:RED (3) for cases involving real credentials or PII.

**PAP (Permissible Actions Protocol):**

| PAP | Color | Permitted Actions |
|-----|-------|-------------------|
| 0 | WHITE | Any action, active scanning permitted |
| 1 | GREEN | Active investigation, no external contact with threat actor |
| 2 | AMBER | Passive investigation only, no active probing |
| 3 | RED | No action beyond reading the report |

Default for this lab: PAP:WHITE (0) for purple team exercises. Use PAP:AMBER (2) for real external threats (honeypot-sourced cases).

**Tag taxonomy:**

Use consistent tags across all cases:

- **Attack type:** `sql-injection`, `brute-force`, `port-scan`, `malware`, `credential-stuffing`, `lateral-movement`, `privilege-escalation`, `data-exfiltration`, `command-and-control`, `persistence`
- **MITRE technique:** `T1190`, `T1110`, `T1059`, etc.
- **Source:** `purple-team`, `honeypot`, `external`, `insider`
- **VLAN:** `vlan10`, `vlan20`, `vlan30`, `vlan40`
- **Tool:** `sqlmap`, `nmap`, `metasploit`, `caldera`, `hydra`

**API case creation example:**

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[SEVERITY-3] SQL Injection - sear to DVWA - T1190",
    "description": "## Incident Summary\n\nWazuh rule 9000001 (HOMELAB SQL Injection - UNION SELECT) fired at 2026-01-09T14:30:46Z.\n\n**Source:** 10.10.20.20 (sear, VLAN 20)\n**Target:** 10.10.40.10 (DVWA, VLAN 40)\n**Port:** 80/TCP\n\n## Enrichment\n\n- ML Score: 0.92 (Critical)\n- AbuseIPDB: N/A (internal)\n- LLM Triage: SQL injection attack using UNION-based technique to extract credentials\n\n## Evidence\n\n- Suricata SID 9000001, 9000003, 9000004, 9000005\n- ET SID 2006446\n- SQLmap user-agent detected",
    "severity": 3,
    "tlp": 2,
    "pap": 0,
    "flag": false,
    "tags": ["sql-injection", "T1190", "purple-team", "vlan40", "sqlmap"],
    "status": "New"
  }'
```

### 7.2 Case Workflow

**Status progression:**

```
New --> InProgress --> Resolved
```

| Status | When | Action |
|--------|------|--------|
| New | Case created (auto or manual) | Analyst reviews and assigns |
| InProgress | Investigation active | Analyst works through IR tasks |
| Resolved | Investigation complete | Set resolution status (see below) |

**Resolution statuses:**

| Resolution | When to Use |
|------------|-------------|
| TruePositive | Confirmed malicious activity occurred |
| FalsePositive | Alert triggered but no actual threat (tune the rule) |
| Indeterminate | Unable to confirm or deny with available evidence |

**Impact levels (for TruePositive cases):**

| Impact | Description |
|--------|-------------|
| NoImpact | Attack detected but no systems affected (blocked or isolated) |
| WithImpact | Systems were affected but contained |
| NotApplicable | Lab exercise or purple team activity |

**Updating case status via API:**

```bash
# Move to InProgress
curl -s -X PATCH "http://10.10.30.22:9000/api/case/CASE_ID" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"status": "InProgress"}'

# Resolve as TruePositive with NoImpact
curl -s -X PATCH "http://10.10.30.22:9000/api/case/CASE_ID" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "Resolved",
    "resolutionStatus": "TruePositive",
    "impactStatus": "NoImpact",
    "summary": "Confirmed SQL injection attack from sear to DVWA during purple team exercise. All 5 custom Suricata rules fired correctly. No impact -- DVWA is an intentionally vulnerable target on isolated VLAN 40."
  }'
```

### 7.3 IR Phase Tasks

For every confirmed incident (TruePositive), create these 5 tasks aligned with NIST 800-61 Section 3:

**Task 1: Identification**

Purpose: Confirm the incident, determine scope, and document initial findings.

Checklist:
- Confirm the alert is a true positive (not a false positive or test)
- Identify all affected systems (IPs, hostnames, agent IDs)
- Identify the attack vector (MITRE technique)
- Determine the timeline (first alert to detection)
- Document initial indicators of compromise (IOCs)
- Assign severity based on the escalation matrix

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/task" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Phase 1: Identification",
    "group": "NIST 800-61",
    "description": "Confirm the incident and determine scope.\n\n- [ ] Confirm true positive\n- [ ] Identify all affected systems\n- [ ] Identify attack vector and MITRE technique\n- [ ] Establish timeline\n- [ ] Document IOCs\n- [ ] Assign severity",
    "status": "Waiting",
    "order": 1
  }'
```

**Task 2: Containment**

Purpose: Stop the attack from spreading and preserve evidence.

Short-term containment (immediate):
- Block attacker IP (Cloudflare, OPNsense, or Wazuh active-response)
- Isolate affected endpoint if compromised (Velociraptor or network isolation)
- Disable compromised accounts

Long-term containment:
- Apply temporary firewall rules
- Increase monitoring on affected systems
- Preserve forensic images before remediation

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/task" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Phase 2: Containment",
    "group": "NIST 800-61",
    "description": "Stop the spread and preserve evidence.\n\n**Short-term:**\n- [ ] Block attacker IP\n- [ ] Isolate affected endpoint\n- [ ] Disable compromised accounts\n\n**Long-term:**\n- [ ] Apply temporary firewall rules\n- [ ] Increase monitoring\n- [ ] Preserve forensic images",
    "status": "Waiting",
    "order": 2
  }'
```

**Task 3: Eradication**

Purpose: Remove the threat from the environment.

Checklist:
- Remove malware or unauthorized files
- Patch exploited vulnerabilities
- Reset compromised credentials
- Remove unauthorized accounts or persistence mechanisms
- Verify clean state with Velociraptor artifact collection

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/task" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Phase 3: Eradication",
    "group": "NIST 800-61",
    "description": "Remove the threat from the environment.\n\n- [ ] Remove malware or unauthorized files\n- [ ] Patch exploited vulnerabilities\n- [ ] Reset compromised credentials\n- [ ] Remove persistence mechanisms\n- [ ] Verify clean state (Velociraptor sweep)",
    "status": "Waiting",
    "order": 3
  }'
```

**Task 4: Recovery**

Purpose: Restore systems to normal operation and verify.

Checklist:
- Restore systems from clean backup (PBS if needed)
- Re-enable network connectivity
- Verify services are functioning normally
- Monitor for re-infection (24-72 hour watch period)
- Remove temporary containment rules when confident

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/task" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Phase 4: Recovery",
    "group": "NIST 800-61",
    "description": "Restore normal operations.\n\n- [ ] Restore from backup if needed\n- [ ] Re-enable network connectivity\n- [ ] Verify service functionality\n- [ ] Monitor for re-infection (24-72h)\n- [ ] Remove temporary containment rules",
    "status": "Waiting",
    "order": 4
  }'
```

**Task 5: Lessons Learned**

Purpose: Document what happened, what worked, what did not, and what to improve. This is where the After-Action Report (AAR) lives.

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/task" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Phase 5: Lessons Learned",
    "group": "NIST 800-61",
    "description": "Document the incident and improve defenses.\n\n- [ ] Complete After-Action Report (AAR)\n- [ ] Update detection rules if needed\n- [ ] Update runbooks if needed\n- [ ] Share findings with team (Discord)\n- [ ] Update this case summary",
    "status": "Waiting",
    "order": 5
  }'
```

### 7.4 Observable Management

**Supported observable types:**

| Data Type | Description | Example | Analyzers to Run |
|-----------|-------------|---------|-----------------|
| `ip` | IPv4 or IPv6 address | 203.0.113.50 | AbuseIPDB, Abuse_Finder, Shodan |
| `domain` | Domain name | evil-domain.com | GoogleDNS, Shodan, Abuse_Finder |
| `url` | Full URL | https://evil.com/payload | VirusTotal |
| `hash` | File hash (MD5/SHA1/SHA256) | d41d8cd98f... | VirusTotal |
| `filename` | File name | malware.exe | (manual review) |
| `mail` | Email address | attacker@evil.com | Abuse_Finder |
| `fqdn` | Fully qualified domain name | c2.evil.com | GoogleDNS, Shodan |
| `user-agent` | HTTP User-Agent string | sqlmap/1.7.2 | (manual review) |
| `other` | Any other indicator | Process name, registry key | (manual review) |

**Adding an observable via API:**

```bash
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/artifact" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "ip",
    "data": "203.0.113.50",
    "message": "Source IP seen in brute-force attack against SSH",
    "tlp": 2,
    "ioc": true,
    "sighted": true,
    "tags": ["brute-force", "ssh", "external"]
  }'
```

**Running analyzers on an observable via API:**

```bash
# First, get the observable ID from the case
curl -s "http://10.10.30.22:9000/api/case/artifact/_search" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"query": {"_parent": {"_type": "case", "_query": {"_id": "CASE_ID"}}}}'

# Run analyzer on the observable (use Cortex API)
curl -s -X POST "http://10.10.30.22:9001/api/analyzer/AbuseIPDB_1_0/run" \
  -H "Authorization: Bearer <CORTEX_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "203.0.113.50",
    "dataType": "ip",
    "tlp": 2,
    "message": "AbuseIPDB check for brute-force source"
  }'
```

**Bulk import observables:**

```bash
# Add multiple observables at once
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/artifact" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '[
    {"dataType": "ip", "data": "203.0.113.50", "message": "Attack source 1", "tlp": 2, "ioc": true, "tags": ["scanner"]},
    {"dataType": "ip", "data": "198.51.100.25", "message": "Attack source 2", "tlp": 2, "ioc": true, "tags": ["scanner"]},
    {"dataType": "domain", "data": "evil-c2.example.com", "message": "Suspected C2 domain", "tlp": 2, "ioc": true, "tags": ["c2"]},
    {"dataType": "hash", "data": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "message": "Suspicious file hash from endpoint", "tlp": 2, "ioc": true, "tags": ["malware"]}
  ]'
```

### 7.5 Escalation Procedures

**When to increase severity:**

- Additional systems found to be affected (scope expansion)
- Evidence of lateral movement beyond the initial target
- Data exfiltration confirmed
- Attacker demonstrates persistent access (backdoor, scheduled task)
- Attack originates from a previously trusted source (insider threat)

```bash
# Increase severity from 2 to 3
curl -s -X PATCH "http://10.10.30.22:9000/api/case/CASE_ID" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"severity": 3}'
```

**When to merge cases:**

Merge cases when you discover two or more cases represent the same incident (same attacker, same campaign, related activity).

1. Open the primary case (keep this one)
2. In TheHive UI, use the Merge function to combine the secondary case into the primary
3. All observables, tasks, and logs from the secondary case transfer to the primary
4. The secondary case is closed with a reference to the primary

**When to create child cases:**

Create a child case when an incident spawns a distinct sub-investigation:

- A malware sample needs dedicated reverse engineering analysis
- A compromised account requires separate credential investigation
- A different VLAN is affected and needs parallel investigation

### 7.6 Case Closure Checklist

Before resolving any case, verify all items are complete:

- [ ] All 5 IR phase tasks are completed or marked N/A with justification
- [ ] All observables have been analyzed (Cortex analyzers run)
- [ ] All IOCs are marked with `ioc: true` flag
- [ ] Resolution status is set (TruePositive / FalsePositive / Indeterminate)
- [ ] Impact status is set (NoImpact / WithImpact / NotApplicable)
- [ ] Case summary field is populated with a concise description of the outcome
- [ ] All containment actions are documented in task logs
- [ ] Detection rule improvements are documented (if any)
- [ ] After-Action Report is written (for Severity 3-4 TruePositive cases)
- [ ] Discord notification sent to team with case outcome

### 7.7 After-Action Report (AAR) Template

The AAR follows NIST 800-61 Section 3.4 (Lessons Learned). Store the AAR as a task log entry on Task 5 (Lessons Learned) in TheHive. For Severity 3-4 incidents, also export as a standalone markdown document.

Copy this template and fill in all sections:

```markdown
# After-Action Report

## Incident Summary

| Field | Value |
|-------|-------|
| TheHive Case ID | #XXXX |
| Classification | [e.g., SQL Injection, Brute Force, Malware, Lateral Movement] |
| Severity | [1-Low / 2-Medium / 3-High / 4-Critical] |
| Resolution | [TruePositive / FalsePositive / Indeterminate] |
| Impact | [NoImpact / WithImpact / NotApplicable] |
| Lead Analyst | [Name] |
| Date Range | [First detection] to [Case closure] |
| MITRE ATT&CK | [Technique IDs, e.g., T1190, T1059.001] |

## Executive Summary

[2-3 sentences. What happened, what was the impact, and what was the outcome. Written for a non-technical audience.]

## Timeline of Events

| Timestamp (UTC) | Source | Event |
|-----------------|--------|-------|
| YYYY-MM-DDTHH:MM:SSZ | [Wazuh/Zeek/ELK/Shuffle/Manual] | [Description of event] |
| YYYY-MM-DDTHH:MM:SSZ | [Source] | [Description] |
| YYYY-MM-DDTHH:MM:SSZ | [Source] | [Description] |
| YYYY-MM-DDTHH:MM:SSZ | [Source] | [Detection -- alert fired] |
| YYYY-MM-DDTHH:MM:SSZ | [Analyst] | [Investigation started] |
| YYYY-MM-DDTHH:MM:SSZ | [Analyst] | [Containment action taken] |
| YYYY-MM-DDTHH:MM:SSZ | [Analyst] | [Eradication complete] |
| YYYY-MM-DDTHH:MM:SSZ | [Analyst] | [Recovery verified] |
| YYYY-MM-DDTHH:MM:SSZ | [Analyst] | [Case closed] |

## Root Cause Analysis

[What was the root cause of the incident? What vulnerability or misconfiguration was exploited? What allowed the attacker to gain access?]

## Impact Assessment

| Category | Assessment |
|----------|------------|
| Systems Affected | [List all affected hosts, IPs, services] |
| Data Exposure | [What data was accessed, exfiltrated, or modified? None / Limited / Significant] |
| Dwell Time | [Time from initial compromise to detection] |
| Business Impact | [Operational impact. For this lab: impact on research/learning objectives] |

## What Worked Well

- [Detection capability that caught the attack, e.g., "Custom Suricata rule 9000001 detected UNION SELECT within 1 second"]
- [SOAR automation that accelerated response, e.g., "WF1 auto-enriched with ML score 0.92 and created TheHive case within 30 seconds"]
- [Investigation tool that provided key evidence, e.g., "Zeek HTTP logs provided full URI reconstruction"]

## Areas for Improvement

- [Detection gap, e.g., "No rule for time-based blind SQL injection without SLEEP keyword"]
- [Process gap, e.g., "Containment took 15 minutes because manual Cloudflare block was needed"]
- [Tool gap, e.g., "Velociraptor hunt for webshells was not pre-built"]

## Action Items

| # | Action | Owner | Deadline | Status |
|---|--------|-------|----------|--------|
| 1 | [e.g., Create Suricata rule for blind SQLi without SLEEP] | [Name] | [Date] | [Open/InProgress/Closed] |
| 2 | [e.g., Add auto-block logic to WF1 for internal attack sources] | [Name] | [Date] | [Status] |
| 3 | [e.g., Build Velociraptor webshell hunt artifact] | [Name] | [Date] | [Status] |
| 4 | [e.g., Schedule purple team re-test after rule update] | [Name] | [Date] | [Status] |

## Detection Engineering Updates

- [ ] New Wazuh rule(s) created: [Rule ID(s) and description]
- [ ] New Suricata rule(s) created: [SID(s) and description]
- [ ] New ELK detection rule(s) created: [Rule name(s)]
- [ ] Existing rule(s) tuned: [Which rules and what changed]
- [ ] New Zeek script or notice: [Description]
- [ ] ML model retraining needed: [Yes/No, reason]
- [ ] Shuffle workflow updated: [Which WF and what changed]

## Metrics

| Metric | Value |
|--------|-------|
| Mean Time to Detect (MTTD) | [Time from first malicious activity to first alert] |
| Mean Time to Respond (MTTR) | [Time from first alert to containment complete] |
| Dwell Time | [Time from initial compromise to eradication] |
| Total Alerts Generated | [Count of related Wazuh + ELK alerts] |
| False Positive Rate | [If applicable, how many related alerts were FP] |

---

*Report prepared by [Analyst Name] on [Date]. Stored in TheHive Case #XXXX, Task 5.*
```

**Storing the AAR:**

1. Open the case in TheHive
2. Navigate to Task 5 (Lessons Learned)
3. Click "Add Log"
4. Paste the completed AAR template as the log entry
5. Mark Task 5 as Completed

**Exporting significant AARs:**

For Severity 3-4 TruePositive cases, export the AAR as a standalone document:

1. Copy the AAR from the TheHive task log
2. Save as `AAR-CASE_ID-YYYY-MM-DD-short-description.md`
3. Store in the project's incident-response documentation
4. Reference the file path in the TheHive case summary

---

## 8. SOAR Workflow Operations

This section documents all Shuffle SOAR workflows. All workflows run on brisket (10.10.20.30). Shuffle Frontend: https://10.10.20.30:3443. Shuffle Backend API: http://10.10.20.30:5001. All workflow credentials use `$varname` substitution (workflow variables) -- never hardcoded.

**Ollama Configuration (applies to all LLM-enabled workflows):**

- Model: `qwen3:8b` on brisket Ollama (http://10.10.20.30:11434)
- Temperature: 0.3 (deterministic output)
- All prompts prefixed with `/no_think` to suppress reasoning chain
- Response parsing strips `<think>...</think>` tags via regex
- GPU scheduling: 3-hour minimum stagger between Ollama-heavy workflows to avoid RTX A1000 contention
- Schedule order: 0600 WF5, 0605 WF2, 0900 WF6, 1200 WF7, 1500 WF8, 1805 WF2

**Listing all workflows:**

```bash
curl -s http://10.10.20.30:5001/api/v1/workflows \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{w[\"id\"]:40} {w[\"name\"]}') for w in json.load(sys.stdin)]"
```

### 8.1 WF1 -- Threat Enrichment & Auto-Block

**Purpose:** Real-time alert enrichment pipeline. Receives Wazuh alerts level 8+, enriches with AbuseIPDB + ML scoring + Ollama triage, creates TheHive cases for high-confidence threats, optionally auto-blocks via Cloudflare.

**Trigger:** Webhook (automatic). Wazuh ossec.conf integration fires on alerts with `rule.level >= 8`.

**Pipeline steps:**

1. Parse incoming alert JSON
2. Extract source IP, check if external (skip RFC1918/internal)
3. AbuseIPDB lookup: confidence score, report count, country, ISP
4. ML Scorer: POST to http://10.10.20.30:5002/score with alert JSON -> ml_score (0-1), ml_label, top features
5. Combined score: `max(abuse_normalized, ml_score)` where `abuse_normalized = abuseipdb_confidence / 100`
6. Dedup check: skip if same source IP alerted within 24 hours
7. Ollama triage: 1-2 sentence analyst summary. If ml_score >= 0.7, includes top 7 feature analysis
8. TheHive case creation: if combined_score >= 0.7 OR rule_level >= 10
9. Cloudflare block: if abuse_score >= 90 AND reports >= 5 AND NOT whitelisted. **Currently disabled** (branch condition `HONEYPOT_DISABLED` set to preserve honeypot research value)
10. Discord notification with scores, classification, and triage summary

**Manual re-trigger:** Paste an alert JSON directly to the WF1 webhook URL in Shuffle.

**Discord output format:**

```
[ALERT] Rule 5763 (Level 10) - SSH brute force from 45.33.32.156
Agent: DVWA | MITRE: T1110.001
AbuseIPDB: 95/100 (23 reports, CN, AS4134 Chinanet)
ML Score: 0.87 (malicious) | Combined: 0.95
Triage: External SSH brute force from known malicious Chinese IP targeting DVWA.
Action: TheHive case #1234 created. Cloudflare block: HONEYPOT_DISABLED.
```

**Common failure modes:**

- AbuseIPDB rate limit exceeded (1000 checks/day free tier): WF1 continues without AbuseIPDB data, uses ML score only
- ML Scorer timeout: check GPU contention with `nvidia-smi` on brisket. Restart ml-scorer container
- Ollama timeout: increase timeout to 120s in Shuffle HTTP action. Check if another workflow is using GPU
- Dedup false suppression: if a genuinely different alert from the same IP is suppressed, manually create a TheHive case

### 8.2 WF2 -- Watch Turnover Digest

**Purpose:** Generates a shift turnover report summarizing the last 12 hours of alert activity. Provides posture assessment and action items for the incoming analyst.

**Trigger:** Cron at 0605 and 1805 EST daily (covers AM/PM shift changes).

**Manual execution:**

```bash
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Replace `WORKFLOW_ID` with the WF2 ID from the workflow listing command in section 8.0.

**Pipeline steps:**

1. Query OpenSearch `wazuh-alerts-4.x-*` for last 12 hours
2. Aggregate by rule.id, agent.name, data.srcip, rule.mitre.id
3. Ollama summarizes top threats, assigns posture level
4. Discord digest posted

**Discord output format:**

```
[WATCH TURNOVER] 2026-03-04 18:05 EST

Posture: GUARDED
Alerts (12h): 847 total, 12 high (level 8+), 2 critical (level 12+)
Top Sources: 45.33.32.156 (23 alerts), 185.220.101.4 (15 alerts)
Top Rules: 5763 SSH brute force (31), 31168 Web scan (18)
MITRE: T1110 Brute Force (31), T1595 Active Scanning (18)

Narrative: Sustained SSH brute force campaign from Chinese IP range against
DVWA. Web scanning activity from Tor exit node. No lateral movement detected.
All auto-enrichment processed normally.

Action Items:
- Review TheHive case #1234 (SSH brute force, awaiting closure)
- Monitor 185.220.101.4 for escalation
```

**Posture levels:** NORMAL (baseline activity), GUARDED (elevated but expected), ELEVATED (active threats requiring attention), CRITICAL (active incident).

**Common failure modes:**

- OpenSearch connection timeout: verify indexer health with `curl -sk https://10.10.20.30:9200/_cluster/health -u admin:'PASSWORD'`
- Ollama produces truncated output: increase `num_predict` to 3000 in the HTTP action
- Empty digest (0 alerts): normal during maintenance windows, verify agents are reporting

### 8.3 WF3 -- Detection Gap Analyzer

**Purpose:** Post-campaign analysis. Cross-references Caldera operation results with Wazuh/ELK alerts to compute detection coverage percentage and identify gaps.

**Trigger:** Webhook (manual POST after completing a Caldera campaign).

**Manual execution:**

```bash
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_id": "CALDERA_OPERATION_ID",
    "start_time": "now-24h",
    "end_time": "now"
  }'
```

**Pipeline steps:**

1. Query Caldera API (http://10.10.30.21:8888) for operation results (techniques executed, success/fail)
2. Query Wazuh OpenSearch for alerts in the operation time window
3. Cross-reference: which MITRE techniques generated alerts vs. which did not
4. Compute detection coverage: `(techniques_detected / techniques_executed) * 100`
5. Ollama generates gap analysis report with recommendations
6. Discord notification with coverage summary
7. TheHive case created with full gap report

**Discord output format:**

```
[DETECTION GAP ANALYSIS] Campaign: APT29 Simulation
Coverage: 73% (11/15 techniques detected)
Detected: T1059.001, T1053.005, T1543.003, T1021.002, ...
Gaps: T1055.001 (Process Injection), T1003.001 (LSASS Dump),
      T1070.004 (File Deletion), T1036.005 (Masquerading)
Recommendation: Add Wazuh rule for Sysmon EventID 10 (process access)
               to catch LSASS credential dumping.
TheHive Case: #1245
```

**When to use:** After every Caldera campaign completion. Wait 2-5 minutes after the campaign ends before triggering to allow Suricata/Wazuh processing.

**Common failure modes:**

- Caldera API unreachable: verify smoker is online, check `curl http://10.10.30.21:8888/api/v2/health -H 'KEY: <CALDERA_API_KEY>'`
- Zero techniques found: verify the operation_id is correct (use full UUID)
- Time window mismatch: adjust start_time/end_time to cover the full campaign duration

### 8.4 WF5 -- Daily Alert Cluster Triage

**Purpose:** Clusters the last 24 hours of alerts by source IP and classifies each cluster to reduce analyst alert fatigue. Identifies which clusters need investigation vs. routine activity.

**Trigger:** Cron at 0600 EST daily (Mon-Sat).

**Manual execution:**

```bash
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Pipeline steps:**

1. Query OpenSearch for last 24 hours of `wazuh-alerts-4.x-*`
2. Aggregate by source IP, extract top rules and MITRE techniques per cluster
3. Ollama classifies each cluster into one of four categories
4. TheHive alerts created for INVESTIGATE items
5. Discord summary posted

**Classification categories:**

| Category | Meaning | Action |
|----------|---------|--------|
| CAMPAIGN | Expected red team / Caldera activity from sear (10.10.20.20) | Acknowledge, no action |
| ROUTINE | Normal operational alerts (agent heartbeats, system updates) | No action |
| INVESTIGATE | Suspicious activity requiring analyst review | Review TheHive alert, investigate |
| MISCONFIG | Likely misconfiguration or noisy rule | Tune rule, adjust threshold |

**Discord output format:**

```
[CLUSTER TRIAGE] 2026-03-04 06:00 EST

Top 10 Clusters (24h):

1. 45.33.32.156 (47 alerts) -> INVESTIGATE
   Rules: 5763 SSH brute force (31), 5710 auth failure (16)
   MITRE: T1110.001 Password Guessing

2. 10.10.20.20 (89 alerts) -> CAMPAIGN
   Rules: 31168 Web attack (45), 5763 SSH brute force (44)
   Note: sear IP, authorized testing

3. 10.10.10.1 (23 alerts) -> ROUTINE
   Rules: 60101 Firewall state change (23)
   Note: OPNsense operational logs
```

**Common failure modes:**

- Too many clusters (>50): workflow may timeout. Increase execution timeout in Shuffle settings
- INVESTIGATE classification on known sear IP: sear (10.10.20.20) should be in the whitelist. Check workflow variable configuration

### 8.5 WF6 -- ML Model Drift Monitor

**Purpose:** Monitors ML scorer behavior for distribution drift. Samples recent alerts, scores them via the ML scorer, and compares the score distribution against the training baseline.

**Trigger:** Cron at 0900 EST daily.

**Manual execution:**

```bash
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Pipeline steps:**

1. Query OpenSearch for ~200 recent alerts
2. POST each to ML Scorer (http://10.10.20.30:5002/score)
3. Compute score distribution statistics (mean, p50, p95, malicious %)
4. Compare against baseline distribution
5. Ollama classifies drift level
6. Results indexed to ELK `ml-drift` index
7. Discord alert posted

**Drift classifications:**

| Classification | Threshold | Action |
|---------------|-----------|--------|
| STABLE | Mean shift <0.05, malicious % change <10pp | No action |
| MINOR_DRIFT | Mean shift 0.05-0.1, malicious % change 10-20pp | Monitor, check next day |
| SIGNIFICANT_DRIFT | Mean shift >0.1, malicious % change >20pp, p95 shift >0.15 | Investigate cause, assess retraining |

**Discord output format:**

```
[ML DRIFT MONITOR] 2026-03-04 09:00 EST

Status: STABLE
Sample Size: 200 alerts
Current Distribution: mean=0.23, p50=0.15, p95=0.78
Baseline Distribution: mean=0.21, p50=0.14, p95=0.76
Malicious %: 4.5% (baseline: 4.2%)
Drift: Mean shift +0.02, within normal range.
```

**Common failure modes:**

- ML Scorer unhealthy: check `curl http://10.10.20.30:5002/health`. Restart container if needed
- GPU contention: WF6 runs at 0900, 3 hours after WF5/WF2. If Ollama is still processing, scores may timeout
- Baseline not set: on first run, the workflow establishes the baseline. Subsequent runs compare against it

### 8.6 WF7 -- Honeypot Intelligence Report

**Purpose:** Weekly intelligence report from GCP honeypot data. Analyzes captured credentials, access patterns, and attacker techniques for threat intelligence value.

**Trigger:** Cron at 1200 EST every Sunday.

**Manual execution:**

```bash
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Pipeline steps:**

1. Query ELK (https://10.10.30.23:9200) for `honeypot-credentials` index (last 7 days)
2. Query ELK for `honeypot-access` index (last 7 days)
3. Aggregate by attacker IP, credential pairs, access paths, user agents
4. Ollama generates intelligence report with week-over-week comparison
5. Discord report posted

**Discord output format:**

```
[HONEYPOT INTEL] Week of 2026-02-24 to 2026-03-02

Credential Captures: 142 (prev week: 128, +11%)
Unique Source IPs: 47 (prev: 39, +21%)
Top Countries: CN (34%), US (18%), RU (12%), BR (8%)

Top Credentials Attempted:
  admin:admin (23), admin:password (18), root:123456 (15)

Notable Patterns:
- 3 IPs attempted wp-admin paths after credential capture (post-auth behavior)
- New user-agent cluster: "Mozilla/5.0 zgrab/0.x" (ZGrab scanner, 12 IPs)
- Increased SSH brute force from AS4134 (Chinanet) subnet

MITRE Techniques: T1078 Valid Accounts, T1110.001 Password Guessing,
                  T1595.002 Vulnerability Scanning
```

**Common failure modes:**

- ELK containers down: honeypot indices are on ELK LXC 201. See Troubleshooting section 11.3
- Empty indices: verify Fluent Bit is shipping from GCP VM. Check Tailscale connectivity (`tailscale status` on GCP VM)
- Ollama timeout on large datasets: increase timeout, or limit query to last 7 days

### 8.7 WF8 -- LLM Log Anomaly Finder

**Purpose:** Anomaly hunting across Wazuh and Zeek data. Uses IsolationForest for statistical anomaly detection combined with Ollama classification for context-aware analysis.

**Trigger:** Cron at 1500 EST daily.

**Manual execution:**

```bash
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Pipeline steps:**

1. Query OpenSearch for last 24 hours of `wazuh-alerts-4.x-*` and `zeek-*` indices
2. Run IsolationForest anomaly detection on alert features
3. Ollama classifies each anomaly into categories
4. Discord notification to SOC channel for internal network anomalies
5. Discord notification to honeypot channel (`$discord_webhook_honeypot`) for GCP/honeypot anomalies

**Anomaly classifications:**

| Classification | Meaning | Action |
|---------------|---------|--------|
| ANOMALOUS | Genuinely unusual pattern, warrants investigation | Investigate immediately |
| MISCONFIG | Likely misconfigured service or noisy rule | Tune rule, fix config |
| TRANSIENT | One-off event, not sustained | Acknowledge, no action |
| BLIND_SPOT | Detection gap -- activity that should have more coverage | Write new detection rule |

**Discord output format (SOC channel):**

```
[ANOMALY FINDER] 2026-03-04 15:00 EST

Internal Network Anomalies (3 found):

1. ANOMALOUS: DC01 -- unusual PowerShell execution pattern
   Rule 92036 (Level 8) at 14:23 EST
   Context: Base64-encoded command, not seen in last 30 days
   Action: Investigate for T1059.001

2. MISCONFIG: smokehouse -- repeated Zeek DNS timeout warnings
   114 events in 2 hours, resolver 10.10.10.1
   Action: Check OPNsense DNS settings

3. TRANSIENT: brisket -- Docker container restart loop (3 restarts)
   Resolved at 13:45 EST
   Action: None, self-resolved
```

**Discord output format (honeypot channel):**

```
[HONEYPOT ANOMALY] 2026-03-04 15:00 EST

1. ANOMALOUS: GCP VM -- POST to /wp-content/uploads/shell.php
   Source: 103.45.67.89 (VN)
   Context: Possible web shell upload attempt, novel path
   Action: Review honeypot-access and honeypot-wazuh indices
```

**Relationship to WF5:** WF5 handles high-volume alert clusters (top 10 by count). WF8 handles low-volume rare patterns that clustering would miss.

**Common failure modes:**

- IsolationForest produces too many anomalies: adjust contamination parameter in workflow
- Ollama timeout due to GPU contention with Grafana dashboards or ML Scorer: check `nvidia-smi` on brisket
- Zeek indices empty: verify Fluent Bit on smokehouse is shipping to OpenSearch

---

## 9. Adversary Simulation Operations

All adversary simulation is conducted from **sear** (10.10.20.20, Kali Linux). Attacks **MUST** target VLAN 40 only (10.10.40.0/24) unless explicitly running authorized AD attacks on VLAN 30.

### 9.1 run_attack.sh Usage

The `run_attack.sh` wrapper ensures ground-truth logging for every attack. It records timestamps, MITRE technique IDs, tools used, source/target IPs, and success status.

**Location:** `~/attack-scripts/run_attack.sh` on sear.

**Syntax:**

```bash
./run_attack.sh <attack_type> ["optional notes"]
./run_attack.sh --list                              # List all 200+ attack types
./run_attack.sh --list <category>                   # List attacks in category
./run_attack.sh --campaign-id CAMP-001 <attack>     # Tag attack with campaign ID
./run_attack.sh --auto-confirm <attack>             # Skip confirmation prompt
```

**Attack categories and examples:**

| Category | Example Attacks | Default Target |
|----------|----------------|----------------|
| Web | sqli_union, sqli_blind, xss_reflected, xss_stored, lfi, rfi, cmdi, path_traversal, log4shell, ssrf | DVWA (10.10.40.10) |
| Credential | login_brute, wordpress_brute, xmlrpc_brute, credential_stuffing | WordPress (10.10.40.30), DVWA |
| Recon | syn_scan, full_tcp, udp_scan, version_detection, os_fingerprinting, smb_enum | All VLAN 40 targets |
| Brute Force | ssh_brute, ftp_brute, telnet_brute, mysql_brute, postgres_brute | Metasploitable (10.10.40.20) |
| C2 Simulation | http_beacon, dns_beacon, http_exfiltration, dns_exfiltration | Metasploitable (10.10.40.20) |
| API | crapi_bola, crapi_bfla, crapi_mass_assign, crapi_ssrf | crAPI (10.10.40.31) |
| Metasploit | vsftpd_234, distcc_exec, ms17_010, tomcat_upload, java_rmi | Metasploitable (10.10.40.20/21) |
| AD (restricted) | ldap_enum, kerberoast, password_spray, bloodhound, asreproast | DC01 (10.10.30.40), WS01 (10.10.30.41) |

**AD attack safety:** AD attacks target VLAN 30 (10.10.30.40/41). The script requires typing `CONFIRM-AD` before execution.

### 9.2 Ground-Truth Logging

Every `run_attack.sh` execution appends a line to `attack-scripts/attack_log.csv` on sear:

```
attack_id,timestamp_start,timestamp_end,category,subcategory,technique_id,tool,source_ip,target_ip,target_port,target_service,success,notes
ATK-20260304-001,2026-03-04T14:30:00Z,2026-03-04T14:30:45Z,web,sqli,T1190,sqlmap,10.10.20.20,10.10.40.10,80,dvwa,true,"UNION-based injection test"
```

This CSV is the ground truth for correlating attacks to detections. Every alert validation starts by matching the alert timestamp against this log.

### 9.3 Caldera Campaign Execution

Caldera v5.3.0 runs on smoker (http://10.10.30.21:8888). Login: red / <PLATFORM_PASSWORD>.

**4 Sandcat agents deployed:**

| Agent | Host | IP | OS |
|-------|------|----|----|
| Sandcat-DC01 | DC01 | 10.10.30.40 | Windows Server 2022 |
| Sandcat-WS01 | WS01 | 10.10.30.41 | Windows 10 |
| Sandcat-DVWA | DVWA | 10.10.40.10 | Debian Linux |
| Sandcat-Meta3 | Metasploitable 3 | 10.10.40.20 | Ubuntu Linux |

**29 MITRE ATT&CK adversary profiles** are available for structured campaigns.

**Creating a campaign via UI:**

1. Open http://10.10.30.21:8888, log in as red
2. Navigate to Operations > Create Operation
3. Select an adversary profile from the 29 available
4. Select agent group: `targets`
5. Settings: `auto_close=false`, `source=basic`, `planner=atomic`
6. Click Start

**Creating a campaign via API:**

```bash
# List available adversary profiles
curl -s http://10.10.30.21:8888/api/v2/adversaries \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{a[\"adversary_id\"]:40} {a[\"name\"]}') for a in json.load(sys.stdin)]"

# List available agents
curl -s http://10.10.30.21:8888/api/v2/agents \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{a[\"paw\"]:12} {a[\"host\"]:20} {a[\"platform\"]}') for a in json.load(sys.stdin)]"

# Create and start an operation (use FULL adversary UUID -- truncated causes 0-link failures)
curl -s -X POST http://10.10.30.21:8888/api/v2/operations \
  -H "KEY: <CALDERA_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "APT29-Sim-2026-03-04",
    "adversary": {"adversary_id": "FULL_UUID_HERE"},
    "source": {"id": "basic"},
    "auto_close": false,
    "group": "targets"
  }'

# Check operation status
curl -s http://10.10.30.21:8888/api/v2/operations/OPERATION_ID \
  -H "KEY: <CALDERA_API_KEY>" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'State: {d[\"state\"]}, Links: {len(d.get(\"chain\",[]))}')"
```

### 9.4 Post-Attack Validation

After any attack (manual or Caldera campaign), follow this procedure:

**Step 1: Wait for processing (2-5 minutes)**

Suricata on smokehouse needs time to process SPAN traffic. Wazuh rules fire on log ingestion. Allow 2-5 minutes before querying for alerts.

**Step 2: Query Wazuh for alerts in the attack window**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 100,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30m", "lte": "now"}}},
        {"term": {"data.srcip": "10.10.20.20"}}
      ]
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "rule.mitre.id", "agent.name", "data.srcip", "data.dstip"]
}'
```

**Step 3: Check Zeek network flows**

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-conn-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30m", "lte": "now"}}},
        {"term": {"id.orig_h": "10.10.20.20"}}
      ]
    }
  },
  "_source": ["@timestamp", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "conn_state", "duration", "orig_bytes", "resp_bytes"]
}'
```

**Step 4: Trigger WF3 detection gap analysis (for Caldera campaigns)**

```bash
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_id": "CALDERA_OPERATION_ID",
    "start_time": "now-2h",
    "end_time": "now"
  }'
```

**Step 5: Correlate ground truth to detections**

Compare `attack_log.csv` entries (by timestamp and target IP) against Wazuh alerts and Zeek flows. Compute detection rate per technique. Document gaps for rule development.

---

## 10. Scenario Runbooks

Each runbook follows the structure: **Trigger** (what initiates the runbook), **Verify** (confirm it is real), **Investigate** (gather evidence), **Respond** (take action), **Document** (create/update TheHive case).

### RB-01: SSH Brute Force

**Trigger:** Wazuh rule 5763 (level 10) "sshd: Multiple authentication failures" or high-frequency `rule.groups: authentication_failed`.

**Verify:**

```bash
# Get JWT token
TOKEN=$(curl -s -u wazuh-wui:'<WAZUH_API_PASSWORD>' -k -X POST \
  "https://10.10.20.30:55000/security/user/authenticate" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# Query for SSH brute force alerts from the source IP
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        {"term": {"rule.id": "5763"}},
        {"term": {"data.srcip": "SUSPECT_IP"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "rule.level", "agent.name", "data.srcip", "data.dstuser"]
}'
```

Check if the source IP is sear (10.10.20.20) running an authorized brute force test. Cross-reference `attack_log.csv` on sear.

**Investigate:**

```bash
# AbuseIPDB lookup
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=SUSPECT_IP&maxAgeInDays=90" \
  -H "Key: ABUSEIPDB_API_KEY" -H "Accept: application/json"

# Check if IP appears in alerts on other agents
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"term": {"data.srcip": "SUSPECT_IP"}},
  "aggs": {"by_agent": {"terms": {"field": "agent.name"}}}
}'

# Zeek connection metadata for the source IP
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-conn-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "query": {
    "bool": {
      "must": [
        {"term": {"id.orig_h": "SUSPECT_IP"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "id.orig_h", "id.resp_h", "id.resp_p", "conn_state", "duration"]
}'
```

**Respond:**

If external and malicious (AbuseIPDB confidence >= 50 or multiple reports):

```bash
# Block via Cloudflare (if honeypot mode allows)
curl -X POST "https://api.cloudflare.com/client/v4/accounts/CF_ACCOUNT_ID/firewall/access_rules/rules" \
  -H "Authorization: Bearer CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "block",
    "configuration": {"target": "ip", "value": "SUSPECT_IP"},
    "notes": "SSH brute force - AbuseIPDB score XX, XX reports"
  }'
```

If internal authorized testing: verify against `attack_log.csv`, acknowledge in TheHive case, close as FalsePositive.

**Document:**

Create TheHive case with: source IP, failure count, targeted agents, country/ISP, AbuseIPDB score, block action taken, MITRE T1110.001.

```bash
curl -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[RB-01] SSH Brute Force from SUSPECT_IP",
    "description": "SSH brute force detected by Wazuh rule 5763.\nSource: SUSPECT_IP\nTarget agents: AGENT_LIST\nFailure count: XX\nAbuseIPDB: XX/100",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["ssh-brute-force", "T1110.001", "auto-enriched"]
  }'
```

### RB-02: SQL Injection

**Trigger:** Suricata SID 2006446 (ET WEB_SERVER UNION SELECT) or custom SIDs 9000001-9000005 (custom SQL injection rules). Alert appears as Wazuh rule with `rule.groups: ids` or `rule.groups: web`.

**Verify:**

```bash
# Query for SQL injection alerts
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"bool": {"should": [
          {"range": {"rule.id": {"gte": 9000001, "lte": 9000005}}},
          {"match": {"rule.description": "SQL injection"}}
        ]}}
      ]
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "data.srcip", "data.dstip", "agent.name"]
}'
```

Check if the source IP is sear (10.10.20.20) running authorized testing against DVWA (10.10.40.10).

**Investigate:**

```bash
# Check Zeek HTTP logs for the actual payload
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/zeek-http-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        {"term": {"id.orig_h": "SUSPECT_IP"}},
        {"term": {"id.resp_h": "10.10.40.10"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "method", "host", "uri", "status_code", "user_agent", "response_body_len"]
}'
```

Look for: `UNION SELECT` in URI, `' OR 1=1` patterns, encoded variants (`%27`, `%20UNION`), HTTP 200 responses with large response bodies (successful extraction).

**Respond:**

- If external/unauthorized: block source IP via Cloudflare. Review web application configuration (DVWA security level, exposed services).
- If successful injection (HTTP 200 with data): assess data exposure, check for additional payloads (file upload, command injection follow-up).
- Document payloads as IOCs (observables) in TheHive.

**Document:**

```bash
curl -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[RB-02] SQL Injection against DVWA from SUSPECT_IP",
    "description": "SQL injection detected by Suricata/Wazuh.\nSource: SUSPECT_IP\nTarget: 10.10.40.10:80 (DVWA)\nPayload: [extracted URI]\nSuccess: [yes/no based on HTTP response]",
    "severity": 3,
    "tlp": 2,
    "pap": 2,
    "tags": ["sqli", "T1190", "web-attack", "dvwa"]
  }'
```

### RB-03: Lateral Movement (AD Environment)

**Trigger:** Alerts from DC01 (agent 005, 10.10.30.40) or WS01 (agent 006, 10.10.30.41) with MITRE techniques T1021 (Remote Services), T1047 (WMI), T1059 (Command/Scripting Interpreter), T1003 (Credential Dumping), or T1550 (Use Alternate Authentication Material).

**Verify:**

```bash
# Check for lateral movement indicators on AD agents
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        {"terms": {"agent.name": ["DC01", "WS01"]}},
        {"range": {"@timestamp": {"gte": "now-2h"}}},
        {"terms": {"rule.mitre.id": ["T1021", "T1021.002", "T1047", "T1059", "T1059.001", "T1003", "T1003.001", "T1550"]}}
      ]
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "rule.mitre.id", "agent.name", "data.srcip"]
}'

# Check if a Caldera campaign is running
curl -s http://10.10.30.21:8888/api/v2/operations \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{o[\"id\"]:40} {o[\"name\"]:30} {o[\"state\"]}') for o in json.load(sys.stdin) if o['state'] == 'running']"
```

**Investigate:**

Open Velociraptor (https://10.10.20.30:8889). Run VQL queries on the affected endpoint:

```
-- Process listing (look for unusual processes)
SELECT Pid, Name, CommandLine, Username, CreateTime FROM pslist()

-- Network connections (look for unexpected outbound)
SELECT Pid, Name, Laddr, Raddr, Status FROM netstat() WHERE Status = 'ESTABLISHED'

-- Scheduled tasks (persistence check)
SELECT * FROM Artifact.Windows.System.TaskScheduler()

-- Recently created accounts
SELECT Name, SID, LastLogin FROM Artifact.Windows.Sys.Users() WHERE Created > timestamp(epoch=now() - 86400)
```

Check for Kerberoasting (Event ID 4769 with RC4 encryption), Pass-the-Hash (Event ID 4624 logon type 9), DCSync (Event ID 4662 with replication GUID).

**Respond:**

If unauthorized:

1. Isolate WS01 from the network (OPNsense firewall rule or Velociraptor quarantine)
2. Reset compromised credentials on DC01
3. Review DC01 security event logs for privilege escalation
4. Check for persistence mechanisms on both systems

If authorized Caldera campaign: document detection coverage per technique.

**Document:**

```bash
curl -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[RB-03] Lateral Movement in AD Environment",
    "description": "Lateral movement indicators detected on DC01/WS01.\nTechniques: T1021, T1059\nSource: [IP/host]\nAffected accounts: [list]\nCaldera campaign: [yes/no, operation ID if applicable]",
    "severity": 3,
    "tlp": 3,
    "pap": 2,
    "tags": ["lateral-movement", "active-directory", "T1021", "T1059"]
  }'
```

### RB-04: Malware / Suspicious Binary

**Trigger:** Wazuh FIM (syscheck) alert for new or modified executable in a monitored directory. Rule groups include `syscheck`, `ossec`. Key fields: `syscheck.event` (added/modified), `syscheck.path`, `syscheck.md5_after`, `syscheck.sha256_after`.

**Verify:**

```bash
# Query syscheck events on the affected agent
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "query": {
    "bool": {
      "must": [
        {"term": {"agent.name": "AGENT_NAME"}},
        {"match": {"rule.groups": "syscheck"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "syscheck.event", "syscheck.path", "syscheck.md5_after", "syscheck.sha256_after", "syscheck.size_after", "syscheck.uname_after"]
}'
```

Check if the file change corresponds to a known system update, package installation, or scheduled maintenance.

**Investigate:**

1. Collect the file via Velociraptor:

```
-- Hash the file
SELECT FullPath, Size, hash(path=FullPath) AS Hash
FROM glob(globs="/path/to/suspicious/file")

-- Check if the process is running
SELECT Pid, Name, CommandLine, Username
FROM pslist()
WHERE Name =~ "suspicious_filename"

-- Check for persistence
SELECT * FROM Artifact.Linux.Sys.Crontab()
SELECT * FROM Artifact.Windows.Sys.StartupItems()
```

2. Run Cortex VirusTotal analyzer on the file hash:

```bash
curl -X POST http://10.10.30.22:9001/api/analyzer/VirusTotal_GetReport_3_1/run \
  -H "Authorization: Bearer <CORTEX_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"data": "SHA256_HASH_HERE", "dataType": "hash", "tlp": 2}'

# Check analyzer job status
curl -s http://10.10.30.22:9001/api/job/JOB_ID \
  -H "Authorization: Bearer <CORTEX_API_KEY>"
```

**Respond:**

If malicious:

1. Kill the running process (via Velociraptor or SSH)
2. Quarantine the file (move to isolated directory, do not delete for forensics)
3. Check for additional dropped files in the same directory
4. Scan other endpoints via Velociraptor hunt for the same hash
5. Check for persistence mechanisms (crontab, startup items, systemd services)

**Document:**

```bash
curl -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[RB-04] Suspicious Binary on AGENT_NAME",
    "description": "FIM alert for new/modified executable.\nPath: /path/to/file\nSHA256: HASH\nVirusTotal: XX/YY detections\nProcess running: yes/no",
    "severity": 3,
    "tlp": 2,
    "pap": 2,
    "tags": ["malware", "fim", "syscheck", "T1204"]
  }'
```

Add file hash, filename, and path as observables in the TheHive case.

### RB-05: Honeypot Anomaly

**Trigger:** WF8 classifies a GCP VM pattern as ANOMALOUS. Indicators: novel TTP beyond standard SSH brute force / credential stuffing, post-authentication activity, web shell upload attempts, unusual scanning patterns.

**Verify:**

Review the WF8 Discord output. Check the classification reasoning. Compare to baseline honeypot activity (SSH brute force and wp-login credential captures are expected).

```bash
# Query honeypot-wazuh for recent alerts from agent 009
curl -sk -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/honeypot-wazuh/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "rule.mitre.id", "data.srcip"]
}'
```

**Investigate:**

```bash
# Query honeypot-credentials for credential patterns
curl -sk -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/honeypot-credentials/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"source_ip": "SUSPECT_IP"}},
        {"range": {"@timestamp": {"gte": "now-7d"}}}
      ]
    }
  }
}'

# Query honeypot-access for unusual paths
curl -sk -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/honeypot-access/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-7d"}}},
        {"bool": {"must_not": [
          {"match": {"request_path": "wp-login.php"}}
        ]}}
      ]
    }
  },
  "_source": ["@timestamp", "source_ip", "request_path", "method", "status_code", "user_agent"]
}'
```

Look for: admin panel access (/wp-admin), file uploads (/wp-content/uploads), shell paths (/shell.php, /cmd.php), MITRE techniques beyond T1078/T1110.

**Respond:**

- Do NOT block the attacker IP (honeypot research value -- observe the full attack chain)
- Capture full session data if the attacker demonstrates sophisticated techniques
- Update honeypot configuration if evasion techniques are detected
- Feed findings to WF7 weekly intelligence report

**Document:**

```bash
curl -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[RB-05] Honeypot Anomaly - SUSPECT_IP",
    "description": "WF8 classified anomalous activity on GCP honeypot.\nSource: SUSPECT_IP\nActivity: [description]\nNovelty: [what makes this different from baseline]",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["honeypot", "anomaly", "gcp-vm", "threat-intel"]
  }'
```

### RB-06: ML Model Drift

**Trigger:** WF6 classifies as SIGNIFICANT_DRIFT. Indicators: mean score shift >0.1, malicious classification percentage change >20 percentage points, p95 score shift >0.15.

**Verify:**

```bash
# Query ELK ml-drift index for drift metrics
curl -sk -u elastic:'<PLATFORM_PASSWORD>' -X GET \
  "https://10.10.30.23:9200/ml-drift/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 7,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "_source": ["@timestamp", "classification", "mean_score", "p50_score", "p95_score", "malicious_pct", "sample_size"]
}'
```

Check if drift is sustained (consecutive days) or a one-day anomaly.

**Investigate:**

Determine the cause:

1. **New attack campaign?** Check Caldera operations, `attack_log.csv` for recent campaigns
2. **Network topology change?** New agents added, services moved, VLAN changes
3. **Zeek enrichment rate change?** Zeek join rate affects ~31 features. Check if Fluent Bit on smokehouse is functioning
4. **Model input issues?** Check ML Scorer health and recent scoring errors

```bash
# Sample recent high-scoring alerts manually
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {"range": {"rule.level": {"gte": 8}}},
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip"]
}'

# Score a sample alert manually
curl -s -X POST http://10.10.20.30:5002/score \
  -H "Content-Type: application/json" \
  -d '{"alert": ALERT_JSON_HERE}'
```

**Respond:**

| Cause | Action |
|-------|--------|
| New attack types | Initiate retraining with new labeled data from `attack_log.csv` |
| Topology change | Update feature engineering pipeline, recompute baselines |
| Zeek enrichment drop | Fix Fluent Bit on smokehouse, then reassess drift |
| One-off anomaly | Acknowledge, monitor next day, no action if resolves |

**Document:**

```bash
curl -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[RB-06] ML Model Drift - CLASSIFICATION",
    "description": "WF6 detected SIGNIFICANT_DRIFT.\nMean shift: +X.XX\nMalicious %: XX% (baseline: XX%)\nSustained: yes/no\nCause: [identified cause]\nAction: [retrain/monitor/fix pipeline]",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["ml-drift", "model-health", "xgboost"]
  }'
```

### RB-07: New Vulnerability (CVE)

**Trigger:** Wazuh vulnerability detection alert with CVE identifier. Rule groups include `vulnerability-detector`. Key fields: `data.vulnerability.cve`, `data.vulnerability.severity`, `data.vulnerability.package.name`, `data.vulnerability.package.version`.

**Verify:**

```bash
# Query vulnerability detection alerts
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "query": {
    "bool": {
      "must": [
        {"match": {"rule.groups": "vulnerability-detector"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "agent.name", "data.vulnerability.cve", "data.vulnerability.severity", "data.vulnerability.package.name", "data.vulnerability.package.version", "data.vulnerability.reference"]
}'
```

**Investigate:**

1. Check CVE severity (CVSS score) via NVD or vendor advisory
2. Identify all affected agents:

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"term": {"data.vulnerability.cve": "CVE-YYYY-NNNNN"}},
  "aggs": {"affected_agents": {"terms": {"field": "agent.name"}}}
}'
```

3. Check if the vulnerable service is network-exposed (query Zeek conn logs for relevant ports)
4. Check NVD/vendor advisory for known exploit availability

**Respond:**

| CVSS | Exploit Available | Action |
|------|-------------------|--------|
| 9.0+ | Yes | Patch immediately, consider isolation until patched |
| 9.0+ | No | Patch within 24 hours |
| 7.0-8.9 | Yes | Patch within 48 hours, add compensating controls |
| 7.0-8.9 | No | Patch within 1 week |
| 4.0-6.9 | Any | Patch in next maintenance window |
| < 4.0 | Any | Track, patch when convenient |

If the CVE has a known Suricata signature, add it to the custom rules on smokehouse.

**Document:**

```bash
curl -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[RB-07] CVE-YYYY-NNNNN on AGENT_NAME",
    "description": "Wazuh vulnerability detection.\nCVE: CVE-YYYY-NNNNN\nCVSS: X.X\nPackage: package_name version\nAffected agents: [list]\nExploit available: yes/no\nPatch status: [pending/applied]",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["vulnerability", "cve", "CVE-YYYY-NNNNN", "patch-management"]
  }'
```

### RB-08: Caldera Campaign Validation

**Trigger:** Completed Caldera campaign (decision to validate detection coverage).

**Verify:**

```bash
# Confirm operation completed
curl -s http://10.10.30.21:8888/api/v2/operations/OPERATION_ID \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Name: {d[\"name\"]}\nState: {d[\"state\"]}\nLinks: {len(d.get(\"chain\",[]))}')"

# Get operation time range
curl -s http://10.10.30.21:8888/api/v2/operations/OPERATION_ID \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
chain=d.get('chain',[])
if chain:
    times=[l.get('decide','') for l in chain if l.get('decide')]
    print(f'First: {min(times)}')
    print(f'Last: {max(times)}')
"
```

**Investigate:**

Step 1: Wait 2-5 minutes after campaign completion for alert processing.

Step 2: Trigger WF3 detection gap analysis:

```bash
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "operation_id": "CALDERA_OPERATION_ID",
    "start_time": "CAMPAIGN_START_TIME",
    "end_time": "CAMPAIGN_END_TIME"
  }'
```

Step 3: Review the WF3 Discord output for coverage percentage and gap list.

Step 4: For each undetected technique, query Wazuh to confirm no alerts exist:

```bash
curl -k -u admin:'PASSWORD' -X GET \
  "https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "size": 10,
  "query": {
    "bool": {
      "must": [
        {"term": {"rule.mitre.id": "TXXXX"}},
        {"range": {"@timestamp": {"gte": "CAMPAIGN_START", "lte": "CAMPAIGN_END"}}},
        {"terms": {"agent.name": ["DC01", "WS01", "DVWA"]}}
      ]
    }
  }
}'
```

**Respond:**

For each detection gap:

1. Write a Wazuh custom rule in `local_rules.xml` (rule IDs 100000+)
2. Or write a Suricata custom signature (SIDs 9000001+)
3. Or create an ELK detection rule in Kibana
4. Replay the attack to validate the new rule detects it
5. Assess if significant new labeled data warrants ML pipeline retraining

**Document:**

```bash
curl -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[RB-08] Campaign Validation - CAMPAIGN_NAME",
    "description": "Detection gap analysis for Caldera campaign.\nOperation: OPERATION_ID\nAdversary profile: PROFILE_NAME\nCoverage: XX% (XX/YY techniques)\nGaps: [list of undetected MITRE techniques]\nNew rules created: [list]",
    "severity": 1,
    "tlp": 2,
    "pap": 2,
    "tags": ["campaign-validation", "detection-gap", "caldera", "purple-team"]
  }'
```

Track rule creation progress as tasks within the TheHive case.

---

## 11. Troubleshooting

### 11.1 Wazuh Agent Offline

**Symptoms:** Agent shows `disconnected` in Wazuh Dashboard. Missing alerts from a specific host. WF5 cluster triage reports fewer agents than expected.

**Diagnose:**

```bash
# Get JWT token
TOKEN=$(curl -s -u wazuh-wui:'<WAZUH_API_PASSWORD>' -k -X POST \
  "https://10.10.20.30:55000/security/user/authenticate" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# List disconnected agents
curl -s -k -X GET "https://10.10.20.30:55000/agents?status=disconnected&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Check specific agent detail
curl -s -k -X GET "https://10.10.20.30:55000/agents/AGENT_ID?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

**Fix:**

```bash
# SSH to the affected host and check the agent service
# Linux:
ssh user@HOST_IP
sudo systemctl status wazuh-agent
sudo systemctl restart wazuh-agent

# Windows (from admin PowerShell):
Get-Service WazuhSvc
Restart-Service WazuhSvc

# Check agent config points to correct manager
# Linux: /var/ossec/etc/ossec.conf
# Windows: C:\Program Files (x86)\ossec-agent\ossec.conf
# Verify <server><address>10.10.20.30</address></server>
```

**Verify:** Check firewall rules allow the agent to reach brisket on ports 1514 (events) and 1515 (enrollment). Confirm agent appears as `active` in the API response.

### 11.2 Shuffle Workflow Failed

**Symptoms:** Expected Discord notification did not arrive. Workflow execution shows red/failed status in Shuffle UI. Cron-triggered workflow did not execute at scheduled time.

**Diagnose:**

1. Open https://10.10.20.30:3443 > Workflows > select the workflow > Executions
2. Click the failed execution to see per-node status
3. Check which node failed and read the error output

```bash
# List recent executions via API
curl -s http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/executions \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{e[\"execution_id\"][:12]} {e[\"status\"]:10} {e.get(\"started_at\",\"\")}') for e in json.load(sys.stdin)[:10]]"
```

**Common issues and fixes:**

| Issue | Symptom | Fix |
|-------|---------|-----|
| Ollama timeout | HTTP node timeout after 30s | Increase timeout to 120s in Shuffle HTTP action settings |
| Variable resolution | `$varname` appears literally in request | Check workflow variable exists and name matches exactly |
| Orborus down | All workflows fail, no workers spawning | `ssh bchaplow@10.10.20.30` then `docker restart shuffle-orborus` |
| OpenSearch auth | 401 on query nodes | Verify `$opensearch_user` and `$opensearch_pass` workflow variables |
| Discord webhook invalid | 400/404 on Discord POST | Update `$discord_webhook` workflow variable with new webhook URL |
| Cron not firing | Workflow never executes | Check brisket crontab: `crontab -l`. Re-add cron entry if missing |

**Fix Orborus:**

```bash
ssh bchaplow@10.10.20.30
docker ps | grep orborus
docker restart shuffle-orborus
docker logs --tail 50 shuffle-orborus
```

### 11.3 ELK Containers Down

**Symptoms:** ELK Kibana unreachable at http://10.10.30.23:5601. ELK Elasticsearch queries return connection refused. Fleet agents show offline. Honeypot data pipeline stalled.

**Root cause:** ELK containers on LXC 201 do NOT auto-start on reboot. Any LXC restart (pitcrew maintenance, power outage) requires manual container startup.

**Diagnose:**

```bash
# SSH to pitcrew, then check LXC 201 containers
ssh root@10.10.30.20
pct exec 201 -- bash -c "cd /opt/elk && docker compose ps"
```

**Fix:**

```bash
# Start all ELK containers
ssh root@10.10.30.20
pct exec 201 -- bash -c "cd /opt/elk && docker compose up -d"

# Wait 30-60 seconds for Elasticsearch to initialize, then verify
pct exec 201 -- bash -c "curl -sk https://localhost:9200/_cluster/health -u elastic:'<PLATFORM_PASSWORD>'"
```

**Verify:**

```bash
# Check cluster health (should be green or yellow)
curl -sk https://10.10.30.23:9200/_cluster/health -u elastic:'<PLATFORM_PASSWORD>'

# Check all expected indices exist
curl -sk https://10.10.30.23:9200/_cat/indices?v -u elastic:'<PLATFORM_PASSWORD>' | head -20

# Check Fleet agents reconnected
curl -sk https://10.10.30.23:9200/.fleet-agents/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{"size":10,"_source":["local_metadata.host.hostname","status"]}'
```

Expected indices: `.alerts-security.alerts-default`, `honeypot-credentials`, `honeypot-access`, `honeypot-wazuh`, `apache-parsed-v2`, `ml-drift`, `logs-*`, `metrics-*`.

### 11.4 ML Scorer Unhealthy

**Symptoms:** `curl http://10.10.20.30:5002/health` returns error or no response. WF1 enrichment completes without ML score. WF6 drift monitor fails.

**Diagnose:**

```bash
ssh bchaplow@10.10.20.30

# Check if container is running
docker ps | grep ml-scorer

# Check container logs
docker logs --tail 100 ml-scorer

# Check GPU availability (contention with Ollama)
nvidia-smi
```

**Common issues:**

| Issue | Symptom | Fix |
|-------|---------|-----|
| Container crashed | Not in `docker ps` output | `docker start ml-scorer` or `docker compose up -d ml-scorer` |
| GPU OOM | CUDA out of memory error in logs | Kill competing GPU processes, restart scorer |
| Model file missing | FileNotFoundError in logs | Check model artifact directory exists, re-deploy if needed |
| Port conflict | Address already in use | `docker stop` conflicting container, restart ml-scorer |

**Fix:**

```bash
ssh bchaplow@10.10.20.30

# Restart the ML scorer container
docker restart ml-scorer

# Verify health
curl -s http://10.10.20.30:5002/health
```

**GPU contention:** The RTX A1000 (8GB VRAM) is shared between Ollama and ML Scorer. If both are active simultaneously, OOM can occur. The 3-hour stagger between Ollama-heavy workflows mitigates this, but manual Ollama queries during WF6 execution can cause contention. Check `nvidia-smi` to see current GPU memory usage.

### 11.5 Wazuh Dashboard Unreachable

**Symptoms:** https://10.10.20.30:5601 returns connection refused or certificate error. Wazuh API (port 55000) may still respond.

**Diagnose:**

```bash
ssh bchaplow@10.10.20.30

# Check dashboard container
docker ps | grep wazuh-dashboard

# Check dashboard logs
docker logs --tail 50 wazuh-dashboard

# Check if the indexer (OpenSearch) is healthy -- dashboard depends on it
curl -sk https://10.10.20.30:9200/_cluster/health -u admin:'PASSWORD'
```

**Common issues:**

| Issue | Symptom | Fix |
|-------|---------|-----|
| Dashboard container down | Not in `docker ps` | `docker start wazuh-dashboard` |
| Certificate expired/invalid | Browser SSL error | Regenerate certs per Wazuh documentation |
| Indexer unhealthy | Dashboard shows "Wazuh not ready" | Fix indexer first (check cluster health) |
| Memory pressure | Container killed by OOM | Increase container memory limit in docker-compose.yml |

**Fix:**

```bash
ssh bchaplow@10.10.20.30

# Restart the dashboard
docker restart wazuh-dashboard

# If indexer is also unhealthy, restart the full stack
docker restart wazuh-indexer
# Wait 30 seconds
docker restart wazuh-dashboard
```

**Verify:** Open https://10.10.20.30:5601 in a browser. Accept the self-signed certificate. Confirm the Wazuh dashboard loads and shows agent data.

### 11.6 Query Failures (OpenSearch / ELK)

**Symptoms:** curl queries return `index_not_found_exception`, `parsing_exception`, or `illegal_argument_exception`. Dashboard shows "No results found" for expected data.

**Diagnose:**

```bash
# Check if the target index exists
# OpenSearch (Wazuh):
curl -sk https://10.10.20.30:9200/_cat/indices/wazuh-alerts-4.x-*?v -u admin:'PASSWORD'

# ELK:
curl -sk https://10.10.30.23:9200/_cat/indices?v -u elastic:'<PLATFORM_PASSWORD>' | grep -i honeypot

# Check index mapping for field types
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_mapping/field/data.srcip -u admin:'PASSWORD'

# Check cluster health
curl -sk https://10.10.20.30:9200/_cluster/health -u admin:'PASSWORD'
```

**Common issues:**

| Issue | Fix |
|-------|-----|
| `index_not_found_exception` | Index name or date pattern is wrong. List indices with `_cat/indices` to find correct name |
| `parsing_exception` | JSON syntax error in query body. Validate JSON with `python3 -c "import json; json.load(open('query.json'))"` |
| `illegal_argument_exception` on field | Field type mismatch (e.g., using `term` on a `text` field). Use `match` for text fields, `term` for keyword fields |
| No results but index exists | Time range mismatch. Check `@timestamp` format and ensure `gte`/`lte` cover the expected period |
| Cluster status RED | Unassigned shards. Check: `curl -sk URL/_cat/shards?v | grep UNASSIGNED`. May need disk space cleanup |
| Slow queries | Add `"size": 10` to limit results. Use `"_source"` to select specific fields. Add time range filter |

**Zeek index naming convention:** `zeek-conn-YYYY.MM.DD`, `zeek-http-YYYY.MM.DD`, `zeek-dns-YYYY.MM.DD`, `zeek-ssl-YYYY.MM.DD`, `zeek-files-YYYY.MM.DD`, `zeek-notice-YYYY.MM.DD`, `zeek-weird-YYYY.MM.DD`. Use `zeek-conn-*` for wildcard queries.

---

## 12. API & Query Reference

Consolidated reference for all service APIs. All commands are copy-paste ready.

### 12.1 Wazuh REST API

**Base URL:** https://10.10.20.30:55000
**Auth:** JWT token (obtain via POST to /security/user/authenticate)

```bash
# Step 1: Get JWT token (valid for 900 seconds)
TOKEN=$(curl -s -u wazuh-wui:'<WAZUH_API_PASSWORD>' -k -X POST \
  "https://10.10.20.30:55000/security/user/authenticate" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# List all agents
curl -s -k -X GET "https://10.10.20.30:55000/agents?pretty=true&select=id,name,status,ip,os.name" \
  -H "Authorization: Bearer $TOKEN"

# Get specific agent by ID
curl -s -k -X GET "https://10.10.20.30:55000/agents/001?pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# List active agents only
curl -s -k -X GET "https://10.10.20.30:55000/agents?status=active&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# List disconnected agents
curl -s -k -X GET "https://10.10.20.30:55000/agents?status=disconnected&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Get agent summary (count by status)
curl -s -k -X GET "https://10.10.20.30:55000/agents/summary/status?pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# List rules (with optional search)
curl -s -k -X GET "https://10.10.20.30:55000/rules?limit=20&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Search rules by description
curl -s -k -X GET "https://10.10.20.30:55000/rules?search=brute+force&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Get specific rule by ID
curl -s -k -X GET "https://10.10.20.30:55000/rules?rule_ids=5763&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Restart a specific agent
curl -s -k -X PUT "https://10.10.20.30:55000/agents/001/restart?pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Get manager configuration
curl -s -k -X GET "https://10.10.20.30:55000/manager/configuration?pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Get manager logs (last 50)
curl -s -k -X GET "https://10.10.20.30:55000/manager/logs?limit=50&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

### 12.2 OpenSearch (Wazuh Indexer)

**Base URL:** https://10.10.20.30:9200
**Auth:** Basic (admin:PASSWORD from .env on brisket)
**Primary indices:** `wazuh-alerts-4.x-*`, `zeek-conn-*`, `zeek-http-*`, `zeek-dns-*`, `zeek-ssl-*`, `zeek-files-*`, `zeek-notice-*`, `zeek-weird-*`

```bash
# Cluster health
curl -sk https://10.10.20.30:9200/_cluster/health?pretty -u admin:'PASSWORD'

# List all indices
curl -sk https://10.10.20.30:9200/_cat/indices?v -u admin:'PASSWORD'

# Count documents in wazuh-alerts
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_count -u admin:'PASSWORD'

# Last 10 alerts (most recent first)
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 10,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip"]
}'

# Alerts by rule level (high/critical)
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {"range": {"rule.level": {"gte": 10}}},
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip"]
}'

# Top 10 source IPs (last 24h)
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "aggs": {"top_sources": {"terms": {"field": "data.srcip", "size": 10}}}
}'

# Top 10 rules fired (last 24h)
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "aggs": {"top_rules": {"terms": {"field": "rule.id", "size": 10}}}
}'

# MITRE technique aggregation (last 24h)
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "aggs": {"mitre_techniques": {"terms": {"field": "rule.mitre.id", "size": 20}}}
}'

# Alerts by agent (last 24h histogram)
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "aggs": {
    "by_agent": {"terms": {"field": "agent.name", "size": 15}},
    "over_time": {"date_histogram": {"field": "@timestamp", "calendar_interval": "hour"}}
  }
}'

# Authentication failures
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"match": {"rule.groups": "authentication_failed"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "agent.name", "data.srcip", "data.dstuser"]
}'

# File integrity (syscheck) events
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"match": {"rule.groups": "syscheck"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "agent.name", "syscheck.event", "syscheck.path", "syscheck.sha256_after"]
}'

# Vulnerability detections
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {"match": {"rule.groups": "vulnerability-detector"}},
  "_source": ["@timestamp", "agent.name", "data.vulnerability.cve", "data.vulnerability.severity", "data.vulnerability.package.name"]
}'

# Zeek HTTP requests by source IP
curl -sk https://10.10.20.30:9200/zeek-http-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {"term": {"id.orig_h": "10.10.20.20"}},
  "_source": ["@timestamp", "id.orig_h", "id.resp_h", "method", "host", "uri", "status_code", "user_agent"]
}'

# Zeek DNS queries for a domain
curl -sk https://10.10.20.30:9200/zeek-dns-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "query": {"match": {"query": "example.com"}},
  "_source": ["@timestamp", "id.orig_h", "query", "qtype_name", "rcode_name", "answers"]
}'

# Zeek connection flows between two IPs
curl -sk https://10.10.20.30:9200/zeek-conn-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"id.orig_h": "10.10.20.20"}},
        {"term": {"id.resp_h": "10.10.40.10"}}
      ]
    }
  },
  "_source": ["@timestamp", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "conn_state", "duration", "orig_bytes", "resp_bytes"]
}'

# Alerts with specific MITRE technique
curl -sk https://10.10.20.30:9200/wazuh-alerts-4.x-*/_search -u admin:'PASSWORD' \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"rule.mitre.id": "T1110"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip"]
}'
```

### 12.3 ELK Elasticsearch

**Base URL:** https://10.10.30.23:9200
**Auth:** Basic (elastic:<PLATFORM_PASSWORD>)
**Key indices:** `.alerts-security.alerts-default`, `honeypot-credentials`, `honeypot-access`, `honeypot-wazuh`, `apache-parsed-v2`, `ml-drift`, `logs-*`, `metrics-*`

```bash
# Cluster health
curl -sk https://10.10.30.23:9200/_cluster/health?pretty -u elastic:'<PLATFORM_PASSWORD>'

# List all indices
curl -sk https://10.10.30.23:9200/_cat/indices?v -u elastic:'<PLATFORM_PASSWORD>'

# Detection rule alerts (last 24h)
curl -sk https://10.10.30.23:9200/.alerts-security.alerts-default/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity", "host.name", "source.ip"]
}'

# Alerts by MITRE tactic
curl -sk https://10.10.30.23:9200/.alerts-security.alerts-default/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-7d"}}},
  "aggs": {"by_tactic": {"terms": {"field": "kibana.alert.rule.threat.tactic.name", "size": 20}}}
}'

# Alerts by host
curl -sk https://10.10.30.23:9200/.alerts-security.alerts-default/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "aggs": {"by_host": {"terms": {"field": "host.name", "size": 15}}}
}'

# Windows security events by Event ID
curl -sk https://10.10.30.23:9200/logs-*/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "4625"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "host.name", "event.code", "event.action", "source.ip", "user.name"]
}'

# Linux auth events
curl -sk https://10.10.30.23:9200/logs-*/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"event.dataset": "system.auth"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "_source": ["@timestamp", "host.name", "event.action", "source.ip", "user.name"]
}'

# Fleet agent status
curl -sk https://10.10.30.23:9200/.fleet-agents/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 10,
  "_source": ["local_metadata.host.hostname", "status", "last_checkin"]
}'

# Honeypot credential captures (last 7 days)
curl -sk https://10.10.30.23:9200/honeypot-credentials/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {"range": {"@timestamp": {"gte": "now-7d"}}}
}'

# Honeypot attacker IPs by country
curl -sk https://10.10.30.23:9200/honeypot-access/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-30d"}}},
  "aggs": {"by_country": {"terms": {"field": "geoip.country_name", "size": 20}}}
}'

# Honeypot Wazuh alerts with MITRE techniques
curl -sk https://10.10.30.23:9200/honeypot-wazuh/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "aggs": {"mitre": {"terms": {"field": "rule.mitre.id", "size": 20}}}
}'

# Events by data stream dataset
curl -sk https://10.10.30.23:9200/logs-*/_search -u elastic:'<PLATFORM_PASSWORD>' \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "aggs": {"by_dataset": {"terms": {"field": "data_stream.dataset", "size": 20}}}
}'
```

### 12.4 Shuffle API

**Base URL:** http://10.10.20.30:5001
**Auth:** Bearer token (<SHUFFLE_API_KEY>)

```bash
# List all workflows
curl -s http://10.10.20.30:5001/api/v1/workflows \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>"

# Trigger a workflow execution
curl -s -X POST "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/execute" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'

# Get execution status
curl -s "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/executions" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>"

# Get specific execution result
curl -s "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID/executions/EXECUTION_ID" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>"

# Get workflow details
curl -s "http://10.10.20.30:5001/api/v1/workflows/WORKFLOW_ID" \
  -H "Authorization: Bearer <SHUFFLE_API_KEY>"
```

### 12.5 TheHive API

**Base URL:** http://10.10.30.22:9000
**Auth:** Bearer token (<THEHIVE_API_KEY>)

```bash
# Create a case
curl -s -X POST http://10.10.30.22:9000/api/case \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Case title",
    "description": "Case description",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["tag1", "tag2"]
  }'

# List cases (most recent first)
curl -s -X POST http://10.10.30.22:9000/api/case/_search \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"query": {}, "range": "0-20", "sort": ["-createdAt"]}'

# Search cases by status
curl -s -X POST http://10.10.30.22:9000/api/case/_search \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"_and": [{"_in": {"_field": "status", "list": ["New", "InProgress"]}}]},
    "range": "0-50",
    "sort": ["-severity", "-createdAt"]
  }'

# Update case status (resolve as TruePositive)
curl -s -X PATCH "http://10.10.30.22:9000/api/case/CASE_ID" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"status": "Resolved", "resolutionStatus": "TruePositive", "impactStatus": "WithImpact", "summary": "Confirmed incident, response complete."}'

# Close as FalsePositive
curl -s -X PATCH "http://10.10.30.22:9000/api/case/CASE_ID" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"status": "Resolved", "resolutionStatus": "FalsePositive", "summary": "Confirmed not an incident."}'

# Add observable (IOC) to case
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/artifact" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "ip",
    "data": "1.2.3.4",
    "message": "Source IP of SSH brute force",
    "tlp": 2,
    "tags": ["brute-force", "external"]
  }'

# Create a task in a case
curl -s -X POST "http://10.10.30.22:9000/api/case/CASE_ID/task" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Task 1: Identification",
    "description": "Confirm incident scope, identify affected systems, collect initial evidence.",
    "status": "Waiting",
    "order": 1
  }'

# Add a log entry to a task
curl -s -X POST "http://10.10.30.22:9000/api/case/task/TASK_ID/log" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Investigated source IP 1.2.3.4. AbuseIPDB confidence 95%. Confirmed malicious."
  }'

# List observables for a case
curl -s -X POST "http://10.10.30.22:9000/api/case/artifact/_search" \
  -H "Authorization: Bearer <THEHIVE_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"query": {"_parent": {"_type": "case", "_query": {"_id": "CASE_ID"}}}}'
```

### 12.6 Cortex API

**Base URL:** http://10.10.30.22:9001
**Auth:** Bearer token (<CORTEX_API_KEY>)
**Available analyzers:** AbuseIPDB_1_1, VirusTotal_GetReport_3_1, Shodan_DNSResolve_2_0, Abuse_Finder_3_0, GoogleDNS_resolve_1_0_0

```bash
# List available analyzers
curl -s http://10.10.30.22:9001/api/analyzer \
  -H "Authorization: Bearer <CORTEX_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{a[\"id\"]:40} {a[\"name\"]:30} {a.get(\"dataTypeList\",[])}') for a in json.load(sys.stdin)]"

# Run AbuseIPDB analyzer on an IP
curl -s -X POST http://10.10.30.22:9001/api/analyzer/AbuseIPDB_1_1/run \
  -H "Authorization: Bearer <CORTEX_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"data": "1.2.3.4", "dataType": "ip", "tlp": 2}'

# Run VirusTotal on a hash
curl -s -X POST http://10.10.30.22:9001/api/analyzer/VirusTotal_GetReport_3_1/run \
  -H "Authorization: Bearer <CORTEX_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"data": "SHA256_HASH", "dataType": "hash", "tlp": 2}'

# Run GoogleDNS resolver
curl -s -X POST http://10.10.30.22:9001/api/analyzer/GoogleDNS_resolve_1_0_0/run \
  -H "Authorization: Bearer <CORTEX_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"data": "example.com", "dataType": "domain", "tlp": 2}'

# Run Abuse Finder
curl -s -X POST http://10.10.30.22:9001/api/analyzer/Abuse_Finder_3_0/run \
  -H "Authorization: Bearer <CORTEX_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"data": "1.2.3.4", "dataType": "ip", "tlp": 2}'

# Check job status
curl -s http://10.10.30.22:9001/api/job/JOB_ID \
  -H "Authorization: Bearer <CORTEX_API_KEY>"

# Get job report (after status is "Success")
curl -s http://10.10.30.22:9001/api/job/JOB_ID/report \
  -H "Authorization: Bearer <CORTEX_API_KEY>"
```

### 12.7 Velociraptor VQL Queries

**Access:** https://10.10.20.30:8889 (admin / <PLATFORM_PASSWORD>)
**Run via:** GUI > Notebooks (ad-hoc) or Hunt Manager (multi-client)

```sql
-- List running processes (all clients)
SELECT Pid, Name, CommandLine, Username, CreateTime
FROM pslist()

-- Network connections (ESTABLISHED only)
SELECT Pid, Name, Laddr, Raddr, Status
FROM netstat()
WHERE Status = 'ESTABLISHED'

-- Find files by hash
SELECT FullPath, Size, hash(path=FullPath) AS Hash
FROM glob(globs='/tmp/**')
WHERE Hash.SHA256 = 'TARGET_SHA256_HASH'

-- Recent file modifications (last hour)
SELECT FullPath, Size, Mtime
FROM glob(globs='/etc/**')
WHERE Mtime > timestamp(epoch=now() - 3600)

-- Windows startup items (persistence)
SELECT * FROM Artifact.Windows.Sys.StartupItems()

-- Windows scheduled tasks
SELECT * FROM Artifact.Windows.System.TaskScheduler()

-- Linux crontab entries
SELECT * FROM Artifact.Linux.Sys.Crontab()

-- DNS cache (Windows)
SELECT * FROM Artifact.Windows.Sys.DnsCache()

-- User accounts
SELECT Name, SID, LastLogin FROM Artifact.Windows.Sys.Users()

-- Services (look for suspicious services)
SELECT Name, DisplayName, Status, PathName, StartMode
FROM Artifact.Windows.Sys.Services()
WHERE StartMode = 'Auto'
```

### 12.8 Caldera API

**Base URL:** http://10.10.30.21:8888
**Auth:** Header `KEY: <CALDERA_API_KEY>`

```bash
# List all operations
curl -s http://10.10.30.21:8888/api/v2/operations \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{o[\"id\"]:40} {o[\"name\"]:30} {o[\"state\"]}') for o in json.load(sys.stdin)]"

# Create a new operation
curl -s -X POST http://10.10.30.21:8888/api/v2/operations \
  -H "KEY: <CALDERA_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Campaign Name",
    "adversary": {"adversary_id": "FULL_UUID"},
    "source": {"id": "basic"},
    "auto_close": false,
    "group": "targets"
  }'

# Get operation details and results
curl -s http://10.10.30.21:8888/api/v2/operations/OPERATION_ID \
  -H "KEY: <CALDERA_API_KEY>"

# List all agents
curl -s http://10.10.30.21:8888/api/v2/agents \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{a[\"paw\"]:12} {a[\"host\"]:20} {a[\"platform\"]:10} {a[\"last_seen\"]}') for a in json.load(sys.stdin)]"

# List adversary profiles
curl -s http://10.10.30.21:8888/api/v2/adversaries \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{a[\"adversary_id\"]:40} {a[\"name\"]}') for a in json.load(sys.stdin)]"

# List abilities (individual techniques)
curl -s http://10.10.30.21:8888/api/v2/abilities \
  -H "KEY: <CALDERA_API_KEY>" | \
  python3 -c "import sys,json; [print(f'{a[\"ability_id\"]:40} {a[\"name\"]:40} {a.get(\"technique_id\",\"\")}') for a in json.load(sys.stdin)[:20]]"

# Stop a running operation
curl -s -X PATCH "http://10.10.30.21:8888/api/v2/operations/OPERATION_ID" \
  -H "KEY: <CALDERA_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"state": "cleanup"}'

# Health check
curl -s http://10.10.30.21:8888/api/v2/health -H "KEY: <CALDERA_API_KEY>"
```

### 12.9 Cloudflare API

**Base URL:** https://api.cloudflare.com/client/v4
**Auth:** Bearer token (stored as `$cf_api_token` in Shuffle workflow variables)

```bash
# Block an IP
curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/CF_ACCOUNT_ID/firewall/access_rules/rules" \
  -H "Authorization: Bearer CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "block",
    "configuration": {"target": "ip", "value": "1.2.3.4"},
    "notes": "Blocked by SOC - reason"
  }'

# List existing access rules
curl -s "https://api.cloudflare.com/client/v4/accounts/CF_ACCOUNT_ID/firewall/access_rules/rules?page=1&per_page=20" \
  -H "Authorization: Bearer CF_API_TOKEN"

# Delete an access rule (unblock)
curl -s -X DELETE "https://api.cloudflare.com/client/v4/accounts/CF_ACCOUNT_ID/firewall/access_rules/rules/RULE_ID" \
  -H "Authorization: Bearer CF_API_TOKEN"
```

Note: Replace `CF_ACCOUNT_ID` and `CF_API_TOKEN` with the values from Shuffle workflow variables `$cf_account_id` and `$cf_api_token`. Cloudflare blocking is currently disabled (HONEYPOT_DISABLED) to preserve honeypot research value.

### 12.10 ML Scorer API

**Base URL:** http://10.10.20.30:5002
**Auth:** None required

```bash
# Health check
curl -s http://10.10.20.30:5002/health

# Score a single alert
curl -s -X POST http://10.10.20.30:5002/score \
  -H "Content-Type: application/json" \
  -d '{
    "alert": {
      "rule": {"id": "5763", "level": 10, "description": "SSH brute force"},
      "agent": {"name": "DVWA", "id": "007"},
      "data": {"srcip": "45.33.32.156", "dstip": "10.10.40.10"},
      "timestamp": "2026-03-04T14:30:00Z"
    }
  }'
```

**Response format:**

```json
{
  "ml_score": 0.87,
  "ml_label": "malicious",
  "top_features": [
    {"feature": "rule_level", "importance": 0.23},
    {"feature": "src_alert_count_24h", "importance": 0.18},
    {"feature": "unique_rules_triggered", "importance": 0.15}
  ],
  "model": "xgboost_binary",
  "version": "20260127_120522"
}
```

**Notes:**

- The ML Scorer uses the `_safe_col` fix deployed 2026-02-18 for handling missing columns
- 102 behavioral features across 6 categories (alert metadata, temporal, agent behavioral, Zeek network, anomaly meta, interaction/derived)
- No IP-based features to avoid topology bias
- GPU-accelerated on RTX A1000

---

*SOC Playbook maintained by Brian Chaplow. For architecture details, see docs/architecture.md. For component-specific documentation, see the individual component READMEs.*
