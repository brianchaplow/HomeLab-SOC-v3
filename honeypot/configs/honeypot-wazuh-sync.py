#!/usr/bin/env python3
"""Sync Wazuh alerts for GCP VM (agent 009) to ELK honeypot-wazuh index."""
import json
import os
import sys
import urllib.request
import urllib.error
import ssl
import base64
from datetime import datetime, timezone

STATE_FILE = os.path.expanduser("~/honeypot-wazuh-sync.state")
BATCH_SIZE = 500

# Wazuh Indexer on brisket (localhost)
WAZUH_HOST = os.environ.get("WAZUH_HOST", "https://127.0.0.1:9200")
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "YOUR_WAZUH_PASSWORD")

# ELK on pitcrew LXC 201
ELK_HOST = os.environ.get("ELK_HOST", "https://10.10.30.23:9200")
ELK_USER = os.environ.get("ELK_USER", "elastic")
ELK_PASS = os.environ.get("ELK_PASS", "YOUR_ELK_PASSWORD")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def _req(url, user, password, method="GET", data=None):
    """Make an HTTP request with basic auth."""
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, context=CTX, timeout=30) as resp:
        return json.loads(resp.read())


def get_last_timestamp():
    """Read last synced timestamp from state file."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return f.read().strip()
    return "1970-01-01T00:00:00.000Z"


def save_timestamp(ts):
    """Save last synced timestamp."""
    with open(STATE_FILE, "w") as f:
        f.write(ts)


def fetch_alerts(since_ts):
    """Fetch agent 009 alerts from Wazuh Indexer newer than since_ts."""
    query = {
        "size": BATCH_SIZE,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.id": "009"}},
                    {"range": {"@timestamp": {"gt": since_ts}}}
                ]
            }
        }
    }
    result = _req(f"{WAZUH_HOST}/wazuh-alerts-*/_search", WAZUH_USER, WAZUH_PASS, "POST", query)
    return result["hits"]["hits"]


def bulk_index(docs):
    """Bulk index documents to ELK honeypot-wazuh."""
    if not docs:
        return 0
    lines = []
    for doc in docs:
        action = json.dumps({"index": {"_index": "honeypot-wazuh", "_id": doc["_id"]}})
        source = json.dumps(doc["_source"])
        lines.append(action)
        lines.append(source)
    body = "\n".join(lines) + "\n"

    creds = base64.b64encode(f"{ELK_USER}:{ELK_PASS}".encode()).decode()
    headers = {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/x-ndjson"
    }
    req = urllib.request.Request(
        f"{ELK_HOST}/_bulk", data=body.encode(), headers=headers, method="POST"
    )
    with urllib.request.urlopen(req, context=CTX, timeout=60) as resp:
        result = json.loads(resp.read())
    errors = sum(1 for item in result["items"] if item["index"].get("error"))
    return len(docs) - errors


def main():
    last_ts = get_last_timestamp()
    total = 0

    while True:
        docs = fetch_alerts(last_ts)
        if not docs:
            break
        indexed = bulk_index(docs)
        total += indexed
        last_ts = docs[-1]["_source"]["@timestamp"]
        save_timestamp(last_ts)
        print(f"  Synced {indexed} docs (total: {total}, latest: {last_ts})")
        if len(docs) < BATCH_SIZE:
            break

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[{now}] honeypot-wazuh sync complete: {total} new docs")


if __name__ == "__main__":
    main()
