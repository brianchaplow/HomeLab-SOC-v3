#!/usr/bin/env python3
"""
Honeypot Research Dashboard — Data Import Pipeline
Exports Wazuh GCP-VM alerts from brisket, transforms all 3 honeypot datasets,
and bulk-imports into ELK Elasticsearch (10.10.30.23:9200).

Three target indices:
  - honeypot-credentials  (~3,140 docs from honeypot-credentials.json)
  - honeypot-access        (~737 docs from honeypot-access.json, parsed Apache logs)
  - honeypot-wazuh         (~5,900 docs exported from brisket Wazuh)

Usage: python reference/honeypot-import.py
"""

import json
import os
import re
import subprocess
import sys
import urllib.request
import ssl
from datetime import datetime

# --- Configuration ---
BRISKET_HOST = "bchaplow@10.10.20.30"
BRISKET_OS_URL = "https://localhost:9200"
BRISKET_OS_USER = "admin"
BRISKET_OS_PASS = os.environ.get("OPENSEARCH_PASS", "your_opensearch_password")

ELK_HOST = "https://10.10.30.23:9200"
ELK_USER = "elastic"
ELK_PASS = os.environ.get("ELK_PASS", "your_elastic_password")

ARCHIVE_DIR = r"C:\Users\bchap\Documents\honeypot-archive"
CREDS_FILE = os.path.join(ARCHIVE_DIR, "honeypot-credentials.json")
ACCESS_FILE = os.path.join(ARCHIVE_DIR, "honeypot-access.json")
WAZUH_EXPORT_FILE = os.path.join(ARCHIVE_DIR, "wazuh-gcp-vm-export.ndjson")

SCROLL_SIZE = 1000
BULK_CHUNK = 500

# SSL context that skips verification (self-signed certs)
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def elk_request(method, path, body=None):
    """Make a request to ELK Elasticsearch."""
    url = f"{ELK_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")

    # Basic auth
    import base64
    creds = base64.b64encode(f"{ELK_USER}:{ELK_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")

    try:
        with urllib.request.urlopen(req, context=CTX) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        print(f"  HTTP {e.code}: {err_body[:500]}")
        raise


def elk_bulk(ndjson_lines):
    """Send bulk request to ELK. ndjson_lines is a list of strings."""
    url = f"{ELK_HOST}/_bulk"
    data = "\n".join(ndjson_lines) + "\n"

    req = urllib.request.Request(url, data=data.encode(), method="POST")
    req.add_header("Content-Type", "application/x-ndjson")

    import base64
    creds = base64.b64encode(f"{ELK_USER}:{ELK_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")

    with urllib.request.urlopen(req, context=CTX) as resp:
        result = json.loads(resp.read().decode())

    if result.get("errors"):
        errs = [i for i in result["items"] if "error" in i.get("index", i.get("create", {}))]
        if errs:
            print(f"  {len(errs)} bulk errors, first: {json.dumps(errs[0])[:300]}")
    return result


# ==============================================================
# Step 1: Export Wazuh GCP-VM alerts from brisket via SSH+curl
# ==============================================================
def export_wazuh():
    """Export all agent.name=gcp-vm docs from brisket Wazuh via scroll API."""
    print("\n=== Step 1: Export Wazuh GCP-VM alerts from brisket ===")

    if os.path.exists(WAZUH_EXPORT_FILE):
        with open(WAZUH_EXPORT_FILE, "r") as f:
            count = sum(1 for _ in f)
        print(f"  Export file already exists with {count} docs, skipping export.")
        print(f"  Delete {WAZUH_EXPORT_FILE} to re-export.")
        return count

    # Initial scroll request
    query = json.dumps({
        "query": {"match": {"agent.name": "gcp-vm"}},
        "size": SCROLL_SIZE
    }).replace('"', '\\"')

    cmd = (
        f'ssh {BRISKET_HOST} "curl -sk -u {BRISKET_OS_USER}:{BRISKET_OS_PASS} '
        f'{BRISKET_OS_URL}/wazuh-alerts-4.x-*/_search?scroll=2m '
        f'-H \'Content-Type: application/json\' '
        f'-d \\"{query}\\""'
    )

    all_docs = []
    print("  Starting scroll export...")

    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        print(f"  SSH error: {result.stderr}")
        sys.exit(1)

    data = json.loads(result.stdout)
    scroll_id = data.get("_scroll_id")
    hits = data["hits"]["hits"]
    all_docs.extend(hits)
    total = data["hits"]["total"]["value"]
    print(f"  Total docs to export: {total}")
    print(f"  Batch 1: {len(hits)} docs")

    # Continue scrolling
    batch = 2
    while len(hits) > 0:
        scroll_body = json.dumps({"scroll": "2m", "scroll_id": scroll_id}).replace('"', '\\"')
        cmd = (
            f'ssh {BRISKET_HOST} "curl -sk -u {BRISKET_OS_USER}:{BRISKET_OS_PASS} '
            f'{BRISKET_OS_URL}/_search/scroll '
            f'-H \'Content-Type: application/json\' '
            f'-d \\"{scroll_body}\\""'
        )
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        data = json.loads(result.stdout)
        scroll_id = data.get("_scroll_id")
        hits = data["hits"]["hits"]
        all_docs.extend(hits)
        print(f"  Batch {batch}: {len(hits)} docs (total so far: {len(all_docs)})")
        batch += 1

    # Write to NDJSON
    with open(WAZUH_EXPORT_FILE, "w", encoding="utf-8") as f:
        for doc in all_docs:
            f.write(json.dumps(doc["_source"]) + "\n")

    print(f"  Exported {len(all_docs)} docs to {WAZUH_EXPORT_FILE}")
    return len(all_docs)


# ==============================================================
# Step 2: Index mappings
# ==============================================================
MAPPINGS = {
    "honeypot-credentials": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "timestamp": {"type": "date"},
                "request_id": {"type": "keyword"},
                "session_id": {"type": "keyword"},
                "honeypot": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "phase": {"type": "integer"},
                        "version": {"type": "keyword"}
                    }
                },
                "target": {
                    "properties": {
                        "site": {"type": "keyword"},
                        "uri": {"type": "keyword"},
                        "method": {"type": "keyword"}
                    }
                },
                "source": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "integer"},
                        "user_agent": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                        "referer": {"type": "keyword"},
                        "accept_language": {"type": "keyword"},
                        "accept_encoding": {"type": "keyword"}
                    }
                },
                "cloudflare": {
                    "properties": {
                        "country": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "region": {"type": "keyword"},
                        "postal_code": {"type": "keyword"},
                        "timezone": {"type": "keyword"},
                        "threat_score": {"type": "float"},
                        "bot_score": {"type": "float"},
                        "bot_verified": {"type": "boolean"},
                        "ja3_hash": {"type": "keyword"},
                        "asn": {"type": "keyword"},
                        "colo": {"type": "keyword"}
                    }
                },
                "security": {
                    "properties": {
                        "validation_issues": {"type": "keyword"},
                        "rate_limit": {
                            "properties": {
                                "attempts": {"type": "integer"},
                                "remaining": {"type": "integer"},
                                "blocked": {"type": "boolean"}
                            }
                        }
                    }
                },
                "interaction": {"type": "keyword"},
                "credentials": {
                    "properties": {
                        "username": {"type": "keyword"},
                        "password": {"type": "keyword"},
                        "password_encrypted": {"type": "keyword"},
                        "hashes": {
                            "properties": {
                                "username_hash": {"type": "keyword"},
                                "password_hash": {"type": "keyword"},
                                "pair_hash": {"type": "keyword"}
                            }
                        },
                        "username_analysis": {
                            "properties": {
                                "length": {"type": "integer"},
                                "type": {"type": "keyword"},
                                "patterns": {
                                    "properties": {
                                        "is_generic": {"type": "boolean"},
                                        "is_default_wp": {"type": "boolean"},
                                        "contains_admin": {"type": "boolean"},
                                        "contains_test": {"type": "boolean"},
                                        "contains_site_name": {"type": "boolean"},
                                        "is_numeric": {"type": "boolean"},
                                        "has_year": {"type": "boolean"}
                                    }
                                }
                            }
                        },
                        "password_analysis": {
                            "properties": {
                                "length": {"type": "integer"},
                                "charset": {
                                    "properties": {
                                        "lowercase": {"type": "boolean"},
                                        "uppercase": {"type": "boolean"},
                                        "digits": {"type": "boolean"},
                                        "special": {"type": "boolean"},
                                        "unicode": {"type": "boolean"}
                                    }
                                },
                                "patterns": {
                                    "properties": {
                                        "all_lowercase": {"type": "boolean"},
                                        "all_uppercase": {"type": "boolean"},
                                        "all_digits": {"type": "boolean"},
                                        "starts_uppercase": {"type": "boolean"},
                                        "ends_digits": {"type": "boolean"},
                                        "ends_special": {"type": "boolean"},
                                        "keyboard_walk": {"type": "boolean"},
                                        "repeating": {"type": "boolean"},
                                        "sequential_digits": {"type": "boolean"},
                                        "leet_speak": {"type": "boolean"}
                                    }
                                },
                                "entropy_estimate": {"type": "float"},
                                "complexity_score": {"type": "integer"}
                            }
                        },
                        "wordlist_match": {
                            "properties": {
                                "username_in_common_list": {"type": "boolean"},
                                "password_in_common_list": {"type": "boolean"},
                                "matched_wordlist": {"type": "keyword"}
                            }
                        },
                        "remember_me": {"type": "boolean"},
                        "redirect_to": {"type": "keyword"}
                    }
                },
                "classification": {
                    "properties": {
                        "indicators": {"type": "keyword"},
                        "primary_classification": {"type": "keyword"},
                        "confidence": {"type": "keyword"}
                    }
                },
                "log_type": {"type": "keyword"},
                "research_project": {"type": "keyword"},
                "data_classification": {"type": "keyword"},
                "source_system": {"type": "keyword"}
            }
        }
    },
    "honeypot-access": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "source_ip": {"type": "ip"},
                "method": {"type": "keyword"},
                "path": {"type": "keyword"},
                "status_code": {"type": "integer"},
                "response_size": {"type": "long"},
                "user_agent": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                "raw_log": {"type": "text"},
                "log_type": {"type": "keyword"},
                "research_project": {"type": "keyword"},
                "data_classification": {"type": "keyword"},
                "source_system": {"type": "keyword"}
            }
        }
    },
    "honeypot-wazuh": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "agent": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "name": {"type": "keyword"},
                        "id": {"type": "keyword"}
                    }
                },
                "data": {
                    "properties": {
                        "srcip": {"type": "ip"},
                        "srcuser": {"type": "keyword"},
                        "srcport": {"type": "keyword"},
                        "protocol": {"type": "keyword"},
                        "id": {"type": "keyword"},
                        "url": {"type": "keyword"}
                    }
                },
                "rule": {
                    "properties": {
                        "description": {"type": "keyword"},
                        "level": {"type": "integer"},
                        "id": {"type": "keyword"},
                        "groups": {"type": "keyword"},
                        "mitre": {
                            "properties": {
                                "technique": {"type": "keyword"},
                                "id": {"type": "keyword"},
                                "tactic": {"type": "keyword"}
                            }
                        },
                        "pci_dss": {"type": "keyword"},
                        "nist_800_53": {"type": "keyword"},
                        "gdpr": {"type": "keyword"},
                        "hipaa": {"type": "keyword"},
                        "tsc": {"type": "keyword"},
                        "gpg13": {"type": "keyword"},
                        "firedtimes": {"type": "integer"},
                        "mail": {"type": "boolean"}
                    }
                },
                "GeoLocation": {
                    "properties": {
                        "country_name": {"type": "keyword"},
                        "location": {"type": "geo_point"}
                    }
                },
                "location": {"type": "keyword"},
                "manager": {
                    "properties": {
                        "name": {"type": "keyword"}
                    }
                },
                "full_log": {"type": "text"},
                "decoder": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "parent": {"type": "keyword"}
                    }
                },
                "input": {
                    "properties": {
                        "type": {"type": "keyword"}
                    }
                },
                "predecoder": {
                    "properties": {
                        "program_name": {"type": "keyword"},
                        "timestamp": {"type": "keyword"},
                        "hostname": {"type": "keyword"}
                    }
                },
                "id": {"type": "keyword"},
                "timestamp": {"type": "keyword"}
            }
        }
    }
}


# ==============================================================
# Step 3: Transform datasets
# ==============================================================
APACHE_LOG_RE = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+[^"]*"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


def parse_apache_log(log_line):
    """Parse Apache combined log format into structured fields."""
    m = APACHE_LOG_RE.match(log_line)
    if not m:
        return None
    return {
        "source_ip": m.group("ip"),
        "method": m.group("method"),
        "path": m.group("path"),
        "status_code": int(m.group("status")),
        "response_size": int(m.group("size")),
        "user_agent": m.group("ua"),
    }


def transform_credentials():
    """Read honeypot-credentials.json and yield (action, doc) tuples."""
    print("\n=== Transforming honeypot-credentials.json ===")
    with open(CREDS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"  Loaded {len(data)} docs")

    for doc in data:
        yield (
            json.dumps({"index": {"_index": "honeypot-credentials"}}),
            json.dumps(doc)
        )


def transform_access():
    """Read honeypot-access.json, parse Apache logs, yield (action, doc) tuples."""
    print("\n=== Transforming honeypot-access.json ===")
    with open(ACCESS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"  Loaded {len(data)} docs")

    parsed = 0
    for doc in data:
        log_line = doc.get("log", "")
        fields = parse_apache_log(log_line)
        if fields is None:
            # Keep raw doc with timestamp
            out = {
                "@timestamp": doc.get("@timestamp"),
                "raw_log": log_line,
                "log_type": doc.get("log_type", "honeypot"),
                "research_project": doc.get("research_project"),
                "data_classification": doc.get("data_classification"),
                "source_system": doc.get("source_system"),
            }
        else:
            out = {
                "@timestamp": doc.get("@timestamp"),
                "raw_log": log_line,
                "log_type": doc.get("log_type", "honeypot"),
                "research_project": doc.get("research_project"),
                "data_classification": doc.get("data_classification"),
                "source_system": doc.get("source_system"),
                **fields,
            }
            parsed += 1

        yield (
            json.dumps({"index": {"_index": "honeypot-access"}}),
            json.dumps(out)
        )

    print(f"  Parsed {parsed}/{len(data)} Apache log lines")


def transform_wazuh():
    """Read exported Wazuh NDJSON and yield (action, doc) tuples."""
    print("\n=== Transforming Wazuh export ===")
    count = 0
    with open(WAZUH_EXPORT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            doc = json.loads(line)
            yield (
                json.dumps({"index": {"_index": "honeypot-wazuh"}}),
                json.dumps(doc)
            )
            count += 1
    print(f"  Prepared {count} Wazuh docs")


# ==============================================================
# Step 4: Create indices and bulk import
# ==============================================================
def create_index(name, mapping):
    """Create an index with mapping, deleting if it already exists."""
    print(f"\n  Creating index: {name}")
    # Delete if exists
    try:
        elk_request("DELETE", f"/{name}")
        print(f"    Deleted existing index")
    except Exception:
        pass

    elk_request("PUT", f"/{name}", mapping)
    print(f"    Created with mapping")


def bulk_import(doc_generator, index_name):
    """Bulk import docs from a generator yielding (action_line, doc_line) tuples."""
    lines = []
    total = 0
    errors = 0

    for action_line, doc_line in doc_generator:
        lines.append(action_line)
        lines.append(doc_line)

        if len(lines) >= BULK_CHUNK * 2:
            result = elk_bulk(lines)
            batch_count = len(lines) // 2
            total += batch_count
            if result.get("errors"):
                err_items = [i for i in result["items"]
                             if "error" in i.get("index", i.get("create", {}))]
                errors += len(err_items)
            print(f"    {index_name}: imported {total} docs so far...")
            lines = []

    # Flush remaining
    if lines:
        result = elk_bulk(lines)
        batch_count = len(lines) // 2
        total += batch_count
        if result.get("errors"):
            err_items = [i for i in result["items"]
                         if "error" in i.get("index", i.get("create", {}))]
            errors += len(err_items)

    print(f"    {index_name}: {total} docs imported, {errors} errors")
    return total, errors


# ==============================================================
# Main
# ==============================================================
def main():
    print("=" * 60)
    print("Honeypot Research Dashboard — Data Import Pipeline")
    print("=" * 60)

    # Step 1: Export Wazuh
    export_wazuh()

    # Step 2: Create indices
    print("\n=== Creating indices on ELK ===")
    for idx_name, mapping in MAPPINGS.items():
        create_index(idx_name, mapping)

    # Step 3: Bulk import
    print("\n=== Bulk importing data ===")

    # Credentials
    total_c, err_c = bulk_import(transform_credentials(), "honeypot-credentials")

    # Access
    total_a, err_a = bulk_import(transform_access(), "honeypot-access")

    # Wazuh
    total_w, err_w = bulk_import(transform_wazuh(), "honeypot-wazuh")

    # Step 4: Verify
    print("\n=== Verification ===")
    for idx in ["honeypot-credentials", "honeypot-access", "honeypot-wazuh"]:
        # Force refresh
        elk_request("POST", f"/{idx}/_refresh")
        result = elk_request("GET", f"/{idx}/_count")
        print(f"  {idx}: {result['count']} docs")

    print(f"\n=== Summary ===")
    print(f"  honeypot-credentials: {total_c} imported ({err_c} errors)")
    print(f"  honeypot-access:      {total_a} imported ({err_a} errors)")
    print(f"  honeypot-wazuh:       {total_w} imported ({err_w} errors)")
    print(f"\nDone! Next: create Kibana data views and dashboard.")


if __name__ == "__main__":
    main()
