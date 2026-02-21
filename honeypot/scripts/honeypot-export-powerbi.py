#!/usr/bin/env python3
"""
Honeypot Research — Power BI Export
Pulls all docs from 3 ELK honeypot indices via Scroll API, flattens nested
JSON into dot-notation columns, and writes CSVs + a manifest for Power BI.

Output directory: ~/Documents/honeypot-powerbi/
  honeypot-credentials.csv
  honeypot-access.csv
  honeypot-wazuh.csv
  export-manifest.json

Usage: python reference/honeypot-export-powerbi.py
"""

import base64
import csv
import json
import os
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

# --- Configuration ---
ELK_HOST = "https://10.10.30.23:9200"
ELK_USER = "elastic"
ELK_PASS = os.environ.get("ELK_PASS", "your_elastic_password")

INDICES = ["honeypot-credentials", "honeypot-access", "honeypot-wazuh"]
SCROLL_SIZE = 1000
SCROLL_TIMEOUT = "2m"

OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "Documents", "honeypot-powerbi")

# SSL context for self-signed certs
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

AUTH_HEADER = "Basic " + base64.b64encode(f"{ELK_USER}:{ELK_PASS}".encode()).decode()


# --- ELK Helpers ---

def elk_request(method, path, body=None):
    """Make a request to ELK Elasticsearch."""
    url = f"{ELK_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", AUTH_HEADER)
    try:
        with urllib.request.urlopen(req, context=CTX) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        print(f"  HTTP {e.code}: {err_body[:500]}")
        raise


def scroll_all(index):
    """Scroll through all docs in an index, returning list of _source dicts."""
    docs = []

    # Initial search with scroll
    result = elk_request("POST", f"/{index}/_search?scroll={SCROLL_TIMEOUT}", {
        "size": SCROLL_SIZE,
        "query": {"match_all": {}},
        "sort": ["_doc"],
        "track_total_hits": True
    })

    scroll_id = result.get("_scroll_id")
    hits = result["hits"]["hits"]
    total = result["hits"]["total"]["value"]
    docs.extend(h["_source"] for h in hits)
    print(f"  {index}: {total} total docs — batch 1 ({len(hits)} docs)")

    # Continue scrolling
    batch = 2
    while hits:
        result = elk_request("POST", "/_search/scroll", {
            "scroll": SCROLL_TIMEOUT,
            "scroll_id": scroll_id
        })
        scroll_id = result.get("_scroll_id")
        hits = result["hits"]["hits"]
        if hits:
            docs.extend(h["_source"] for h in hits)
            print(f"  {index}: batch {batch} ({len(hits)} docs, {len(docs)} total)")
        batch += 1

    # Clear scroll
    if scroll_id:
        try:
            elk_request("DELETE", "/_search/scroll", {"scroll_id": scroll_id})
        except Exception:
            pass

    print(f"  {index}: fetched {len(docs)} docs")
    return docs


# --- JSON Flattener ---

def flatten_doc(doc, parent_key="", sep="."):
    """Flatten a nested dict into dot-notation keys.

    - Nested dicts -> dot-separated keys
    - Lists of scalars -> pipe-delimited string
    - Lists of dicts -> pipe-delimited JSON (rare, but handles it)
    - geo_point {lat, lon} at GeoLocation.location -> GeoLocation.lat, GeoLocation.lon
    """
    items = {}
    for key, val in doc.items():
        full_key = f"{parent_key}{sep}{key}" if parent_key else key

        # Special handling: geo_point stored as {"lat": ..., "lon": ...}
        if full_key == "GeoLocation.location" and isinstance(val, dict):
            lat = val.get("lat", "")
            lon = val.get("lon", "")
            items["GeoLocation.lat"] = lat
            items["GeoLocation.lon"] = lon
            continue

        if isinstance(val, dict):
            items.update(flatten_doc(val, full_key, sep))
        elif isinstance(val, list):
            # Convert list to pipe-delimited string
            str_parts = []
            for item in val:
                if isinstance(item, dict):
                    str_parts.append(json.dumps(item, ensure_ascii=False))
                else:
                    str_parts.append(str(item))
            items[full_key] = " | ".join(str_parts)
        else:
            items[full_key] = val

    return items


# --- CSV Writer ---

def write_csv(docs, index_name):
    """Flatten all docs, discover all columns, write CSV."""
    if not docs:
        print(f"  {index_name}: no docs, skipping CSV")
        return 0, set()

    # Pass 1: flatten all docs and collect all field names
    flat_docs = []
    all_fields = set()
    for doc in docs:
        flat = flatten_doc(doc)
        flat_docs.append(flat)
        all_fields.update(flat.keys())

    # Sort columns: @timestamp first, then alphabetical
    columns = sorted(all_fields)
    if "@timestamp" in columns:
        columns.remove("@timestamp")
        columns.insert(0, "@timestamp")

    # Write CSV
    csv_path = os.path.join(OUTPUT_DIR, f"{index_name}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        for flat in flat_docs:
            row = []
            for col in columns:
                val = flat.get(col, "")
                if val is None:
                    val = ""
                elif isinstance(val, bool):
                    val = str(val).lower()
                else:
                    val = str(val)
                row.append(val)
            writer.writerow(row)

    print(f"  {index_name}: wrote {len(flat_docs)} rows, {len(columns)} columns -> {csv_path}")
    return len(flat_docs), all_fields


# --- Manifest ---

def find_date_range(docs):
    """Find min/max @timestamp across docs."""
    timestamps = []
    for doc in docs:
        ts = doc.get("@timestamp") or doc.get("timestamp")
        if ts:
            timestamps.append(str(ts))
    if not timestamps:
        return None, None
    timestamps.sort()
    return timestamps[0], timestamps[-1]


def write_manifest(index_stats):
    """Write export-manifest.json with counts and date ranges."""
    manifest = {
        "export_timestamp": datetime.now(timezone.utc).isoformat(),
        "elk_host": ELK_HOST,
        "output_dir": OUTPUT_DIR,
        "indices": {}
    }
    for index_name, info in index_stats.items():
        manifest["indices"][index_name] = {
            "doc_count": info["count"],
            "column_count": info["columns"],
            "date_min": info["date_min"],
            "date_max": info["date_max"],
            "csv_file": f"{index_name}.csv"
        }

    manifest_path = os.path.join(OUTPUT_DIR, "export-manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n  Manifest -> {manifest_path}")
    return manifest


# --- Main ---

def main():
    print("=" * 60)
    print("Honeypot Research — Power BI Export")
    print("=" * 60)

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\nOutput: {OUTPUT_DIR}")

    index_stats = {}

    for index_name in INDICES:
        print(f"\n--- {index_name} ---")

        # Scroll all docs
        docs = scroll_all(index_name)

        # Find date range
        date_min, date_max = find_date_range(docs)

        # Flatten and write CSV
        count, fields = write_csv(docs, index_name)

        index_stats[index_name] = {
            "count": count,
            "columns": len(fields),
            "date_min": date_min,
            "date_max": date_max
        }

    # Write manifest
    manifest = write_manifest(index_stats)

    # Verify against ES _count
    print("\n--- Verification ---")
    all_match = True
    for index_name in INDICES:
        try:
            result = elk_request("GET", f"/{index_name}/_count")
            es_count = result["count"]
        except Exception:
            es_count = "ERROR"
        export_count = index_stats[index_name]["count"]
        match = "OK" if es_count == export_count else "MISMATCH"
        if match != "OK":
            all_match = False
        print(f"  {index_name}: ES={es_count}, exported={export_count} [{match}]")

    # Summary
    print("\n" + "=" * 60)
    print("Export complete!")
    total = sum(s["count"] for s in index_stats.values())
    print(f"  Total docs: {total}")
    print(f"  Files: {OUTPUT_DIR}")
    if all_match:
        print("  All counts verified against Elasticsearch.")
    else:
        print("  WARNING: Some counts did not match — check above.")
    print("=" * 60)


if __name__ == "__main__":
    main()
