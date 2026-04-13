#!/bin/bash
# Trigger WF-HACCP-1.1 (Cortex Enrichment on Tier1 Cases) via Shuffle API
# Called by bchaplow crontab every 5 min (offset 2 min from WF-HACCP-1)
# No Ollama calls; queries TheHive for new cases, creates observables, submits Cortex jobs

SHUFFLE_API="http://localhost:5001"
API_KEY="YOUR_SHUFFLE_API_KEY"
WF_ID="4d5153f1-ee3a-48a1-bb5c-8a6159cc262c"
START_NODE="145ab5fc-641e-4b68-81d8-19eb11c8527f"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"execution_argument\":\"{\\\"type\\\":\\\"cortex_enrichment\\\"}\",\"start\":\"${START_NODE}\"}" \
  "${SHUFFLE_API}/api/v1/workflows/${WF_ID}/execute")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | WF-HACCP-1.1 | HTTP ${HTTP_CODE} | ${BODY}"
