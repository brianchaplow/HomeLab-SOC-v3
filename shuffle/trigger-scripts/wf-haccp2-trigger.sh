#!/bin/bash
# Trigger WF-HACCP-2 (Tier2 Novel-Entity Digest) via Shuffle API
# Called by system cron once daily at 0730 ET
# No Ollama calls; reads haccp-entities-seen + ES ingest-geoip

SHUFFLE_API="http://localhost:5001"
API_KEY="YOUR_SHUFFLE_API_KEY"
WF_ID="5c8016af-7593-42eb-85fe-4ae9166fbc8e"
START_NODE="0dddf4a7-e2a9-4d98-9217-bdef27912f8e"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"execution_argument\":\"{\\\"type\\\":\\\"tier2_digest\\\"}\",\"start\":\"${START_NODE}\"}" \
  "${SHUFFLE_API}/api/v1/workflows/${WF_ID}/execute")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | HTTP ${HTTP_CODE} | ${BODY}"
