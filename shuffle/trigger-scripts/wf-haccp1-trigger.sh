#!/bin/bash
# Trigger WF-HACCP-1 (Phase14 Tier1 Investigation) via Shuffle API
# Called by system cron every 5 min
# No Ollama calls — reads pre-enriched llm.* fields from haccp ES

SHUFFLE_API="http://localhost:5001"
API_KEY="YOUR_SHUFFLE_API_KEY"
WF_ID="3e0e633d-7538-4685-9348-9c2317cc33e5"
START_NODE="35ef926f-e7cc-4f52-988e-769ee11f684c"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"execution_argument\":\"{\\\"type\\\":\\\"tier1_poll\\\"}\",\"start\":\"${START_NODE}\"}" \
  "${SHUFFLE_API}/api/v1/workflows/${WF_ID}/execute")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | HTTP ${HTTP_CODE} | ${BODY}"
