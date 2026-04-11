#!/bin/bash
# Trigger WF11 (Evening Digest) via Shuffle API
# Called by system cron at 1730 EDT (local time)

SHUFFLE_API="http://localhost:5001"
API_KEY="YOUR_SHUFFLE_API_KEY"
# WF_ID must be updated after cloning WF10 in UI
WF_ID="3f92a661-b8f5-47ca-aff4-7e70bf11db92"
START_NODE="ac6072b1-26dd-4aeb-a3ea-f58dc19e23f3"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"execution_argument\":\"{\\\"type\\\":\\\"evening_digest\\\"}\",\"start\":\"${START_NODE}\"}" \
  "${SHUFFLE_API}/api/v1/workflows/${WF_ID}/execute")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | HTTP ${HTTP_CODE} | ${BODY}"
