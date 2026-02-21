#!/bin/bash
# Trigger WF2 (Watch Turnover Digest) via Shuffle API
# Called by system cron at 10:45 and 22:45 UTC (05:45/17:45 EST)

SHUFFLE_API="http://localhost:5001"
API_KEY="YOUR_SHUFFLE_API_KEY"
WF_ID="8e834f39-c9e9-47da-892d-b068d2f6bbe9"
START_NODE="03e30fac-31c7-4e43-9571-f2cb2adb437d"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"execution_argument\":\"{\\\"type\\\":\\\"scheduled_digest\\\"}\",\"start\":\"${START_NODE}\"}" \
  "${SHUFFLE_API}/api/v1/workflows/${WF_ID}/execute")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | HTTP ${HTTP_CODE} | ${BODY}"
