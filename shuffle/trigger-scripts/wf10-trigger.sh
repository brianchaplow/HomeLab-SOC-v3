#!/bin/bash
# Trigger WF10 (Morning Briefing) via Shuffle API
# Called by system cron at 0530 EDT (local time)

SHUFFLE_API="http://localhost:5001"
API_KEY="YOUR_SHUFFLE_API_KEY"
WF_ID="e70b654d-ceeb-4851-aebc-043e8e5013aa"
# START_NODE must be updated after building workflow in UI
START_NODE="212e8f57-bb63-4ca0-a2f4-8cf199add42a"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"execution_argument\":\"{\\\"type\\\":\\\"morning_briefing\\\"}\",\"start\":\"${START_NODE}\"}" \
  "${SHUFFLE_API}/api/v1/workflows/${WF_ID}/execute")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | HTTP ${HTTP_CODE} | ${BODY}"
