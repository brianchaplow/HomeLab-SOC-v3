#!/bin/bash
# WF9: Stalker Visit Alert - every 5 minutes
# Webhook URL is per-install; set WF9_WEBHOOK_URL (Shuffle UI -> workflow -> webhook trigger)
WEBHOOK_URL="${WF9_WEBHOOK_URL:-http://localhost:3443/api/v1/hooks/webhook_YOUR_WEBHOOK_ID}"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | HTTP ${HTTP_CODE} | ${BODY}"
