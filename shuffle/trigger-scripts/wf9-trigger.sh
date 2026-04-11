#!/bin/bash
# WF9: Stalker Visit Alert - every 5 minutes

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST http://localhost:3443/api/v1/hooks/webhook_5069df28-e494-446b-84f1-31079a57224b \
  -H "Content-Type: application/json" \
  -d "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | HTTP ${HTTP_CODE} | ${BODY}"
