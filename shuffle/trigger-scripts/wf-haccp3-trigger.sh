#!/bin/bash
# Trigger WF-HACCP-3 (Nightly Wazuh Cross-Correlator) via Shuffle API
# Called by bchaplow crontab at 0200 ET nightly
# No Ollama calls; queries brisket OpenSearch + haccp ES, correlates on IP

SHUFFLE_API="http://localhost:5001"
API_KEY="YOUR_SHUFFLE_API_KEY"
WF_ID="c94fd866-0c53-486b-ba4f-92f4330e6dd6"
START_NODE="1d7ed962-d56d-4bdc-9d59-d0a5bcfa8813"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
  -H "Authorization: Bearer YOUR_SHUFFLE_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"execution_argument\":\"{\\\"type\\\":\\\"nightly_cross_correlator\\\"}\",\"start\":\"${START_NODE}\"}" \
  "${SHUFFLE_API}/api/v1/workflows/${WF_ID}/execute")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | WF-HACCP-3 | HTTP ${HTTP_CODE} | ${BODY}"
