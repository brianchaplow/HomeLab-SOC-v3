#!/bin/bash
# WF-PROJECTS trigger — daily project status report
# Cron: 0 8 * * * America/New_York (0800 ET)
# Posts to #project-status via $discord_webhook_projects. No Ollama.

SHUFFLE_API="http://localhost:5001"
API_KEY="YOUR_SHUFFLE_API_KEY"
WF_ID="f9d207a3-eb0c-43ca-9d0a-51c123153741"
LOG_FILE="/home/bchaplow/wf-projects-trigger.log"

HTTP_CODE=$(curl -s -o /tmp/wf-projects-trigger.out -w "%{http_code}"   -X POST "${SHUFFLE_API}/api/v1/workflows/${WF_ID}/execute"   -H "Authorization: Bearer ${API_KEY}"   -H "Content-Type: application/json"   -d '{}')

BODY=$(cat /tmp/wf-projects-trigger.out)
echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | HTTP ${HTTP_CODE} | ${BODY}" >> "${LOG_FILE}"
