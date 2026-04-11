#!/bin/bash
# WF-CS1: Capitol Signals Collector
# Runs collectors, then summarizes results for Shuffle (under 32KB limit)
# Cron: 0 2 * * * (UTC 02:00 / EST 21:00)

LOGFILE="/home/bchaplow/wf-cs1-trigger.log"
WEBHOOK_URL="http://localhost:3443/api/v1/hooks/webhook_ac71e84f-330f-4ff1-9c28-d09f69e8a1f1"
TMPFILE="/tmp/cs1-result.json"
SUMMARY="/tmp/cs1-summary.json"

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Starting Capitol Signals collector run" >> "$LOGFILE"

# Run collectors (this takes 2-5 minutes with Ollama)
curl -s -X POST http://localhost:5010/run > "$TMPFILE"

if [ ! -s "$TMPFILE" ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: Empty response from collector" >> "$LOGFILE"
    rm -f "$TMPFILE"
    exit 1
fi

FULLSIZE=$(wc -c < "$TMPFILE")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Collector finished ($FULLSIZE bytes), summarizing for Shuffle" >> "$LOGFILE"

# Summarize to under 32KB: extract counts + high-value items only
python3 /home/bchaplow/cs1-summarize.py 2>> "$LOGFILE"

SUMSIZE=$(wc -c < "$SUMMARY")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Summary: $SUMSIZE bytes (from $FULLSIZE)" >> "$LOGFILE"

# Send summary to Shuffle webhook
SHUFFLE_RESULT=$(curl -s -H "Content-Type: application/json" "$WEBHOOK_URL" -d @"$SUMMARY")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Shuffle response: $SHUFFLE_RESULT" >> "$LOGFILE"

rm -f "$TMPFILE" "$SUMMARY"
