#!/bin/bash
curl -s -X POST "http://localhost:5001/api/v1/workflows/edd6e990-5b10-4793-9dc5-c9dead3a22b5/execute" \
  -H "Authorization: Bearer YOUR_SHUFFLE_API_KEY" \
  -H "Content-Type: application/json" -d "{}" >> "$HOME/wf7-trigger.log" 2>&1
echo " $(date)" >> "$HOME/wf7-trigger.log"
