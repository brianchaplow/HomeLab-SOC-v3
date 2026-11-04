#!/bin/bash
curl -s -X POST "http://localhost:5001/api/v1/workflows/012e3168-5d9b-4020-bac1-87812e8ca466/execute" \
  -H "Authorization: Bearer YOUR_SHUFFLE_API_KEY" \
  -H "Content-Type: application/json" -d "{}" >> "$HOME/wf6-trigger.log" 2>&1
echo " $(date)" >> "$HOME/wf6-trigger.log"
