#!/bin/bash
curl -s -X POST "http://localhost:5001/api/v1/workflows/5fca80c6-178f-4ec5-ab23-f42ae7fd4b2b/execute" \
  -H "Authorization: Bearer YOUR_SHUFFLE_API_KEY" \
  -H "Content-Type: application/json" -d "{}" >> /home/bchaplow/wf8-trigger.log 2>&1
echo " $(date)" >> /home/bchaplow/wf8-trigger.log
