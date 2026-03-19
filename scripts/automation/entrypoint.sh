#!/bin/bash
echo "[$(date)] SOC Automation starting..."

# Run initial enrichment
echo "[$(date)] Running initial enrichment..."
cd /app && python scripts/enrichment.py --startup 2>&1 | tee -a /app/logs/enrichment.log

# Test ML model loading
echo "[$(date)] Testing ML model..."
cd /app && python scripts/ml_scorer.py --test 2>&1 | tee -a /app/logs/ml_scorer.log

echo "[$(date)] Starting scheduler loop..."

# Simple scheduler loop
while true; do
    MINUTE=$(date +%M)
    HOUR=$(date +%H)
    DOW=$(date +%u)  # 1=Monday, 7=Sunday
    
    # Every 5 minutes: ML scoring
    if [ $((10#$MINUTE % 5)) -eq 0 ]; then
        echo "[$(date)] Running ML scorer..."
        cd /app && python scripts/ml_scorer.py >> /app/logs/ml_scorer.log 2>&1
    fi
    
    # Every 15 minutes: enrichment
    if [ $((10#$MINUTE % 15)) -eq 0 ]; then
        echo "[$(date)] Running enrichment..."
        cd /app && python scripts/enrichment.py >> /app/logs/enrichment.log 2>&1
    fi
    
    # Top of hour: autoblock
    if [ "$MINUTE" = "00" ]; then
        echo "[$(date)] Running autoblock..."
        cd /app && python scripts/autoblock.py >> /app/logs/autoblock.log 2>&1
    fi
    
    # 0600: Morning digest
    if [ "$HOUR" = "06" ] && [ "$MINUTE" = "00" ]; then
        echo "[$(date)] Running morning digest..."
        cd /app && python scripts/digest.py --watch morning >> /app/logs/digest.log 2>&1
    fi
    
    # 1800: Evening digest
    if [ "$HOUR" = "18" ] && [ "$MINUTE" = "00" ]; then
        echo "[$(date)] Running evening digest..."
        cd /app && python scripts/digest.py --watch evening >> /app/logs/digest.log 2>&1
    fi
    
    # Sunday 0800: Weekly digest
    if [ "$DOW" = "7" ] && [ "$HOUR" = "08" ] && [ "$MINUTE" = "00" ]; then
        echo "[$(date)] Running weekly digest..."
        cd /app && python scripts/digest.py --watch weekly >> /app/logs/digest.log 2>&1
    fi
    
    # Sleep until next minute
    sleep 60
done
