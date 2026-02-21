#!/bin/bash
# ==============================================================================
# SOC AUTOMATION LOCAL BACKUP
# ==============================================================================

BACKUP_BASE="/share/Backups/infrastructure"
DATE=$(date +%Y%m%d)

echo "[$(date)] Starting SOC backup..."

# Backup SOC automation configs
tar -czf ${BACKUP_BASE}/soc-automation/soc-backup-${DATE}.tar.gz \
  --exclude='*.log' \
  --exclude='__pycache__' \
  -C /share/Container soc-automation

# Cleanup old backups (keep 4 weeks)
find ${BACKUP_BASE} -name "*.tar.gz" -mtime +28 -delete

echo "[$(date)] SOC backup complete"
