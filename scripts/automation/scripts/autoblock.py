#!/usr/bin/env python3
"""
###############################################################################
# AUTO-BLOCK SCRIPT
# Purpose: Automatically block CONFIRMED malicious IPs at Cloudflare
# 
# CRITICAL: Only blocks IPs with abuse score >= 90 AND >= 5 reports
#           This ensures we never block legitimate visitors
# 
# Schedule: Hourly via cron
# 
# Author:  Brian S. Chaplow
# 
# Process:
#   1. Query OpenSearch for high-threat IPs not yet blocked
#   2. Verify against whitelist
#   3. Block at Cloudflare via API
#   4. Mark as blocked in OpenSearch
#   5. Send notification to Discord
###############################################################################
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

import requests
import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from utils.opensearch_client import get_client
from utils.discord_notify import get_notifier

# =============================================================================
# LOGGING SETUP
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================
CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"
BLOCKED_LOG_PATH = Path(__file__).parent.parent / "data" / "blocked_ips.json"

def load_config() -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"Could not load config: {e}, using defaults")
        return {}

def load_blocked_log() -> Dict[str, Any]:
    """Load blocked IPs log from disk."""
    try:
        if BLOCKED_LOG_PATH.exists():
            with open(BLOCKED_LOG_PATH) as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load blocked log: {e}")
    return {"blocked": [], "total_blocked": 0}

def save_blocked_log(log: Dict[str, Any]):
    """Save blocked IPs log to disk."""
    try:
        BLOCKED_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(BLOCKED_LOG_PATH, 'w') as f:
            json.dump(log, f, indent=2)
    except Exception as e:
        logger.error(f"Could not save blocked log: {e}")


# =============================================================================
# CLOUDFLARE CLIENT
# =============================================================================
class CloudflareClient:
    """
    Client for Cloudflare API - IP blocking via Firewall Rules.
    
    Uses Access Rules (IP Block) for simplicity.
    """
    
    BASE_URL = "https://api.cloudflare.com/client/v4"
    
    def __init__(
        self, 
        api_token: Optional[str] = None,
        account_id: Optional[str] = None
    ):
        """Initialize with API token and zone ID."""
        self.api_token = api_token or os.getenv('CLOUDFLARE_API_TOKEN')
        self.account_id = account_id or os.getenv('CLOUDFLARE_ACCOUNT_ID')
        
        if not self.api_token:
            logger.warning("CLOUDFLARE_API_TOKEN not set")
        
        if not self.account_id:
            logger.warning("CLOUDFLARE_ACCOUNT_ID not set")
        
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }
    
    @property
    def is_configured(self) -> bool:
        """Check if Cloudflare is properly configured."""
        return bool(self.api_token and self.account_id)
    
    def block_ip(
        self, 
        ip: str, 
        note: str = "SOC Auto-Block",
        mode: str = "block"
    ) -> Dict[str, Any]:
        """
        Block an IP at Cloudflare zone level.
        
        Args:
            ip: IP address to block
            note: Note to attach to the rule
            mode: "block" (hard block) or "challenge" (captcha)
            
        Returns:
            Dict with success status and rule ID
        """
        if not self.is_configured:
            return {"success": False, "error": "Cloudflare not configured"}
        
        # Create IP Access Rule
        url = f"{self.BASE_URL}/accounts/{self.account_id}/firewall/access_rules/rules"
        
        payload = {
            "mode": mode,
            "configuration": {
                "target": "ip",
                "value": ip
            },
            "notes": f"{note} | {datetime.utcnow().isoformat()}"
        }
        
        try:
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=10
            )
            
            data = response.json()
            
            if data.get("success"):
                rule_id = data.get("result", {}).get("id")
                logger.info(f"Blocked {ip} at Cloudflare (rule: {rule_id})")
                return {
                    "success": True,
                    "rule_id": rule_id,
                    "ip": ip
                }
            else:
                errors = data.get("errors", [])
                error_msg = errors[0].get("message") if errors else "Unknown error"
                
                # Check if already blocked
                if "already exists" in error_msg.lower():
                    logger.info(f"IP {ip} already blocked at Cloudflare")
                    return {"success": True, "already_blocked": True, "ip": ip}
                
                logger.error(f"Cloudflare block failed: {error_msg}")
                return {"success": False, "error": error_msg, "ip": ip}
                
        except Exception as e:
            logger.error(f"Error blocking {ip}: {e}")
            return {"success": False, "error": str(e), "ip": ip}
    
    def list_blocked_ips(self, page: int = 1, per_page: int = 50) -> List[Dict]:
        """List currently blocked IPs."""
        if not self.is_configured:
            return []
        
        url = f"{self.BASE_URL}/accounts/{self.account_id}/firewall/access_rules/rules"
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                params={"page": page, "per_page": per_page, "mode": "block"},
                timeout=10
            )
            
            data = response.json()
            
            if data.get("success"):
                return data.get("result", [])
            return []
            
        except Exception as e:
            logger.error(f"Error listing blocked IPs: {e}")
            return []


# =============================================================================
# WHITELIST CHECKER (same as enrichment.py)
# =============================================================================
class WhitelistChecker:
    """Check IPs against whitelist."""
    
    def __init__(self, config: Dict[str, Any]):
        whitelist = config.get('whitelist', {})
        self.ips = set(whitelist.get('ips', []))
        self.fingerprints = set(whitelist.get('fingerprints', []))
        
        self.ip_prefixes = []
        for ip in self.ips:
            if '/' in ip:
                base = ip.split('/')[0]
                parts = base.split('.')
                bits = int(ip.split('/')[1])
                prefix_parts = bits // 8
                self.ip_prefixes.append('.'.join(parts[:prefix_parts]) + '.')
    
    def is_whitelisted(self, ip: str, fingerprint: str = None) -> bool:
        if ip in self.ips:
            return True
        for prefix in self.ip_prefixes:
            if ip.startswith(prefix):
                return True
        if fingerprint and fingerprint in self.fingerprints:
            return True
        return False


# =============================================================================
# MAIN AUTO-BLOCK LOGIC
# =============================================================================
def run_autoblock(dry_run: bool = False):
    """
    Main auto-block routine.
    
    Args:
        dry_run: If True, report what would be blocked without blocking
    """
    logger.info("=" * 60)
    logger.info("AUTO-BLOCK RUN STARTING" + (" (DRY RUN)" if dry_run else ""))
    logger.info("=" * 60)
    
    # Load config
    config = load_config()
    block_config = config.get('blocking', {})
    
    if not block_config.get('enabled', True):
        logger.info("Auto-blocking is disabled in config")
        return
    
    threshold = int(os.getenv('BLOCK_THRESHOLD', block_config.get('threshold', 90)))
    min_reports = block_config.get('min_reports', 5)
    
    logger.info(f"Blocking threshold: score >= {threshold}, reports >= {min_reports}")
    
    # Initialize clients
    try:
        os_client = get_client()
        if not os_client.test_connection():
            logger.error("Cannot connect to OpenSearch, aborting")
            return
    except Exception as e:
        logger.error(f"OpenSearch client error: {e}")
        return
    
    cf_client = CloudflareClient()
    if not cf_client.is_configured:
        logger.warning("Cloudflare not configured, will only mark in OpenSearch")
    
    notifier = get_notifier()
    whitelist = WhitelistChecker(config)
    blocked_log = load_blocked_log()
    
    # Get high-threat IPs
    high_threats = os_client.get_high_threat_ips(
        index='apache-parsed-v2',
        threshold=threshold,
        hours=24
    )
    
    if not high_threats:
        logger.info("No high-threat IPs found to block")
        return
    
    logger.info(f"Found {len(high_threats)} high-threat IPs to evaluate")
    
    # Process each IP
    blocked_count = 0
    skipped_whitelist = 0
    skipped_reports = 0
    already_blocked = 0
    
    for threat in high_threats:
        ip = threat.get('client_ip')
        threat_intel = threat.get('threat_intel', {}).get('abuseipdb', {})
        fingerprint = threat.get('visitor_fingerprint')
        
        score = threat_intel.get('score', 0)
        reports = threat_intel.get('total_reports', 0)
        country = threat_intel.get('country_code', 'Unknown')
        isp = threat_intel.get('isp', 'Unknown')
        
        # Skip if whitelisted
        if whitelist.is_whitelisted(ip, fingerprint):
            logger.info(f"Skipping whitelisted IP: {ip}")
            skipped_whitelist += 1
            continue
        
        # Skip if not enough reports (could be false positive)
        if reports < min_reports:
            logger.info(f"Skipping {ip}: only {reports} reports (need {min_reports})")
            skipped_reports += 1
            continue
        
        # Skip if already in our log
        if ip in [b['ip'] for b in blocked_log.get('blocked', [])]:
            logger.debug(f"Already in blocked log: {ip}")
            already_blocked += 1
            continue
        
        reason = (
            f"AbuseIPDB score {score}/100 with {reports} reports. "
            f"ISP: {isp}. Country: {country}."
        )
        
        if dry_run:
            logger.info(f"[DRY RUN] Would block: {ip} (score: {score}, reports: {reports})")
            continue
        
        # Block at Cloudflare
        if cf_client.is_configured:
            result = cf_client.block_ip(
                ip=ip,
                note=f"SOC Auto-Block: score {score}",
                mode=block_config.get('cloudflare', {}).get('action', 'block')
            )
            
            if result.get('already_blocked'):
                already_blocked += 1
                continue
            
            if not result.get('success'):
                logger.error(f"Failed to block {ip}: {result.get('error')}")
                continue
        
        # Mark as blocked in OpenSearch
        os_client.mark_ip_blocked(
            index='apache-parsed-v2',
            ip=ip,
            block_info={'reason': reason}
        )
        
        # Add to blocked log
        blocked_log.setdefault('blocked', []).append({
            'ip': ip,
            'score': score,
            'reports': reports,
            'country': country,
            'isp': isp,
            'blocked_at': datetime.utcnow().isoformat(),
            'reason': reason
        })
        
        # Send notification
        notifier.send_block_notification(
            ip=ip,
            score=score,
            reason=reason,
            duration=block_config.get('duration', '7d')
        )
        
        blocked_count += 1
        logger.info(f"BLOCKED: {ip} (score: {score}, reports: {reports})")
    
    # Update totals and save
    blocked_log['total_blocked'] = len(blocked_log.get('blocked', []))
    save_blocked_log(blocked_log)
    
    # Summary
    logger.info("-" * 60)
    logger.info("AUTO-BLOCK COMPLETE")
    logger.info(f"  Blocked: {blocked_count}")
    logger.info(f"  Already blocked: {already_blocked}")
    logger.info(f"  Skipped (whitelist): {skipped_whitelist}")
    logger.info(f"  Skipped (low reports): {skipped_reports}")
    logger.info(f"  Total ever blocked: {blocked_log['total_blocked']}")
    logger.info("=" * 60)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto-Block Script")
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Report what would be blocked without blocking'
    )
    parser.add_argument(
        '--list-blocked',
        action='store_true',
        help='List currently blocked IPs from Cloudflare'
    )
    
    args = parser.parse_args()
    
    if args.list_blocked:
        cf = CloudflareClient()
        blocked = cf.list_blocked_ips()
        print(f"\nCurrently blocked IPs ({len(blocked)}):")
        for rule in blocked:
            ip = rule.get('configuration', {}).get('value', 'N/A')
            note = rule.get('notes', '')
            created = rule.get('created_on', '')
            print(f"  {ip} | {note} | {created}")
    else:
        run_autoblock(dry_run=args.dry_run)
