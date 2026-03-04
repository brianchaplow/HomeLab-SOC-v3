#!/usr/bin/env python3
"""
###############################################################################
# IP ENRICHMENT SCRIPT
# Purpose: Check visitor IPs against AbuseIPDB and write reputation scores
#          back to OpenSearch for threat correlation
# 
# Schedule: Every 15 minutes via cron
# 
# Author:  Brian S. Chaplow
# 
# Process:
#   1. Query OpenSearch for IPs without enrichment data
#   2. Check each IP against AbuseIPDB (with rate limiting)
#   3. Write threat intel back to OpenSearch
#   4. Alert on high-threat IPs immediately
###############################################################################
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

import requests
import yaml
from ratelimit import limits, sleep_and_retry

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
CACHE_PATH = Path(__file__).parent.parent / "data" / "ip_cache.json"

def load_config() -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"Could not load config: {e}, using defaults")
        return {}

def load_cache() -> Dict[str, Any]:
    """Load IP reputation cache from disk."""
    try:
        if CACHE_PATH.exists():
            with open(CACHE_PATH) as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load cache: {e}")
    return {"ips": {}, "last_updated": None}

def save_cache(cache: Dict[str, Any]):
    """Save IP reputation cache to disk."""
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        cache["last_updated"] = datetime.utcnow().isoformat()
        with open(CACHE_PATH, 'w') as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        logger.error(f"Could not save cache: {e}")


# =============================================================================
# ABUSEIPDB CLIENT
# =============================================================================
class AbuseIPDBClient:
    """
    Client for AbuseIPDB API.
    
    Free tier limits:
      - 1000 checks per day
      - 60 checks per minute
    """
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize with API key from param or environment."""
        self.api_key = api_key or os.getenv('ABUSEIPDB_KEY')
        
        if not self.api_key:
            logger.error("ABUSEIPDB_KEY not set!")
            raise ValueError("AbuseIPDB API key required")
        
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        self.daily_checks = 0
        self.daily_limit = 900  # Leave buffer under 1000
    
    # Rate limit: 60 per minute
    @sleep_and_retry
    @limits(calls=60, period=60)
    def check_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Check an IP address against AbuseIPDB.
        
        Args:
            ip: IP address to check
            max_age_days: How far back to look for reports
            
        Returns:
            Dict with abuse score, reports count, etc.
        """
        if self.daily_checks >= self.daily_limit:
            logger.warning(f"Daily limit reached ({self.daily_limit})")
            return None
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True
                },
                timeout=10
            )
            
            self.daily_checks += 1
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "is_tor": data.get("isTor", False),
                    "is_public_proxy": data.get("isPublicProxy", False),
                    "last_reported": data.get("lastReportedAt"),
                    "checked_at": datetime.utcnow().isoformat()
                }
            elif response.status_code == 429:
                logger.warning("Rate limited by AbuseIPDB")
                return None
            else:
                logger.error(f"AbuseIPDB error {response.status_code}: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error checking IP {ip}: {e}")
            return None


# =============================================================================
# WHITELIST CHECKER
# =============================================================================
class WhitelistChecker:
    """Check IPs against whitelist to avoid enriching known-good addresses."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize with config whitelist."""
        whitelist = config.get('whitelist', {})
        self.ips = set(whitelist.get('ips', []))
        self.fingerprints = set(whitelist.get('fingerprints', []))
        self.user_agents = whitelist.get('user_agents', [])
        
        # Expand CIDR ranges (simplified - just prefix matching)
        self.ip_prefixes = []
        for ip in self.ips:
            if '/' in ip:
                # Extract prefix (e.g., "192.168.1.0/24" -> "192.168.1.")
                base = ip.split('/')[0]
                parts = base.split('.')
                bits = int(ip.split('/')[1])
                prefix_parts = bits // 8
                self.ip_prefixes.append('.'.join(parts[:prefix_parts]) + '.')
    
    def is_whitelisted(
        self, 
        ip: str, 
        fingerprint: str = None,
        user_agent: str = None
    ) -> bool:
        """Check if IP/fingerprint/UA is whitelisted."""
        # Check exact IP match
        if ip in self.ips:
            return True
        
        # Check IP prefix (CIDR approximation)
        for prefix in self.ip_prefixes:
            if ip.startswith(prefix):
                return True
        
        # Check fingerprint
        if fingerprint and fingerprint in self.fingerprints:
            return True
        
        # Check user agent patterns
        if user_agent:
            for pattern in self.user_agents:
                if pattern.lower() in user_agent.lower():
                    return True
        
        return False


# =============================================================================
# MAIN ENRICHMENT LOGIC
# =============================================================================
def run_enrichment(startup: bool = False):
    """
    Main enrichment routine.
    
    Args:
        startup: If True, run full enrichment on container start
    """
    logger.info("=" * 60)
    logger.info("IP ENRICHMENT RUN STARTING")
    logger.info("=" * 60)
    
    # Load config
    config = load_config()
    enrichment_config = config.get('enrichment', {})
    
    # Initialize clients
    try:
        os_client = get_client()
        if not os_client.test_connection():
            logger.error("Cannot connect to OpenSearch, aborting")
            return
    except Exception as e:
        logger.error(f"OpenSearch client error: {e}")
        return
    
    try:
        abuse_client = AbuseIPDBClient()
    except ValueError:
        logger.error("AbuseIPDB not configured, aborting")
        return
    
    notifier = get_notifier()
    whitelist = WhitelistChecker(config)
    
    # Load cache
    cache = load_cache()
    cache_hours = enrichment_config.get('abuseipdb', {}).get('cache_hours', 24)
    
    # Get unenriched IPs
    lookback_hours = 24 if startup else 1
    limit = 100 if startup else 50
    
    unenriched = os_client.get_unenriched_ips(
        index=enrichment_config.get('source_index', 'apache-parsed-v2'),
        hours=lookback_hours,
        limit=limit
    )
    
    if not unenriched:
        logger.info("No unenriched IPs found")
        return
    
    logger.info(f"Found {len(unenriched)} IPs to enrich")
    
    # Process each IP
    enriched_count = 0
    high_threat_count = 0
    skipped_whitelist = 0
    skipped_cached = 0
    
    alert_threshold = config.get('alerts', {}).get('immediate', {}).get('high_threat_score', 95)
    
    for item in unenriched:
        ip = item['ip']
        sample = item.get('sample', {})
        fingerprint = sample.get('visitor_fingerprint')
        user_agent = sample.get('user_agent', '')
        
        # Skip whitelisted
        if whitelist.is_whitelisted(ip, fingerprint, user_agent):
            logger.debug(f"Skipping whitelisted: {ip}")
            skipped_whitelist += 1
            continue
        
        # Check cache
        cached = cache.get('ips', {}).get(ip)
        if cached:
            cached_time = datetime.fromisoformat(cached.get('checked_at', '2000-01-01'))
            if datetime.utcnow() - cached_time < timedelta(hours=cache_hours):
                logger.debug(f"Using cached data for {ip}")
                # Still write cached data to OpenSearch
                os_client.enrich_ip(
                    index=enrichment_config.get('source_index', 'apache-parsed-v2'),
                    ip=ip,
                    enrichment_data=cached
                )
                skipped_cached += 1
                continue
        
        # Query AbuseIPDB
        result = abuse_client.check_ip(ip)
        
        if result is None:
            logger.warning(f"Could not check {ip}, skipping")
            continue
        
        # Cache result
        cache.setdefault('ips', {})[ip] = result
        
        # Write to OpenSearch
        updated = os_client.enrich_ip(
            index=enrichment_config.get('source_index', 'apache-parsed-v2'),
            ip=ip,
            enrichment_data=result
        )
        
        if updated > 0:
            enriched_count += 1
            logger.info(
                f"Enriched {ip}: score={result['score']}, "
                f"reports={result['total_reports']}, "
                f"isp={result.get('isp', 'N/A')}"
            )
        
        # Immediate alert for high threats
        if result['score'] >= alert_threshold:
            high_threat_count += 1
            logger.warning(f"HIGH THREAT: {ip} (score: {result['score']})")
            
            notifier.send_threat_alert(
                ip=ip,
                score=result['score'],
                country=result.get('country_code', 'Unknown'),
                reports=result['total_reports'],
                action="Monitoring",
                details={
                    'path': sample.get('path'),
                    'user_agent': user_agent,
                    'isp': result.get('isp'),
                    'is_tor': result.get('is_tor'),
                    'is_proxy': result.get('is_public_proxy')
                }
            )
    
    # Save cache
    save_cache(cache)
    
    # Summary
    logger.info("-" * 60)
    logger.info("ENRICHMENT COMPLETE")
    logger.info(f"  Enriched: {enriched_count}")
    logger.info(f"  High threats: {high_threat_count}")
    logger.info(f"  Skipped (whitelist): {skipped_whitelist}")
    logger.info(f"  Skipped (cached): {skipped_cached}")
    logger.info(f"  API calls used: {abuse_client.daily_checks}")
    logger.info("=" * 60)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IP Enrichment Script")
    parser.add_argument(
        '--startup', 
        action='store_true',
        help='Run full enrichment (container startup mode)'
    )
    parser.add_argument(
        '--test-ip',
        type=str,
        help='Test enrichment for a specific IP'
    )
    
    args = parser.parse_args()
    
    if args.test_ip:
        # Test mode - check single IP
        try:
            client = AbuseIPDBClient()
            result = client.check_ip(args.test_ip)
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"Error: {e}")
    else:
        run_enrichment(startup=args.startup)
