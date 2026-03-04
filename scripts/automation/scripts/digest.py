#!/usr/bin/env python3
"""
###############################################################################
# WATCH TURNOVER DIGEST SCRIPT
# Purpose: Generate Navy-style watch turnover reports for SOC operations
# 
# Schedule:
#   - Morning (0600): Oncoming watch brief - overnight summary
#   - Evening (1800): Offgoing watch summary - day activity
#   - Weekly (Sunday 0800): Comprehensive threat intel report
# 
# Author:  Brian S. Chaplow
# 
# Philosophy:
#   Watch turnover is critical in Navy operations. The offgoing watch must
#   brief the oncoming watch on all relevant events, anomalies, and action
#   items. This script automates that process for homelab SOC operations.
###############################################################################
"""

import os
import sys
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import pytz

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

def load_config() -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"Could not load config: {e}, using defaults")
        return {}


# =============================================================================
# WATCH TURNOVER GENERATOR
# =============================================================================
class WatchTurnover:
    """
    Generate watch turnover reports for SOC operations.
    
    Formats:
      - Morning: Brief for oncoming watch
      - Evening: Summary from offgoing watch
      - Weekly: Comprehensive threat landscape
    """
    
    def __init__(self):
        """Initialize with OpenSearch and Discord clients."""
        self.os_client = get_client()
        self.notifier = get_notifier()
        self.config = load_config()
        self.tz = pytz.timezone(os.getenv('TZ', 'America/New_York'))
    
    # -------------------------------------------------------------------------
    # MORNING WATCH TURNOVER (0600)
    # -------------------------------------------------------------------------
    def generate_morning_brief(self) -> Dict[str, Any]:
        """
        Generate morning watch turnover brief.
        
        "Good morning. Here's what happened overnight..."
        
        Covers:
          - Overnight traffic summary (1800-0600)
          - Active threats detected
          - IPs blocked overnight
          - Anomalies requiring attention
          - Action items for day watch
        """
        logger.info("Generating MORNING watch turnover...")
        
        # Get stats for overnight period (last 12 hours)
        stats = self.os_client.get_traffic_stats(hours=12)
        
        # Get high-threat activity
        threats = self.os_client.get_high_threat_ips(threshold=75, hours=12)
        
        # Generate highlights
        highlights = self._generate_highlights(stats, "overnight")
        
        # Generate action items
        action_items = self._generate_action_items(stats, threats)
        
        # Format threats for report
        formatted_threats = [
            {
                'ip': t.get('client_ip'),
                'score': t.get('threat_intel', {}).get('abuseipdb', {}).get('score', 0),
                'country': t.get('geo', {}).get('country_name', 'Unknown')
            }
            for t in threats[:5]
        ]
        
        return {
            'watch_type': 'morning',
            'stats': stats,
            'threats': formatted_threats,
            'highlights': highlights,
            'action_items': action_items
        }
    
    # -------------------------------------------------------------------------
    # EVENING WATCH TURNOVER (1800)
    # -------------------------------------------------------------------------
    def generate_evening_summary(self) -> Dict[str, Any]:
        """
        Generate evening watch turnover summary.
        
        "Day watch complete. Here's the summary..."
        
        Covers:
          - Day traffic summary (0600-1800)
          - Notable visitors
          - Threat activity
          - Scanner/bot report
          - Recommendations for night watch
        """
        logger.info("Generating EVENING watch turnover...")
        
        # Get stats for day period (last 12 hours)
        stats = self.os_client.get_traffic_stats(hours=12)
        
        # Get threats
        threats = self.os_client.get_high_threat_ips(threshold=75, hours=12)
        
        # Generate highlights
        highlights = self._generate_highlights(stats, "day")
        
        # Format threats
        formatted_threats = [
            {
                'ip': t.get('client_ip'),
                'score': t.get('threat_intel', {}).get('abuseipdb', {}).get('score', 0),
                'country': t.get('geo', {}).get('country_name', 'Unknown')
            }
            for t in threats[:5]
        ]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(stats, threats)
        
        return {
            'watch_type': 'evening',
            'stats': stats,
            'threats': formatted_threats,
            'highlights': highlights,
            'action_items': recommendations  # Using action_items slot for recommendations
        }
    
    # -------------------------------------------------------------------------
    # WEEKLY REPORT (Sunday 0800)
    # -------------------------------------------------------------------------
    def generate_weekly_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive weekly threat intel report.
        
        Covers:
          - 7-day traffic trends
          - Threat landscape summary
          - Top attackers
          - Geographic distribution
          - Recommendations
        """
        logger.info("Generating WEEKLY threat intel report...")
        
        # Get stats for full week (168 hours)
        stats = self.os_client.get_traffic_stats(hours=168)
        
        # Get all threats from the week
        threats = self.os_client.get_high_threat_ips(threshold=50, hours=168)
        
        # Executive summary highlights
        highlights = [
            f"Total requests: {stats.get('total_requests', 0):,}",
            f"Unique visitors: {stats.get('unique_visitors', 0):,}",
            f"Unique IPs: {stats.get('unique_ips', 0):,}",
        ]
        
        threat_breakdown = stats.get('threat_breakdown', {})
        if threat_breakdown.get('malicious', 0) > 0:
            highlights.append(f"⛔ {threat_breakdown['malicious']} requests from malicious IPs")
        if threat_breakdown.get('high_risk', 0) > 0:
            highlights.append(f"🔴 {threat_breakdown['high_risk']} requests from high-risk IPs")
        
        # Top attackers
        formatted_threats = [
            {
                'ip': t.get('client_ip'),
                'score': t.get('threat_intel', {}).get('abuseipdb', {}).get('score', 0),
                'country': t.get('geo', {}).get('country_name', 'Unknown')
            }
            for t in sorted(
                threats, 
                key=lambda x: x.get('threat_intel', {}).get('abuseipdb', {}).get('score', 0),
                reverse=True
            )[:10]
        ]
        
        # Recommendations
        recommendations = self._generate_weekly_recommendations(stats, threats)
        
        return {
            'watch_type': 'weekly',
            'stats': stats,
            'threats': formatted_threats,
            'highlights': highlights,
            'action_items': recommendations
        }
    
    # -------------------------------------------------------------------------
    # HELPER: GENERATE HIGHLIGHTS
    # -------------------------------------------------------------------------
    def _generate_highlights(
        self, 
        stats: Dict[str, Any], 
        period: str
    ) -> List[str]:
        """Generate notable highlights from stats."""
        highlights = []
        
        total = stats.get('total_requests', 0)
        visitors = stats.get('unique_visitors', 0)
        
        # Traffic volume assessment
        if total > 500:
            highlights.append(f"High traffic period: {total:,} requests")
        elif total < 50:
            highlights.append(f"Light traffic {period}: {total:,} requests")
        
        # Visitor count
        if visitors > 0:
            highlights.append(f"{visitors} unique visitors (by fingerprint)")
        
        # Status code analysis
        status = stats.get('by_status', {})
        if status.get('404', 0) > total * 0.5:
            highlights.append("⚠️ High 404 rate (scanner activity)")
        if status.get('403', 0) > 0:
            highlights.append(f"🚫 {status['403']} blocked requests (403)")
        
        # Threat activity
        threat_breakdown = stats.get('threat_breakdown', {})
        malicious = threat_breakdown.get('malicious', 0)
        if malicious > 0:
            highlights.append(f"⛔ {malicious} requests from known malicious IPs")
        
        # Geographic notes
        countries = stats.get('by_country', {})
        if countries:
            top_country = max(countries, key=countries.get)
            if top_country not in ['United States']:
                highlights.append(f"Top traffic source: {top_country}")
        
        return highlights[:8]  # Limit to 8 highlights
    
    # -------------------------------------------------------------------------
    # HELPER: GENERATE ACTION ITEMS
    # -------------------------------------------------------------------------
    def _generate_action_items(
        self,
        stats: Dict[str, Any],
        threats: List[Dict]
    ) -> List[str]:
        """Generate action items for next watch."""
        items = []
        
        # High-threat IPs to monitor
        unblocked_threats = [
            t for t in threats 
            if t.get('threat_intel', {}).get('abuseipdb', {}).get('score', 0) >= 90
            and not t.get('threat_intel', {}).get('blocked')
        ]
        
        if unblocked_threats:
            items.append(f"Review {len(unblocked_threats)} high-threat IPs for blocking")
        
        # Status code issues
        status = stats.get('by_status', {})
        if status.get('500', 0) > 0:
            items.append("⚠️ Investigate server errors (500 responses)")
        
        # Scanner activity
        threat_breakdown = stats.get('threat_breakdown', {})
        if threat_breakdown.get('malicious', 0) > 10:
            items.append("Consider additional WAF rules for malicious traffic")
        
        # Default item if nothing notable
        if not items:
            items.append("Routine monitoring - no critical items")
        
        return items[:5]
    
    # -------------------------------------------------------------------------
    # HELPER: GENERATE RECOMMENDATIONS
    # -------------------------------------------------------------------------
    def _generate_recommendations(
        self,
        stats: Dict[str, Any],
        threats: List[Dict]
    ) -> List[str]:
        """Generate recommendations for night watch."""
        recs = []
        
        # Based on threat activity
        if len(threats) > 10:
            recs.append("Elevated threat activity - maintain vigilance")
        
        # Based on traffic patterns
        total = stats.get('total_requests', 0)
        if total > 1000:
            recs.append("High traffic day - review logs for anomalies")
        
        # Geographic concerns
        countries = stats.get('by_country', {})
        concern_countries = ['Russia', 'China', 'North Korea']
        for country in concern_countries:
            if countries.get(country, 0) > 50:
                recs.append(f"Elevated traffic from {country} - monitor closely")
        
        # Default
        if not recs:
            recs.append("Standard operations - continue routine monitoring")
        
        return recs[:5]
    
    # -------------------------------------------------------------------------
    # HELPER: WEEKLY RECOMMENDATIONS
    # -------------------------------------------------------------------------
    def _generate_weekly_recommendations(
        self,
        stats: Dict[str, Any],
        threats: List[Dict]
    ) -> List[str]:
        """Generate weekly strategic recommendations."""
        recs = []
        
        # Threat landscape
        threat_breakdown = stats.get('threat_breakdown', {})
        total_threats = (
            threat_breakdown.get('suspicious', 0) +
            threat_breakdown.get('high_risk', 0) +
            threat_breakdown.get('malicious', 0)
        )
        
        if total_threats > 100:
            recs.append("Consider implementing stricter Cloudflare WAF rules")
        
        # Scanner activity
        status = stats.get('by_status', {})
        error_rate = status.get('404', 0) / max(stats.get('total_requests', 1), 1)
        if error_rate > 0.5:
            recs.append("High scanner activity - review honeypot deployment")
        
        # Geographic
        countries = stats.get('by_country', {})
        if len(countries) > 20:
            recs.append("Global reach achieved - maintain geo-blocking rules")
        
        recs.append("Review and update IP reputation cache")
        recs.append("Verify Discord alerting is functioning")
        
        return recs[:5]
    
    # -------------------------------------------------------------------------
    # SEND REPORT
    # -------------------------------------------------------------------------
    def send_report(self, report: Dict[str, Any]) -> bool:
        """Send the generated report to Discord."""
        return self.notifier.send_watch_turnover(
            watch_type=report['watch_type'],
            stats=report['stats'],
            threats=report.get('threats'),
            highlights=report.get('highlights'),
            action_items=report.get('action_items')
        )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================
def run_digest(watch_type: str):
    """
    Run digest generation and send to Discord.
    
    Args:
        watch_type: "morning", "evening", or "weekly"
    """
    logger.info("=" * 60)
    logger.info(f"WATCH TURNOVER: {watch_type.upper()}")
    logger.info("=" * 60)
    
    turnover = WatchTurnover()
    
    # Test OpenSearch connection
    if not turnover.os_client.test_connection():
        logger.error("Cannot connect to OpenSearch, aborting")
        return
    
    # Generate appropriate report
    if watch_type == 'morning':
        report = turnover.generate_morning_brief()
    elif watch_type == 'evening':
        report = turnover.generate_evening_summary()
    elif watch_type == 'weekly':
        report = turnover.generate_weekly_report()
    else:
        logger.error(f"Unknown watch type: {watch_type}")
        return
    
    # Log summary
    stats = report.get('stats', {})
    logger.info(f"Traffic: {stats.get('total_requests', 0):,} requests")
    logger.info(f"Visitors: {stats.get('unique_visitors', 0):,}")
    logger.info(f"Threats: {len(report.get('threats', []))}")
    
    # Send to Discord
    if turnover.send_report(report):
        logger.info("✅ Report sent to Discord")
    else:
        logger.error("❌ Failed to send report to Discord")
    
    logger.info("=" * 60)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Watch Turnover Digest")
    parser.add_argument(
        '--watch',
        type=str,
        choices=['morning', 'evening', 'weekly'],
        required=True,
        help='Type of watch turnover report'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Generate report but do not send to Discord'
    )
    
    args = parser.parse_args()
    
    if args.dry_run:
        logger.info("DRY RUN MODE - will not send to Discord")
        turnover = WatchTurnover()
        
        if args.watch == 'morning':
            report = turnover.generate_morning_brief()
        elif args.watch == 'evening':
            report = turnover.generate_evening_summary()
        else:
            report = turnover.generate_weekly_report()
        
        import json
        print(json.dumps(report, indent=2, default=str))
    else:
        run_digest(args.watch)
