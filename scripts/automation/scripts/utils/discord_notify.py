#!/usr/bin/env python3
"""
###############################################################################
# DISCORD NOTIFICATION UTILITY
# Purpose: Send alerts, digests, and reports to Discord
# Author:  Brian S. Chaplow
###############################################################################
"""

import os
import logging
import requests
from typing import Optional, List, Dict, Any
from datetime import datetime

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
# DISCORD NOTIFIER CLASS
# =============================================================================
class DiscordNotifier:
    """
    Send formatted messages to Discord via webhook.
    
    Supports:
      - Simple text messages
      - Rich embeds with fields
      - Watch turnover reports
      - Threat alerts
    """
    
    def __init__(self, webhook_url: Optional[str] = None):
        """Initialize with webhook URL from param or environment."""
        self.webhook_url = webhook_url or os.getenv('DISCORD_WEBHOOK')
        
        if not self.webhook_url:
            logger.warning("No Discord webhook configured")
    
    # -------------------------------------------------------------------------
    # SEND RAW MESSAGE
    # -------------------------------------------------------------------------
    def send_message(self, content: str) -> bool:
        """Send a simple text message."""
        if not self.webhook_url:
            logger.warning("Discord webhook not configured, skipping")
            return False
        
        try:
            response = requests.post(
                self.webhook_url,
                json={"content": content},
                timeout=10
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send Discord message: {e}")
            return False
    
    # -------------------------------------------------------------------------
    # SEND EMBED
    # -------------------------------------------------------------------------
    def send_embed(
        self,
        title: str,
        description: str = "",
        color: int = 0x00FF00,
        fields: Optional[List[Dict[str, Any]]] = None,
        footer: Optional[str] = None,
        thumbnail_url: Optional[str] = None
    ) -> bool:
        """
        Send a rich embed message.
        
        Args:
            title: Embed title
            description: Main text content
            color: Sidebar color (hex integer)
            fields: List of field dicts with name, value, inline
            footer: Footer text
            thumbnail_url: Small image URL
        """
        if not self.webhook_url:
            return False
        
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if fields:
            embed["fields"] = fields
        
        if footer:
            embed["footer"] = {"text": footer}
        
        if thumbnail_url:
            embed["thumbnail"] = {"url": thumbnail_url}
        
        try:
            response = requests.post(
                self.webhook_url,
                json={"embeds": [embed]},
                timeout=10
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send Discord embed: {e}")
            return False
    
    # -------------------------------------------------------------------------
    # WATCH TURNOVER REPORT
    # -------------------------------------------------------------------------
    def send_watch_turnover(
        self,
        watch_type: str,
        stats: Dict[str, Any],
        threats: List[Dict[str, Any]] = None,
        highlights: List[str] = None,
        action_items: List[str] = None
    ) -> bool:
        """
        Send a Navy-style watch turnover report.
        
        Args:
            watch_type: "morning" or "evening"
            stats: Traffic statistics dict
            threats: List of threat events
            highlights: Notable events
            action_items: Tasks for next watch
        """
        if not self.webhook_url:
            return False
        
        # Colors: Morning = sunrise orange, Evening = sunset purple
        colors = {
            "morning": 0xFF9500,  # Orange
            "evening": 0x9B59B6,  # Purple
            "weekly": 0x3498DB   # Blue
        }
        
        titles = {
            "morning": "🌅 MORNING WATCH TURNOVER",
            "evening": "🌙 EVENING WATCH TURNOVER",
            "weekly": "📊 WEEKLY THREAT INTEL REPORT"
        }
        
        subtitles = {
            "morning": "0600 - Oncoming Watch Brief",
            "evening": "1800 - Day Watch Summary",
            "weekly": "7-Day SOC Summary"
        }
        
        # Build the report
        embeds = []
        
        # Main embed with stats
        main_fields = [
            {
                "name": "📈 Traffic Summary",
                "value": f"**Requests:** {stats.get('total_requests', 0):,}\n"
                         f"**Unique IPs:** {stats.get('unique_ips', 0):,}\n"
                         f"**Unique Visitors:** {stats.get('unique_visitors', 0):,}",
                "inline": True
            },
            {
                "name": "🌍 Top Countries",
                "value": self._format_dict(stats.get('by_country', {}), limit=5) or "N/A",
                "inline": True
            },
            {
                "name": "📊 Status Codes",
                "value": self._format_dict(stats.get('by_status', {})) or "N/A",
                "inline": True
            }
        ]
        
        # Threat breakdown
        threat_breakdown = stats.get('threat_breakdown', {})
        if threat_breakdown:
            threat_text = (
                f"🟢 Clean: {threat_breakdown.get('clean', 0)}\n"
                f"🟡 Moderate: {threat_breakdown.get('moderate', 0)}\n"
                f"🟠 Suspicious: {threat_breakdown.get('suspicious', 0)}\n"
                f"🔴 High Risk: {threat_breakdown.get('high_risk', 0)}\n"
                f"⛔ Malicious: {threat_breakdown.get('malicious', 0)}"
            )
            main_fields.append({
                "name": "🛡️ Threat Breakdown",
                "value": threat_text,
                "inline": False
            })
        
        main_embed = {
            "title": titles.get(watch_type, "WATCH TURNOVER"),
            "description": f"**{subtitles.get(watch_type, '')}**\n\n"
                          f"*Reporting period: Last {12 if watch_type != 'weekly' else 168} hours*",
            "color": colors.get(watch_type, 0x95A5A6),
            "fields": main_fields,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": "SOC Automation | Homelab Security Operations"}
        }
        embeds.append(main_embed)
        
        # Highlights embed (if any)
        if highlights:
            highlight_embed = {
                "title": "⭐ Watch Highlights",
                "description": "\n".join([f"• {h}" for h in highlights[:10]]),
                "color": 0x2ECC71
            }
            embeds.append(highlight_embed)
        
        # Threats embed (if any)
        if threats:
            threat_lines = []
            for t in threats[:5]:
                threat_lines.append(
                    f"• **{t.get('ip', 'Unknown')}** (Score: {t.get('score', 'N/A')}) - "
                    f"{t.get('country', 'Unknown')}"
                )
            
            threat_embed = {
                "title": "🚨 Active Threats",
                "description": "\n".join(threat_lines) if threat_lines else "No active threats",
                "color": 0xE74C3C
            }
            embeds.append(threat_embed)
        
        # Action items embed (if any)
        if action_items:
            action_embed = {
                "title": "📋 Action Items for Next Watch",
                "description": "\n".join([f"☐ {item}" for item in action_items[:5]]),
                "color": 0xF39C12
            }
            embeds.append(action_embed)
        
        # Send all embeds
        try:
            response = requests.post(
                self.webhook_url,
                json={"embeds": embeds},
                timeout=15
            )
            response.raise_for_status()
            logger.info(f"Sent {watch_type} watch turnover to Discord")
            return True
        except Exception as e:
            logger.error(f"Failed to send watch turnover: {e}")
            return False
    
    # -------------------------------------------------------------------------
    # THREAT ALERT
    # -------------------------------------------------------------------------
    def send_threat_alert(
        self,
        ip: str,
        score: int,
        country: str,
        reports: int,
        action: str = "Monitoring",
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send an immediate threat alert.
        
        Args:
            ip: Malicious IP address
            score: AbuseIPDB score
            country: Country of origin
            reports: Number of abuse reports
            action: Action taken (Blocked, Monitoring, etc.)
            details: Additional context
        """
        color = 0xE74C3C if score >= 90 else 0xF39C12  # Red or Orange
        
        fields = [
            {"name": "IP Address", "value": f"`{ip}`", "inline": True},
            {"name": "Abuse Score", "value": f"**{score}/100**", "inline": True},
            {"name": "Country", "value": country or "Unknown", "inline": True},
            {"name": "Total Reports", "value": str(reports), "inline": True},
            {"name": "Action Taken", "value": action, "inline": True},
        ]
        
        if details:
            if details.get('path'):
                fields.append({
                    "name": "Target Path",
                    "value": f"`{details['path']}`",
                    "inline": False
                })
            if details.get('user_agent'):
                fields.append({
                    "name": "User Agent",
                    "value": f"`{details['user_agent'][:100]}`",
                    "inline": False
                })
        
        return self.send_embed(
            title="⚠️ HIGH THREAT DETECTED",
            description=f"Malicious IP detected accessing your infrastructure",
            color=color,
            fields=fields,
            footer="SOC Automation | Threat Detection"
        )
    
    # -------------------------------------------------------------------------
    # BLOCK NOTIFICATION
    # -------------------------------------------------------------------------
    def send_block_notification(
        self,
        ip: str,
        score: int,
        reason: str,
        duration: str = "7d"
    ) -> bool:
        """Send notification that an IP was auto-blocked."""
        return self.send_embed(
            title="🚫 IP AUTO-BLOCKED",
            description=f"Confirmed malicious IP has been blocked at Cloudflare",
            color=0x992D22,  # Dark red
            fields=[
                {"name": "IP Address", "value": f"`{ip}`", "inline": True},
                {"name": "Abuse Score", "value": f"**{score}/100**", "inline": True},
                {"name": "Duration", "value": duration, "inline": True},
                {"name": "Reason", "value": reason, "inline": False}
            ],
            footer="SOC Automation | Automated Response"
        )
    
    # -------------------------------------------------------------------------
    # HELPER: FORMAT DICT
    # -------------------------------------------------------------------------
    def _format_dict(
        self, 
        data: Dict[str, int], 
        limit: int = 5
    ) -> str:
        """Format a dict as a Discord-friendly list."""
        if not data:
            return ""
        
        sorted_items = sorted(data.items(), key=lambda x: x[1], reverse=True)[:limit]
        return "\n".join([f"**{k}:** {v:,}" for k, v in sorted_items])


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================
_notifier = None

def get_notifier() -> DiscordNotifier:
    """Get or create singleton Discord notifier."""
    global _notifier
    if _notifier is None:
        _notifier = DiscordNotifier()
    return _notifier


# =============================================================================
# CLI TEST
# =============================================================================
if __name__ == "__main__":
    notifier = get_notifier()
    
    if notifier.webhook_url:
        print("Testing Discord notification...")
        success = notifier.send_message("🧪 SOC Automation test message")
        print(f"Result: {'✅ Success' if success else '❌ Failed'}")
    else:
        print("❌ DISCORD_WEBHOOK not set")
