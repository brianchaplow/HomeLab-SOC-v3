#!/usr/bin/env python3
"""
###############################################################################
# OPENSEARCH CLIENT UTILITY
# Purpose: Centralized OpenSearch connection and query helpers
# Author:  Brian S. Chaplow
###############################################################################
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from opensearchpy import OpenSearch, helpers

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
# OPENSEARCH CLIENT CLASS
# =============================================================================
class SOCOpenSearchClient:
    """
    OpenSearch client wrapper for SOC automation tasks.
    
    Handles connection management, common queries, and bulk operations
    for enrichment and reporting.
    """
    
    def __init__(self):
        """Initialize OpenSearch connection from environment variables."""
        self.host = os.getenv('OPENSEARCH_HOST', '<qnap-tailscale-ip>')
        self.port = int(os.getenv('OPENSEARCH_PORT', 9200))
        self.user = os.getenv('OPENSEARCH_USER', 'admin')
        self.password = os.getenv('OPENSEARCH_PASS', '')
        
        self.client = OpenSearch(
            hosts=[{'host': self.host, 'port': self.port}],
            http_auth=(self.user, self.password),
            use_ssl=True,
            verify_certs=False,  # Self-signed cert on homelab
            ssl_show_warn=False,
            timeout=30
        )
        
        logger.info(f"OpenSearch client initialized: {self.host}:{self.port}")
    
    # -------------------------------------------------------------------------
    # CONNECTION TEST
    # -------------------------------------------------------------------------
    def test_connection(self) -> bool:
        """Test OpenSearch connectivity."""
        try:
            info = self.client.info()
            logger.info(f"Connected to OpenSearch {info['version']['number']}")
            return True
        except Exception as e:
            logger.error(f"OpenSearch connection failed: {e}")
            return False
    
    # -------------------------------------------------------------------------
    # QUERY: GET UNENRICHED IPS
    # -------------------------------------------------------------------------
    def get_unenriched_ips(
        self, 
        index: str = "apache-parsed-v2",
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get unique IPs that haven't been enriched yet.
        
        Args:
            index: OpenSearch index to query
            hours: Look back this many hours
            limit: Maximum IPs to return
            
        Returns:
            List of dicts with IP and associated metadata
        """
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                    ],
                    "must_not": [
                        {"exists": {"field": "threat_intel.enriched"}}
                    ]
                }
            },
            "aggs": {
                "unique_ips": {
                    "terms": {
                        "field": "client_ip.keyword",
                        "size": limit
                    },
                    "aggs": {
                        "sample": {
                            "top_hits": {
                                "size": 1,
                                "_source": [
                                    "client_ip", "user_agent", "path", 
                                    "geo.country_name", "geo.city_name",
                                    "visitor_fingerprint", "@timestamp"
                                ]
                            }
                        }
                    }
                }
            }
        }
        
        try:
            response = self.client.search(index=index, body=query)
            
            results = []
            for bucket in response['aggregations']['unique_ips']['buckets']:
                ip = bucket['key']
                sample = bucket['sample']['hits']['hits'][0]['_source']
                results.append({
                    'ip': ip,
                    'count': bucket['doc_count'],
                    'sample': sample
                })
            
            logger.info(f"Found {len(results)} unenriched IPs")
            return results
            
        except Exception as e:
            logger.error(f"Error querying unenriched IPs: {e}")
            return []
    
    # -------------------------------------------------------------------------
    # QUERY: GET HIGH THREAT IPS
    # -------------------------------------------------------------------------
    def get_high_threat_ips(
        self,
        index: str = "apache-parsed-v2",
        threshold: int = 90,
        hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Get IPs with abuse score >= threshold that aren't blocked yet.
        
        Args:
            index: OpenSearch index to query
            threshold: Minimum abuse score
            hours: Look back this many hours
            
        Returns:
            List of high-threat IP records
        """
        query = {
            "size": 100,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                        {"range": {"threat_intel.abuseipdb.score": {"gte": threshold}}}
                    ],
                    "must_not": [
                        {"term": {"threat_intel.blocked": True}}
                    ]
                }
            },
            "_source": [
                "client_ip", "threat_intel", "geo", "user_agent",
                "visitor_fingerprint", "path", "@timestamp"
            ],
            "collapse": {
                "field": "client_ip.keyword"
            },
            "sort": [{"threat_intel.abuseipdb.score": "desc"}]
        }
        
        try:
            response = self.client.search(index=index, body=query)
            results = [hit['_source'] for hit in response['hits']['hits']]
            logger.info(f"Found {len(results)} high-threat IPs (score >= {threshold})")
            return results
            
        except Exception as e:
            logger.error(f"Error querying high-threat IPs: {e}")
            return []
    
    # -------------------------------------------------------------------------
    # QUERY: GET TRAFFIC STATS
    # -------------------------------------------------------------------------
    def get_traffic_stats(
        self,
        index: str = "apache-parsed-v2",
        hours: int = 12
    ) -> Dict[str, Any]:
        """
        Get traffic statistics for watch turnover reports.
        
        Args:
            index: OpenSearch index to query
            hours: Look back this many hours
            
        Returns:
            Dict with traffic statistics
        """
        query = {
            "size": 0,
            "query": {
                "range": {"@timestamp": {"gte": f"now-{hours}h"}}
            },
            "aggs": {
                "total_requests": {"value_count": {"field": "@timestamp"}},
                "unique_ips": {"cardinality": {"field": "client_ip.keyword"}},
                "unique_fingerprints": {"cardinality": {"field": "visitor_fingerprint.keyword"}},
                "by_country": {
                    "terms": {"field": "geo.country_name.keyword", "size": 10}
                },
                "by_status": {
                    "terms": {"field": "status.keyword", "size": 10}
                },
                "by_site": {
                    "terms": {"field": "site.keyword", "size": 5}
                },
                "top_paths": {
                    "terms": {"field": "path.keyword", "size": 10}
                },
                "threat_breakdown": {
                    "range": {
                        "field": "threat_intel.abuseipdb.score",
                        "ranges": [
                            {"key": "clean", "to": 25},
                            {"key": "moderate", "from": 25, "to": 50},
                            {"key": "suspicious", "from": 50, "to": 75},
                            {"key": "high_risk", "from": 75, "to": 90},
                            {"key": "malicious", "from": 90}
                        ]
                    }
                }
            }
        }
        
        try:
            response = self.client.search(index=index, body=query)
            aggs = response['aggregations']
            
            return {
                'total_requests': aggs['total_requests']['value'],
                'unique_ips': aggs['unique_ips']['value'],
                'unique_visitors': aggs['unique_fingerprints']['value'],
                'by_country': {b['key']: b['doc_count'] for b in aggs['by_country']['buckets']},
                'by_status': {b['key']: b['doc_count'] for b in aggs['by_status']['buckets']},
                'by_site': {b['key']: b['doc_count'] for b in aggs['by_site']['buckets']},
                'top_paths': {b['key']: b['doc_count'] for b in aggs['top_paths']['buckets']},
                'threat_breakdown': {b['key']: b['doc_count'] for b in aggs['threat_breakdown']['buckets']}
            }
            
        except Exception as e:
            logger.error(f"Error getting traffic stats: {e}")
            return {}
    
    # -------------------------------------------------------------------------
    # UPDATE: ENRICH IP RECORD
    # -------------------------------------------------------------------------
    def enrich_ip(
        self,
        index: str,
        ip: str,
        enrichment_data: Dict[str, Any]
    ) -> int:
        """
        Update all records for an IP with threat intelligence data.
        
        Args:
            index: OpenSearch index
            ip: IP address to enrich
            enrichment_data: Threat intel data to add
            
        Returns:
            Number of documents updated
        """
        update_query = {
            "script": {
                "source": """
                    if (ctx._source.threat_intel == null) {
                        ctx._source.threat_intel = new HashMap();
                    }
                    ctx._source.threat_intel.abuseipdb = params.abuseipdb;
                    ctx._source.threat_intel.enriched = true;
                    ctx._source.threat_intel.enriched_at = params.enriched_at;
                """,
                "params": {
                    "abuseipdb": enrichment_data,
                    "enriched_at": datetime.utcnow().isoformat()
                }
            },
            "query": {
                "term": {"client_ip.keyword": ip}
            }
        }
        
        try:
            response = self.client.update_by_query(
                index=index,
                body=update_query,
                refresh=True
            )
            updated = response.get('updated', 0)
            logger.debug(f"Enriched {updated} records for IP {ip}")
            return updated
            
        except Exception as e:
            logger.error(f"Error enriching IP {ip}: {e}")
            return 0
    
    # -------------------------------------------------------------------------
    # UPDATE: MARK IP AS BLOCKED
    # -------------------------------------------------------------------------
    def mark_ip_blocked(
        self,
        index: str,
        ip: str,
        block_info: Dict[str, Any]
    ) -> int:
        """
        Mark an IP as blocked in OpenSearch.
        
        Args:
            index: OpenSearch index
            ip: IP address that was blocked
            block_info: Blocking metadata
            
        Returns:
            Number of documents updated
        """
        update_query = {
            "script": {
                "source": """
                    if (ctx._source.threat_intel == null) {
                        ctx._source.threat_intel = new HashMap();
                    }
                    ctx._source.threat_intel.blocked = true;
                    ctx._source.threat_intel.blocked_at = params.blocked_at;
                    ctx._source.threat_intel.block_reason = params.reason;
                """,
                "params": {
                    "blocked_at": datetime.utcnow().isoformat(),
                    "reason": block_info.get('reason', 'Auto-blocked by SOC')
                }
            },
            "query": {
                "term": {"client_ip.keyword": ip}
            }
        }
        
        try:
            response = self.client.update_by_query(
                index=index,
                body=update_query,
                refresh=True
            )
            return response.get('updated', 0)
            
        except Exception as e:
            logger.error(f"Error marking IP {ip} as blocked: {e}")
            return 0


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================
_client = None

def get_client() -> SOCOpenSearchClient:
    """Get or create singleton OpenSearch client."""
    global _client
    if _client is None:
        _client = SOCOpenSearchClient()
    return _client


# =============================================================================
# CLI TEST
# =============================================================================
if __name__ == "__main__":
    client = get_client()
    if client.test_connection():
        print("✅ OpenSearch connection successful")
        
        # Test query
        stats = client.get_traffic_stats(hours=24)
        print(f"\nLast 24h stats:")
        print(f"  Total requests: {stats.get('total_requests', 0)}")
        print(f"  Unique IPs: {stats.get('unique_ips', 0)}")
        print(f"  Unique visitors: {stats.get('unique_visitors', 0)}")
    else:
        print("❌ OpenSearch connection failed")
