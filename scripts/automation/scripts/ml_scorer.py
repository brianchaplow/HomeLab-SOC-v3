#!/usr/bin/env python3
"""
ML Scorer for Suricata Alerts - v2 Production
Scores alerts using XGBoost model trained on ground truth data
"""

import os
import sys
import json
import logging
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd
import xgboost as xgb

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent))

from utils.opensearch_client import get_client
from utils.discord_notify import get_notifier

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration
MODEL_DIR = os.getenv('ML_MODEL_DIR', '/app/models/ground_truth_v2_xgb_20260127_171501')
SCORE_THRESHOLD = 0.75
SCORE_THRESHOLD_HIGH = 0.90
LOOKBACK_MINUTES = 10
BATCH_SIZE = 1000


class MLScorer:
    """Score Suricata alerts using trained XGBoost model."""
    
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = Path(model_dir)
        self.model = None
        self.feature_config = None
        self.label_encoders = None
        self.feature_names = None
        self.threshold = SCORE_THRESHOLD
        self._load_model()
    
    def _load_model(self):
        """Load XGBoost model and feature configuration."""
        model_path = self.model_dir / "model.json"
        fe_path = self.model_dir / "feature_engineer.pkl"
        meta_path = self.model_dir / "metadata.json"
        
        # Load model
        self.model = xgb.Booster()
        self.model.load_model(str(model_path))
        logger.info(f"Loaded model from {model_path}")
        
        # Load feature engineer dict
        with open(fe_path, 'rb') as f:
            fe_dict = pickle.load(f)
        
        self.label_encoders = fe_dict.get('label_encoders', {})
        self.feature_names = fe_dict.get('feature_names', [])
        self.feature_config = fe_dict.get('config', {})
        logger.info(f"Loaded feature config with {len(self.feature_names)} features")
        
        # Load metadata for threshold
        if meta_path.exists():
            with open(meta_path) as f:
                meta = json.load(f)
            self.threshold = meta.get('optimal_threshold', SCORE_THRESHOLD)
        
        logger.info(f"Model threshold: {self.threshold}")
    
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer features matching training pipeline."""
        features = pd.DataFrame(index=df.index)
        
        # Basic network features
        features['src_port'] = pd.to_numeric(df.get('src_port', 0), errors='coerce').fillna(0)
        features['dest_port'] = pd.to_numeric(df.get('dest_port', 0), errors='coerce').fillna(0)
        
        # Flow statistics
        flow = df.get('flow', {})
        if isinstance(flow, pd.Series):
            features['bytes_toserver'] = flow.apply(lambda x: x.get('bytes_toserver', 0) if isinstance(x, dict) else 0)
            features['bytes_toclient'] = flow.apply(lambda x: x.get('bytes_toclient', 0) if isinstance(x, dict) else 0)
            features['pkts_toserver'] = flow.apply(lambda x: x.get('pkts_toserver', 0) if isinstance(x, dict) else 0)
            features['pkts_toclient'] = flow.apply(lambda x: x.get('pkts_toclient', 0) if isinstance(x, dict) else 0)
        else:
            features['bytes_toserver'] = 0
            features['bytes_toclient'] = 0
            features['pkts_toserver'] = 0
            features['pkts_toclient'] = 0
        
        # Derived flow features
        features['bytes_total'] = features['bytes_toserver'] + features['bytes_toclient']
        features['pkts_total'] = features['pkts_toserver'] + features['pkts_toclient']
        features['bytes_ratio'] = features['bytes_toserver'] / (features['bytes_toclient'] + 1)
        features['pkts_ratio'] = features['pkts_toserver'] / (features['pkts_toclient'] + 1)
        features['bytes_bidirectional'] = (features['bytes_toserver'] > 0) & (features['bytes_toclient'] > 0)
        features['avg_pkt_size_toserver'] = features['bytes_toserver'] / (features['pkts_toserver'] + 1)
        features['avg_pkt_size_toclient'] = features['bytes_toclient'] / (features['pkts_toclient'] + 1)
        features['avg_pkt_size_total'] = features['bytes_total'] / (features['pkts_total'] + 1)
        
        # Port-based features
        features['is_privileged_src_port'] = (features['src_port'] < 1024).astype(int)
        features['is_privileged_dest_port'] = (features['dest_port'] < 1024).astype(int)
        features['is_ephemeral_src_port'] = (features['src_port'] >= 49152).astype(int)
        features['is_high_port_dest'] = (features['dest_port'] >= 1024).astype(int)
        
        # Well-known port categories
        features['dest_is_web'] = features['dest_port'].isin([80, 443, 8080, 8443]).astype(int)
        features['dest_is_ssh'] = (features['dest_port'] == 22).astype(int)
        features['dest_is_dns'] = (features['dest_port'] == 53).astype(int)
        features['dest_is_mail'] = features['dest_port'].isin([25, 465, 587, 993, 995]).astype(int)
        features['dest_is_database'] = features['dest_port'].isin([3306, 5432, 1433, 27017, 6379]).astype(int)
        features['dest_is_smb'] = features['dest_port'].isin([445, 139]).astype(int)
        features['dest_is_rdp'] = (features['dest_port'] == 3389).astype(int)
        features['dest_is_proxmox'] = (features['dest_port'] == 8006).astype(int)
        features['dest_is_opensearch'] = features['dest_port'].isin([9200, 5601]).astype(int)
        
        # Uncommon port
        common_ports = [22, 25, 53, 80, 443, 445, 993, 995, 3306, 3389, 5432, 8006, 8080, 8443, 9200]
        features['is_uncommon_dest_port'] = (~features['dest_port'].isin(common_ports)).astype(int)
        
        # Log transforms
        features['bytes_total_log'] = np.log1p(features['bytes_total'])
        features['bytes_toserver_log'] = np.log1p(features['bytes_toserver'])
        features['bytes_toclient_log'] = np.log1p(features['bytes_toclient'])
        features['pkts_total_log'] = np.log1p(features['pkts_total'])
        
        # Flow size categories
        features['is_small_flow'] = (features['bytes_total'] < 500).astype(int)
        features['is_large_flow'] = (features['bytes_total'] > 10000).astype(int)
        
        # Protocol encoding
        proto = df.get('proto', 'TCP').fillna('TCP').str.upper()
        if 'proto' in self.label_encoders:
            try:
                features['proto_encoded'] = self.label_encoders['proto'].transform(proto)
            except ValueError:
                features['proto_encoded'] = 0
        else:
            features['proto_encoded'] = 0
        features['proto_is_tcp'] = (proto == 'TCP').astype(int)
        features['proto_is_udp'] = (proto == 'UDP').astype(int)
        features['proto_is_icmp'] = (proto == 'ICMP').astype(int)
        
        # Direction
        direction = df.get('direction', 'unknown').fillna('unknown').str.lower()
        if 'direction' in self.label_encoders:
            try:
                features['direction_encoded'] = self.label_encoders['direction'].transform(direction)
            except ValueError:
                features['direction_encoded'] = 0
        else:
            features['direction_encoded'] = 0
        
        # VLAN features
        vlan = pd.to_numeric(df.get('vlan', 0), errors='coerce').fillna(0).astype(int)
        features['vlan'] = vlan
        features['vlan_10'] = (vlan == 10).astype(int)
        features['vlan_20'] = (vlan == 20).astype(int)
        features['vlan_30'] = (vlan == 30).astype(int)
        features['vlan_40'] = (vlan == 40).astype(int)
        features['vlan_50'] = (vlan == 50).astype(int)
        
        # IP-based features
        src_ip = df.get('src_ip', '').fillna('')
        dest_ip = df.get('dest_ip', '').fillna('')
        
        features['is_internal_src'] = src_ip.str.startswith('10.10.').astype(int)
        features['is_internal_dest'] = dest_ip.str.startswith('10.10.').astype(int)
        features['is_private_src'] = (src_ip.str.startswith('10.') | src_ip.str.startswith('192.168.') | src_ip.str.startswith('172.')).astype(int)
        features['is_private_dest'] = (dest_ip.str.startswith('10.') | dest_ip.str.startswith('192.168.') | dest_ip.str.startswith('172.')).astype(int)
        features['is_internal_traffic'] = (features['is_internal_src'] & features['is_internal_dest']).astype(int)
        features['is_inbound'] = ((~features['is_internal_src'].astype(bool)) & features['is_internal_dest'].astype(bool)).astype(int)
        features['is_outbound'] = (features['is_internal_src'].astype(bool) & (~features['is_internal_dest'].astype(bool))).astype(int)
        features['is_localhost'] = ((src_ip == '127.0.0.1') | (dest_ip == '127.0.0.1')).astype(int)
        features['is_multicast'] = dest_ip.str.startswith('224.').astype(int)
        
        # Time features
        timestamp = pd.to_datetime(df.get('@timestamp', datetime.now()), errors='coerce')
        features['hour_of_day'] = timestamp.dt.hour.fillna(12)
        features['day_of_week'] = timestamp.dt.dayofweek.fillna(0)
        features['is_weekend'] = (features['day_of_week'] >= 5).astype(int)
        features['is_business_hours'] = ((features['hour_of_day'] >= 9) & (features['hour_of_day'] <= 17)).astype(int)
        features['is_night'] = ((features['hour_of_day'] >= 22) | (features['hour_of_day'] <= 6)).astype(int)
        
        # Ensure all expected features exist
        for feat in self.feature_names:
            if feat not in features.columns:
                features[feat] = 0
        
        # Select only features the model expects
        return features[self.feature_names].astype(float)
    
    def score_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Score a batch of alerts."""
        if not alerts:
            return []
        
        df = pd.DataFrame(alerts)
        
        try:
            features = self.engineer_features(df)
            dmatrix = xgb.DMatrix(features)
            scores = self.model.predict(dmatrix)
        except Exception as e:
            logger.error(f"Scoring failed: {e}")
            scores = np.zeros(len(alerts))
        
        results = []
        for i, (alert, score) in enumerate(zip(alerts, scores)):
            alert['ml_score'] = float(score)
            alert['ml_prediction'] = int(score >= self.threshold)
            alert['ml_label'] = 'attack' if score >= self.threshold else 'benign'
            alert['ml_scored_at'] = datetime.utcnow().isoformat()
            results.append(alert)
        
        return results


def run_scoring():
    """Main scoring routine."""
    logger.info("=" * 60)
    logger.info("ML SCORING RUN STARTING")
    logger.info("=" * 60)
    
    # Initialize
    try:
        scorer = MLScorer()
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return
    
    os_client = get_client()
    if not os_client.test_connection():
        logger.error("Cannot connect to OpenSearch")
        return
    
    notifier = get_notifier()
    
    # Query unscored alerts
    query = {
        "size": BATCH_SIZE,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event_type": "alert"}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}}
                ],
                "must_not": [
                    {"exists": {"field": "ml_score"}}
                ]
            }
        },
        "_source": True
    }
    
    try:
        response = os_client.client.search(index='fluentbit-default', body=query)
        hits = response['hits']['hits']
    except Exception as e:
        logger.error(f"Query failed: {e}")
        return
    
    if not hits:
        logger.info("No unscored alerts found")
        return
    
    logger.info(f"Found {len(hits)} unscored alerts")
    
    # Extract alerts and score
    alerts = [hit['_source'] for hit in hits]
    doc_ids = [hit['_id'] for hit in hits]
    
    scored_alerts = scorer.score_alerts(alerts)
    
    # Stats
    high_threat = sum(1 for a in scored_alerts if a['ml_score'] >= SCORE_THRESHOLD_HIGH)
    medium_threat = sum(1 for a in scored_alerts if SCORE_THRESHOLD <= a['ml_score'] < SCORE_THRESHOLD_HIGH)
    predicted_attacks = sum(1 for a in scored_alerts if a['ml_prediction'] == 1)
    
    logger.info(f"Scored {len(scored_alerts)} alerts:")
    logger.info(f"  High threat (>={SCORE_THRESHOLD_HIGH}): {high_threat}")
    logger.info(f"  Medium threat (>={SCORE_THRESHOLD}): {medium_threat}")
    logger.info(f"  Total predicted attacks: {predicted_attacks}")
    
    # Update OpenSearch
    updated = 0
    for doc_id, alert in zip(doc_ids, scored_alerts):
        try:
            os_client.client.update(
                index='fluentbit-default',
                id=doc_id,
                body={
                    "doc": {
                        "ml_score": alert['ml_score'],
                        "ml_prediction": alert['ml_prediction'],
                        "ml_label": alert['ml_label'],
                        "ml_scored_at": alert['ml_scored_at']
                    }
                }
            )
            updated += 1
        except Exception as e:
            logger.error(f"Update failed for {doc_id}: {e}")
    
    logger.info(f"Updated {updated}/{len(scored_alerts)} documents")
    
    # Alert on high threats
    for alert in scored_alerts:
        if alert['ml_score'] >= SCORE_THRESHOLD_HIGH:
            sig = alert.get('alert', {}).get('signature', 'Unknown')
            src = alert.get('src_ip', 'Unknown')
            dest = alert.get('dest_ip', 'Unknown')
            port = alert.get('dest_port', 'Unknown')
            
            notifier.send_embed(
                title="🤖 ML HIGH THREAT DETECTED",
                description=f"ML model detected high-confidence attack",
                color=0xFF0000,
                fields=[
                    {"name": "Score", "value": f"{alert['ml_score']:.3f}", "inline": True},
                    {"name": "Source", "value": src, "inline": True},
                    {"name": "Target", "value": f"{dest}:{port}", "inline": True},
                    {"name": "Signature", "value": sig[:100], "inline": False}
                ]
            )
    
    logger.info("=" * 60)
    logger.info("ML SCORING COMPLETE")
    logger.info("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', action='store_true', help='Test model loading only')
    args = parser.parse_args()
    
    if args.test:
        logger.info("Testing model loading...")
        scorer = MLScorer()
        logger.info(f"✅ Model loaded successfully")
        logger.info(f"   Threshold: {scorer.threshold}")
        logger.info(f"   Model dir: {scorer.model_dir}")
    else:
        run_scoring()
