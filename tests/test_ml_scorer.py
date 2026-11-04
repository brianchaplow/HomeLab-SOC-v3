"""ML scorer feature engineering and batch scoring, without a real model.

The model artifacts aren't in the repo, so MLScorer is built with __new__ and a
fake booster. The fixture alerts are the repo's own sample Suricata alerts.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import ml_scorer

ROOT = Path(__file__).resolve().parent.parent
FEATURES = ["src_port", "dest_port", "dest_is_web", "proto_is_tcp", "vlan", "vlan_20",
            "is_internal_src", "is_internal_dest", "is_inbound", "hour_of_day", "bytes_total"]


class FakeBooster:
    def __init__(self, value=0.95):
        self.value = value
        self.seen = None

    def predict(self, dmatrix):
        self.seen = dmatrix
        return np.full(dmatrix.num_row(), self.value)


def make_scorer(value=0.95, features=FEATURES):
    s = ml_scorer.MLScorer.__new__(ml_scorer.MLScorer)
    s.model = FakeBooster(value)
    s.label_encoders = {}
    s.feature_names = list(features)
    s.feature_config = {}
    s.threshold = 0.75
    return s


@pytest.fixture
def sample_alerts():
    data = json.loads((ROOT / "wazuh/detection-examples/sample-alerts.json").read_text())
    return data["alerts"]


def full_alert(**over):
    a = {
        "@timestamp": "2026-01-09T14:30:45Z", "src_ip": "203.0.113.9", "src_port": 51515,
        "dest_ip": "10.10.40.10", "dest_port": 443, "proto": "TCP", "direction": "to_server",
        "vlan": 20, "flow": {"bytes_toserver": 600, "bytes_toclient": 400,
                             "pkts_toserver": 5, "pkts_toclient": 4},
    }
    a.update(over)
    return a


def test_engineer_features_basic_values():
    f = make_scorer().engineer_features(pd.DataFrame([full_alert()])).iloc[0]
    assert list(f.index) == FEATURES
    assert f["dest_port"] == 443 and f["dest_is_web"] == 1
    assert f["proto_is_tcp"] == 1
    assert f["is_internal_src"] == 0 and f["is_internal_dest"] == 1 and f["is_inbound"] == 1
    assert f["hour_of_day"] == 14
    assert f["bytes_total"] == 1000
    assert f["vlan"] == 20 and f["vlan_20"] == 1


def test_unknown_feature_names_are_zero_filled():
    s = make_scorer(features=FEATURES + ["feature_from_newer_model"])
    f = s.engineer_features(pd.DataFrame([full_alert()]))
    assert (f["feature_from_newer_model"] == 0).all()


def test_suricata_vlan_list_is_unwrapped():
    # Suricata EVE JSON emits vlan as a list, e.g. "vlan": [20].
    f = make_scorer().engineer_features(pd.DataFrame([full_alert(vlan=[20])])).iloc[0]
    assert f["vlan"] == 20
    assert f["vlan_20"] == 1


@pytest.mark.parametrize("missing", ["direction", "proto", "src_ip", "dest_ip", "@timestamp", "vlan", "flow"])
def test_missing_optional_fields_do_not_break_feature_engineering(missing):
    alert = full_alert()
    del alert[missing]
    f = make_scorer().engineer_features(pd.DataFrame([alert]))
    assert len(f) == 1
    assert not f.isna().any().any()


def test_repo_sample_alerts_are_scored(sample_alerts):
    scorer = make_scorer(0.95)
    scored = scorer.score_alerts(sample_alerts)
    assert len(scored) == len(sample_alerts)
    assert all(a["ml_score"] == pytest.approx(0.95) for a in scored)
    assert all(a["ml_label"] == "attack" for a in scored)


def test_threshold_boundary():
    scored = make_scorer(0.75).score_alerts([full_alert()])
    assert scored[0]["ml_prediction"] == 1
    scored = make_scorer(0.7499).score_alerts([full_alert()])
    assert scored[0]["ml_label"] == "benign"


def test_scoring_failure_does_not_label_alerts_benign():
    """If the model blows up, alerts must not be written back as score 0 / benign
    (run_scoring would then persist ml_score=0 and never re-score them)."""
    scorer = make_scorer()

    class Boom:
        def predict(self, _):
            raise RuntimeError("model exploded")

    scorer.model = Boom()
    assert scorer.score_alerts([full_alert()]) == []


def test_empty_batch():
    assert make_scorer().score_alerts([]) == []
