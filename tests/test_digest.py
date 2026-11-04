from unittest import mock

import pytest

import digest


@pytest.fixture
def wt(monkeypatch):
    monkeypatch.setattr(digest, "get_client", mock.Mock())
    monkeypatch.setattr(digest, "get_notifier", mock.Mock())
    return digest.WatchTurnover()


def t(score, blocked=False):
    return {"client_ip": "203.0.113.1", "threat_intel": {"abuseipdb": {"score": score}, "blocked": blocked}}


def test_highlights_light_traffic_and_scanner(wt):
    stats = {"total_requests": 20, "unique_visitors": 3, "by_status": {"404": 15, "403": 2},
             "threat_breakdown": {"malicious": 4}, "by_country": {"Germany": 10, "United States": 5}}
    h = wt._generate_highlights(stats, "overnight")
    assert "Light traffic overnight: 20 requests" in h
    assert any("404" in x for x in h)
    assert any("403" in x for x in h)
    assert any("malicious" in x for x in h)
    assert "Top traffic source: Germany" in h


def test_highlights_empty_stats(wt):
    assert wt._generate_highlights({}, "day") == ["Light traffic day: 0 requests"]


def test_action_items(wt):
    items = wt._generate_action_items({"by_status": {"500": 1}, "threat_breakdown": {"malicious": 11}},
                                      [t(95), t(95, blocked=True), t(80)])
    assert items[0] == "Review 1 high-threat IPs for blocking"
    assert len(items) == 3
    assert wt._generate_action_items({}, []) == ["Routine monitoring - no critical items"]


def test_recommendations(wt):
    recs = wt._generate_recommendations({"total_requests": 2000, "by_country": {"China": 51}}, [t(80)] * 11)
    assert len(recs) == 3
    assert wt._generate_recommendations({}, []) == ["Standard operations - continue routine monitoring"]


def test_weekly_recommendations_handle_zero_traffic(wt):
    recs = wt._generate_weekly_recommendations({"total_requests": 0}, [])
    assert "Verify Discord alerting is functioning" in recs
