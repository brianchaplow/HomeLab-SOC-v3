"""run_enrichment() end to end with fake OpenSearch, AbuseIPDB and Discord."""
from datetime import datetime, timedelta
from unittest import mock

import pytest

import enrichment


@pytest.fixture
def env(monkeypatch, tmp_path):
    os_client = mock.Mock()
    os_client.test_connection.return_value = True
    os_client.enrich_ip.return_value = 3
    notifier = mock.Mock()
    abuse = mock.Mock()
    abuse.daily_checks = 0
    monkeypatch.setattr(enrichment, "get_client", lambda: os_client)
    monkeypatch.setattr(enrichment, "get_notifier", lambda: notifier)
    monkeypatch.setattr(enrichment, "AbuseIPDBClient", lambda: abuse)
    monkeypatch.setattr(enrichment, "CACHE_PATH", tmp_path / "cache.json")

    def run(items, config=None, cache=None):
        if cache is not None:
            monkeypatch.setattr(enrichment, "load_cache", lambda: cache)
        monkeypatch.setattr(enrichment, "load_config", lambda: config or {})
        os_client.get_unenriched_ips.return_value = items
        enrichment.run_enrichment()

    return run, os_client, abuse, notifier


def item(ip, ua="Mozilla/5.0", path="/"):
    return {"ip": ip, "count": 1, "sample": {"user_agent": ua, "path": path}}


def result(score, reports=10):
    return {"score": score, "total_reports": reports, "country_code": "NL", "isp": "x",
            "checked_at": datetime.utcnow().isoformat()}


def test_enriches_and_alerts_on_high_threat(env):
    run, os_client, abuse, notifier = env
    abuse.check_ip.return_value = result(99)
    run([item("203.0.113.5", path="/wp-login.php")])
    os_client.enrich_ip.assert_called_once()
    assert os_client.enrich_ip.call_args.kwargs["enrichment_data"]["score"] == 99
    notifier.send_threat_alert.assert_called_once()
    assert notifier.send_threat_alert.call_args.kwargs["details"]["path"] == "/wp-login.php"


def test_low_score_is_enriched_without_alert(env):
    run, os_client, abuse, notifier = env
    abuse.check_ip.return_value = result(5)
    run([item("203.0.113.5")])
    os_client.enrich_ip.assert_called_once()
    notifier.send_threat_alert.assert_not_called()


def test_lookup_failure_leaves_ip_for_next_run(env):
    run, os_client, abuse, _ = env
    abuse.check_ip.return_value = None
    run([item("203.0.113.5")])
    os_client.enrich_ip.assert_not_called()


def test_fresh_cache_hit_skips_api_but_writes_cached_data(env):
    run, os_client, abuse, _ = env
    cached = result(42)
    run([item("203.0.113.5")], cache={"ips": {"203.0.113.5": cached}})
    abuse.check_ip.assert_not_called()
    assert os_client.enrich_ip.call_args.kwargs["enrichment_data"] == cached


def test_stale_cache_entry_is_rechecked(env):
    run, _, abuse, _ = env
    stale = result(42)
    stale["checked_at"] = (datetime.utcnow() - timedelta(hours=48)).isoformat()
    abuse.check_ip.return_value = result(43)
    run([item("203.0.113.5")], cache={"ips": {"203.0.113.5": stale}})
    abuse.check_ip.assert_called_once_with("203.0.113.5")


def test_whitelisted_ip_is_marked_so_it_stops_occupying_the_queue(env):
    """get_unenriched_ips returns the top-N busiest *unenriched* IPs. A
    whitelisted crawler that is skipped without being marked stays in that
    top-N on every run and can starve real IPs of enrichment."""
    run, os_client, abuse, _ = env
    config = {"whitelist": {"user_agents": ["Googlebot"]}}
    run([item("66.249.66.1", ua="Googlebot/2.1")], config=config)
    abuse.check_ip.assert_not_called()
    os_client.enrich_ip.assert_called_once()
    data = os_client.enrich_ip.call_args.kwargs["enrichment_data"]
    assert data.get("whitelisted") is True
    assert "score" not in data  # must not look like a reputation result


def test_aborts_when_opensearch_unreachable(env):
    run, os_client, abuse, _ = env
    os_client.test_connection.return_value = False
    run([item("203.0.113.5")])
    os_client.get_unenriched_ips.assert_not_called()
