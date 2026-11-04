"""End-to-end autoblock decisions with fake OpenSearch / Cloudflare / Discord."""
from unittest import mock

import pytest

import autoblock


def threat(ip, score=99, reports=20, fp=None):
    return {"client_ip": ip, "visitor_fingerprint": fp,
            "threat_intel": {"abuseipdb": {"score": score, "total_reports": reports,
                                           "country_code": "NL", "isp": "x"}}}


@pytest.fixture
def env(monkeypatch, tmp_path):
    os_client = mock.Mock()
    os_client.test_connection.return_value = True
    notifier = mock.Mock()
    monkeypatch.setattr(autoblock, "get_client", lambda: os_client)
    monkeypatch.setattr(autoblock, "get_notifier", lambda: notifier)
    monkeypatch.setattr(autoblock, "BLOCKED_LOG_PATH", tmp_path / "blocked.json")
    post = mock.Mock()
    post.return_value.json.return_value = {"success": True, "result": {"id": "rule1"}}
    monkeypatch.setattr(autoblock.requests, "post", post)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "t")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "a")

    def run(threats, config, dry_run=False):
        os_client.get_high_threat_ips.return_value = threats
        monkeypatch.setattr(autoblock, "load_config", lambda: config)
        autoblock.run_autoblock(dry_run=dry_run)
        return [c.kwargs["json"]["configuration"]["value"] for c in post.call_args_list]

    return run, os_client, notifier


BASE = {"blocking": {"enabled": True, "threshold": 90, "min_reports": 5,
                     "cloudflare": {"enabled": True, "action": "block"}},
        "whitelist": {"ips": []}}


def cfg(**whitelist):
    c = {k: (dict(v) if isinstance(v, dict) else v) for k, v in BASE.items()}
    c["whitelist"] = {"ips": [], **whitelist}
    return c


def test_blocks_high_threat_ip(env):
    run, os_client, notifier = env
    assert run([threat("203.0.113.66")], cfg()) == ["203.0.113.66"]
    os_client.mark_ip_blocked.assert_called_once()
    notifier.send_block_notification.assert_called_once()


def test_respects_min_reports(env):
    run, *_ = env
    assert run([threat("203.0.113.66", reports=2)], cfg()) == []


def test_disabled_in_config_does_nothing(env):
    run, os_client, _ = env
    c = cfg()
    c["blocking"]["enabled"] = False
    assert run([threat("203.0.113.66")], c) == []
    os_client.get_high_threat_ips.assert_not_called()


def test_dry_run_never_calls_cloudflare(env):
    run, os_client, _ = env
    assert run([threat("203.0.113.66")], cfg(), dry_run=True) == []
    os_client.mark_ip_blocked.assert_not_called()


def test_already_logged_ip_is_not_reblocked(env):
    run, *_ = env
    assert run([threat("203.0.113.66")], cfg()) == ["203.0.113.66"]
    assert run([threat("203.0.113.66")], cfg()) == ["203.0.113.66"]  # no second call


def test_whitelisted_single_host_cidr_is_never_blocked(env):
    run, *_ = env
    assert run([threat("203.0.113.66")], cfg(ips=["203.0.113.66/32"])) == []


def test_cloudflare_disabled_in_config_only_marks_in_opensearch(env):
    run, os_client, _ = env
    c = cfg()
    c["blocking"]["cloudflare"]["enabled"] = False
    assert run([threat("203.0.113.66")], c) == []
    os_client.mark_ip_blocked.assert_called_once()


def test_cloudflare_block_already_exists(monkeypatch):
    post = mock.Mock()
    post.return_value.json.return_value = {"success": False,
                                           "errors": [{"message": "firewallaccessrules.api.duplicate: already exists"}]}
    monkeypatch.setattr(autoblock.requests, "post", post)
    cf = autoblock.CloudflareClient(api_token="t", account_id="a")
    assert cf.block_ip("203.0.113.66") == {"success": True, "already_blocked": True, "ip": "203.0.113.66"}


def test_cloudflare_unconfigured():
    cf = autoblock.CloudflareClient()
    assert cf.block_ip("203.0.113.66")["success"] is False
    assert cf.list_blocked_ips() == []
