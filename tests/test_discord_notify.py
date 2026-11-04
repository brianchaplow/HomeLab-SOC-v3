from unittest import mock

import pytest

from utils import discord_notify

DISCORD_FIELD_VALUE_MAX = 1024  # Discord rejects the whole embed above this


@pytest.fixture
def notifier(monkeypatch):
    post = mock.Mock()
    post.return_value.raise_for_status.return_value = None
    monkeypatch.setattr(discord_notify.requests, "post", post)
    return discord_notify.DiscordNotifier(webhook_url="https://discord.invalid/webhook"), post


def test_unconfigured_notifier_is_a_noop(monkeypatch):
    post = mock.Mock()
    monkeypatch.setattr(discord_notify.requests, "post", post)
    n = discord_notify.DiscordNotifier()
    assert n.send_message("x") is False
    assert n.send_embed("t") is False
    post.assert_not_called()


def test_send_message(notifier):
    n, post = notifier
    assert n.send_message("hello") is True
    assert post.call_args.kwargs["json"] == {"content": "hello"}


def test_http_error_returns_false(notifier):
    n, post = notifier
    post.return_value.raise_for_status.side_effect = Exception("400")
    assert n.send_message("x") is False


def test_threat_alert_fields(notifier):
    n, post = notifier
    assert n.send_threat_alert("203.0.113.7", 97, "NL", 12, details={"path": "/wp-login.php",
                                                                       "user_agent": "curl"})
    embed = post.call_args.kwargs["json"]["embeds"][0]
    assert embed["color"] == 0xE74C3C
    names = [f["name"] for f in embed["fields"]]
    assert "Target Path" in names and "User Agent" in names


def test_threat_alert_with_huge_attacker_controlled_path_stays_within_discord_limits(notifier):
    n, post = notifier
    long_path = "/index.php?" + "A" * 5000
    n.send_threat_alert("203.0.113.7", 99, "NL", 50,
                        details={"path": long_path, "user_agent": "B" * 5000})
    embed = post.call_args.kwargs["json"]["embeds"][0]
    for field in embed["fields"]:
        assert len(field["value"]) <= DISCORD_FIELD_VALUE_MAX, field["name"]


def test_format_dict_sorts_and_limits():
    n = discord_notify.DiscordNotifier(webhook_url=None)
    out = n._format_dict({"a": 1, "b": 3000, "c": 2}, limit=2)
    assert out.splitlines() == ["**b:** 3,000", "**c:** 2"]
    assert n._format_dict({}) == ""


def test_watch_turnover_embeds(notifier):
    n, post = notifier
    stats = {"total_requests": 1234, "unique_ips": 5, "unique_visitors": 4,
             "by_country": {"NL": 3}, "by_status": {"200": 9},
             "threat_breakdown": {"clean": 7, "malicious": 1}}
    assert n.send_watch_turnover("morning", stats, threats=[{"ip": "203.0.113.1", "score": 99, "country": "NL"}],
                                 highlights=["h"] * 20, action_items=["a"] * 9)
    embeds = post.call_args.kwargs["json"]["embeds"]
    assert [e["title"][2:] for e in embeds] == ["MORNING WATCH TURNOVER", "Watch Highlights",
                                                "Active Threats", "Action Items for Next Watch"]
    assert "1,234" in embeds[0]["fields"][0]["value"]
    assert embeds[1]["description"].count("•") == 10
    assert embeds[3]["description"].count("☐") == 5
    assert len(embeds) <= 10  # Discord's per-message embed limit


def test_watch_turnover_minimal_and_weekly_period(notifier):
    n, post = notifier
    assert n.send_watch_turnover("weekly", {})
    embeds = post.call_args.kwargs["json"]["embeds"]
    assert len(embeds) == 1 and "168 hours" in embeds[0]["description"]
