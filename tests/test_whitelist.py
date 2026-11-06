"""Whitelist matching shared by enrichment.py (skip lookups) and autoblock.py
(never block). A miss in autoblock means an owner/allow-listed address can be
blocked at Cloudflare; an over-broad match means real attackers are skipped.
"""
import pytest

import autoblock
import enrichment

CHECKERS = [enrichment.WhitelistChecker, autoblock.WhitelistChecker]


def make(cls, ips=(), fingerprints=(), user_agents=()):
    return cls({"whitelist": {"ips": list(ips), "fingerprints": list(fingerprints),
                              "user_agents": list(user_agents)}})


@pytest.mark.parametrize("cls", CHECKERS)
def test_exact_ip_match(cls):
    wl = make(cls, ips=["203.0.113.7"])
    assert wl.is_whitelisted("203.0.113.7")
    assert not wl.is_whitelisted("203.0.113.70")


@pytest.mark.parametrize("cls", CHECKERS)
def test_octet_aligned_cidr(cls):
    wl = make(cls, ips=["198.51.100.0/24"])
    assert wl.is_whitelisted("198.51.100.1")
    assert wl.is_whitelisted("198.51.100.254")
    assert not wl.is_whitelisted("198.51.101.1")


@pytest.mark.parametrize("cls", CHECKERS)
def test_slash_32_cidr_matches_its_host(cls):
    wl = make(cls, ips=["203.0.113.7/32"])
    assert wl.is_whitelisted("203.0.113.7")


@pytest.mark.parametrize("cls", CHECKERS)
def test_non_octet_aligned_cidr_is_not_over_broad(cls):
    # /20 = 198.51.96.0 - 198.51.111.255; must not whitelist all of 198.51.0.0/16
    wl = make(cls, ips=["198.51.96.0/20"])
    assert wl.is_whitelisted("198.51.100.9")
    assert wl.is_whitelisted("198.51.111.255")
    assert not wl.is_whitelisted("198.51.112.1")
    assert not wl.is_whitelisted("198.51.5.5")


@pytest.mark.parametrize("cls", CHECKERS)
def test_ipv6_range(cls):
    wl = make(cls, ips=["2001:db8:abcd::/48"])
    assert wl.is_whitelisted("2001:db8:abcd:12::1")
    assert not wl.is_whitelisted("2001:db8:ffff::1")


@pytest.mark.parametrize("cls", CHECKERS)
def test_placeholder_and_garbage_entries_do_not_crash_or_match(cls):
    # The shipped config.yaml contains placeholders like these.
    wl = make(cls, ips=["YOUR_HOME_IP_RANGE/24", "YOUR_HOME_IPV6_RANGE", "10.0.0.0/abc"])
    assert not wl.is_whitelisted("203.0.113.7")
    assert not wl.is_whitelisted("not-an-ip")


@pytest.mark.parametrize("cls", CHECKERS)
def test_fingerprint(cls):
    wl = make(cls, fingerprints=["fp-1"])
    assert wl.is_whitelisted("203.0.113.7", "fp-1")
    assert not wl.is_whitelisted("203.0.113.7", "fp-2")


def test_user_agent_substring_case_insensitive():
    wl = make(enrichment.WhitelistChecker, user_agents=["Googlebot"])
    assert wl.is_whitelisted("203.0.113.7", None, "Mozilla/5.0 (compatible; googlebot/2.1)")
    assert not wl.is_whitelisted("203.0.113.7", None, "curl/8.0")


def test_shipped_config_loads_into_whitelist():
    cfg = enrichment.load_config()
    assert cfg["blocking"]["enabled"] is False  # safe default for a public repo
    wl = enrichment.WhitelistChecker(cfg)
    assert not wl.is_whitelisted("203.0.113.7")
