"""SOCOpenSearchClient query construction and response parsing (client mocked)."""
from unittest import mock

import pytest

from utils import opensearch_client as osc


@pytest.fixture
def client(monkeypatch):
    fake = mock.Mock()
    monkeypatch.setattr(osc, "OpenSearch", lambda **kw: fake)
    c = osc.SOCOpenSearchClient()
    return c, fake


def test_env_configuration(monkeypatch):
    seen = {}
    monkeypatch.setattr(osc, "OpenSearch", lambda **kw: seen.update(kw) or mock.Mock())
    monkeypatch.setenv("OPENSEARCH_HOST", "opensearch.test")
    monkeypatch.setenv("OPENSEARCH_PORT", "9201")
    monkeypatch.setenv("OPENSEARCH_USER", "u")
    monkeypatch.setenv("OPENSEARCH_PASS", "p")
    osc.SOCOpenSearchClient()
    assert seen["hosts"] == [{"host": "opensearch.test", "port": 9201}]
    assert seen["http_auth"] == ("u", "p")


def test_connection(client):
    c, fake = client
    fake.info.return_value = {"version": {"number": "2.19.0"}}
    assert c.test_connection() is True
    fake.info.side_effect = Exception("down")
    assert c.test_connection() is False


def test_get_unenriched_ips(client):
    c, fake = client
    fake.search.return_value = {"aggregations": {"unique_ips": {"buckets": [
        {"key": "203.0.113.5", "doc_count": 7,
         "sample": {"hits": {"hits": [{"_source": {"user_agent": "curl"}}]}}}]}}}
    out = c.get_unenriched_ips(index="idx", hours=2, limit=10)
    assert out == [{"ip": "203.0.113.5", "count": 7, "sample": {"user_agent": "curl"}}]
    body = fake.search.call_args.kwargs["body"]
    assert body["aggs"]["unique_ips"]["terms"]["size"] == 10
    assert body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-2h"
    assert body["query"]["bool"]["must_not"] == [{"exists": {"field": "threat_intel.enriched"}}]


def test_get_high_threat_ips(client):
    c, fake = client
    fake.search.return_value = {"hits": {"hits": [{"_source": {"client_ip": "203.0.113.5"}}]}}
    assert c.get_high_threat_ips(threshold=90, hours=24) == [{"client_ip": "203.0.113.5"}]
    body = fake.search.call_args.kwargs["body"]
    assert {"range": {"threat_intel.abuseipdb.score": {"gte": 90}}} in body["query"]["bool"]["filter"]
    assert body["query"]["bool"]["must_not"] == [{"term": {"threat_intel.blocked": True}}]
    assert body["collapse"] == {"field": "client_ip.keyword"}


def test_get_traffic_stats(client):
    c, fake = client
    b = lambda *kv: {"buckets": [{"key": k, "doc_count": v} for k, v in kv]}
    fake.search.return_value = {"aggregations": {
        "total_requests": {"value": 100}, "unique_ips": {"value": 10},
        "unique_fingerprints": {"value": 8}, "by_country": b(("NL", 60)),
        "by_status": b(("200", 90), ("404", 10)), "by_site": b(), "top_paths": b(("/", 50)),
        "threat_breakdown": b(("clean", 80), ("malicious", 2))}}
    s = c.get_traffic_stats(hours=12)
    assert s["total_requests"] == 100 and s["unique_visitors"] == 8
    assert s["by_status"] == {"200": 90, "404": 10}
    assert s["threat_breakdown"] == {"clean": 80, "malicious": 2}


@pytest.mark.parametrize("method,args", [
    ("get_unenriched_ips", {}), ("get_high_threat_ips", {}), ("get_traffic_stats", {}),
])
def test_query_errors_return_empty(client, method, args):
    c, fake = client
    fake.search.side_effect = Exception("boom")
    assert getattr(c, method)(**args) in ([], {})


def test_enrich_and_mark_blocked(client):
    c, fake = client
    fake.update_by_query.return_value = {"updated": 4}
    assert c.enrich_ip("idx", "203.0.113.5", {"score": 1}) == 4
    body = fake.update_by_query.call_args.kwargs["body"]
    assert body["query"] == {"term": {"client_ip.keyword": "203.0.113.5"}}
    assert body["script"]["params"]["abuseipdb"] == {"score": 1}
    assert c.mark_ip_blocked("idx", "203.0.113.5", {"reason": "r"}) == 4
    assert fake.update_by_query.call_args.kwargs["body"]["script"]["params"]["reason"] == "r"
    fake.update_by_query.side_effect = Exception("boom")
    assert c.enrich_ip("idx", "203.0.113.5", {}) == 0
    assert c.mark_ip_blocked("idx", "203.0.113.5", {}) == 0


def test_get_client_is_a_singleton(monkeypatch):
    monkeypatch.setattr(osc, "OpenSearch", lambda **kw: mock.Mock())
    monkeypatch.setattr(osc, "_client", None)
    assert osc.get_client() is osc.get_client()
