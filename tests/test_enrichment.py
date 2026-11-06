from unittest import mock

import pytest

import enrichment


def _resp(status, payload=None, text=""):
    r = mock.Mock(status_code=status, text=text)
    r.json.return_value = payload or {}
    return r


def test_client_requires_key():
    with pytest.raises(ValueError):
        enrichment.AbuseIPDBClient()


def test_check_ip_parses_response(monkeypatch):
    payload = {"data": {"abuseConfidenceScore": 97, "totalReports": 42, "countryCode": "NL",
                        "isp": "Example ISP", "isTor": True}}
    get = mock.Mock(return_value=_resp(200, payload))
    monkeypatch.setattr(enrichment.requests, "get", get)
    client = enrichment.AbuseIPDBClient(api_key="k")
    result = client.check_ip.__wrapped__.__wrapped__(client, "203.0.113.7")
    assert result["score"] == 97
    assert result["total_reports"] == 42
    assert result["is_tor"] is True
    assert result["is_public_proxy"] is False
    assert get.call_args.kwargs["params"]["ipAddress"] == "203.0.113.7"
    assert get.call_args.kwargs["headers"]["Key"] == "k"
    assert client.daily_checks == 1


@pytest.mark.parametrize("status", [429, 500])
def test_check_ip_errors_return_none(monkeypatch, status):
    monkeypatch.setattr(enrichment.requests, "get", mock.Mock(return_value=_resp(status)))
    client = enrichment.AbuseIPDBClient(api_key="k")
    assert client.check_ip.__wrapped__.__wrapped__(client, "203.0.113.7") is None


def test_daily_limit_stops_api_calls(monkeypatch):
    get = mock.Mock()
    monkeypatch.setattr(enrichment.requests, "get", get)
    client = enrichment.AbuseIPDBClient(api_key="k")
    client.daily_checks = client.daily_limit
    assert client.check_ip.__wrapped__.__wrapped__(client, "203.0.113.7") is None
    get.assert_not_called()


def test_cache_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(enrichment, "CACHE_PATH", tmp_path / "data" / "ip_cache.json")
    assert enrichment.load_cache() == {"ips": {}, "last_updated": None}
    enrichment.save_cache({"ips": {"203.0.113.7": {"score": 1}}})
    loaded = enrichment.load_cache()
    assert loaded["ips"]["203.0.113.7"]["score"] == 1
    assert loaded["last_updated"]
