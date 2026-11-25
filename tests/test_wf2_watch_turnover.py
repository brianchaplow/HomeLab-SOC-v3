"""WF2 Watch Turnover: run the exported nodes against a mock lab.

format_digest builds the two text posts (no LLM since the 2026-10-15 rewrite);
score_and_brief ranks alert clusters and asks qwen3 for one brief per cluster.
Every scenario rebuilds the Discord request bodies the way Shuffle does and
parses them, because an invalid body is a silent Discord 400.
"""
import json

import pytest

from shuffle_harness import MockLab, http_body, run_node, upstream

WF2 = "wf2-watch-turnover.json"

# ---------------------------------------------------------------- fixtures

WAZUH_DATA = {
    "total_alerts": 1234, "critical": 0, "high": 3, "medium": 200, "low": 1031,
    # Quote and backslash in a rule name: real Wazuh/Suricata descriptions can carry both.
    "top_rules": [{"rule": 'ET POLICY "Suspicious" UA C:\\Temp', "count": 10}],
    "top_src_ips": [{"ip": "203.0.113.9", "count": 50}],
    "top_agents": [{"agent": "smokehouse", "count": 900}],
    "top_mitre": [{"technique": "Valid Accounts", "count": 42}],
    "hours_back": 12,
}
THEHIVE_DATA = {"open_cases": [{"id": 7, "title": 'Case "quoted"\ttitle\nsecond line', "severity": 2}],
                "total_open": 1}


def wazuh_aggs(mitre_agents=("DC01", "WS01")):
    """One reply for both Wazuh searches: format_digest's technique detail and
    score_and_brief's rule x agent clusters."""
    return {"aggregations": {
        "techniques": {"buckets": [{
            "key": "T1078", "doc_count": 42,
            "tactic": {"buckets": [{"key": "Defense Evasion"}]},
            "technique_name": {"buckets": [{"key": "Valid Accounts"}]},
            "agents": {"buckets": [{"key": a} for a in mitre_agents]},
        }]},
        "clusters": {"buckets": [
            {   # ranks first: level 10 on a critical asset, briefed by the LLM
                "key": {"rule_id": "5710", "agent": "DC01"}, "doc_count": 40, "max_level": {"value": 10},
                "sample": {"hits": {"hits": [{"_source": {
                    "rule": {"description": 'sshd: "invalid" user from C:\\Temp', "level": 10,
                             "groups": ["authentication_failed"], "mitre": {"id": ["T1110"]}},
                    "data": {"srcip": "203.0.113.9"}}}]}},
            },
            {   # ranks last: a firewall block gets a fixed brief and no LLM call
                "key": {"rule_id": "87701", "agent": "opnsense"}, "doc_count": 900, "max_level": {"value": 5},
                "sample": {"hits": {"hits": [{"_source": {
                    "rule": {"description": "pf: blocked inbound", "level": 5, "groups": ["firewall"]},
                    "data": {"srcip": "198.51.100.7", "action": "block", "dstip": "10.10.40.5",
                             "dstport": "445", "protocol": "tcp"}}}]}},
            },
        ]},
        "by_agent": {"buckets": [{"key": "DC01", "distinct_rules": {"value": 3}},
                                 {"key": "opnsense", "distinct_rules": {"value": 1}}]},
    }}


ELASTIC_AGGS = {"aggregations": {
    "clusters": {"buckets": [{   # ranks second, briefed by the LLM
        "key": {"rule": "11111111-2222-3333-4444-555555555555", "host": "WS01"}, "doc_count": 2,
        "sample": {"hits": {"hits": [{"_source": {
            "kibana.alert.rule.name": 'Suspicious "PowerShell" download', "kibana.alert.rule.type": "query",
            "kibana.alert.severity": "high", "kibana.alert.rule.tags": [],
            "kibana.alert.reason": "process event on WS01",
            "process": {"command_line": 'powershell -enc "abc" C:\\x', "parent": {"name": "explorer.exe"}},
            "user": {"name": "labuser"}}}]}},
    }]},
    "by_host": {"buckets": [{"key": "WS01", "distinct_rules": {"value": 1}}]},
}}

INVENTORY = {"hits": {"hits": [
    {"_source": {"host": "DC01", "criticality": "critical", "role": "AD domain controller"}},
    {"_source": {"host": "WS01", "criticality": "medium", "role": "AD workstation"}},
    {"_source": {"host": "opnsense", "criticality": "high", "role": "edge firewall, syslog collector"}},
]}}


def search_replies(**kw):
    # Order matters: the first fragment found in the request path wins.
    return {"soc-asset-inventory": INVENTORY, "/_count": {"count": 3},
            ".alerts-security": ELASTIC_AGGS, "wazuh-alerts": wazuh_aggs(**kw)}


@pytest.fixture
def lab_factory():
    labs = []

    def make(script=(), **kw):
        lab = MockLab(script, search_replies(**kw))
        labs.append(lab)
        return lab

    yield make
    for lab in labs:
        lab.close()


def variables(lab, ollama_url=None):
    return {"ollama_url": ollama_url or lab.url, "opensearch_url": lab.url, "elastic_url": lab.url,
            "kibana_url": "https://kibana.test", "opensearch_user": "u", "opensearch_pass": "p",
            "elastic_user": "u", "elastic_pass": "p"}


def run_format_digest(lab, wazuh_data=WAZUH_DATA):
    result, _ = run_node(WF2, "format_digest", variables(lab),
                         [upstream("query_wazuh", wazuh_data), upstream("query_thehive", THEHIVE_DATA)])
    return result


def run_score_and_brief(lab, timeout=1, budget=3.5, ollama_url=None):
    return run_node(WF2, "score_and_brief", variables(lab, ollama_url), retime=[
        (r"^    LLM_TIMEOUT = 90$", f"    LLM_TIMEOUT = {timeout}"),
        (r"^    LLM_BUDGET = 300$", f"    LLM_BUDGET = {budget}"),
        (r"^    LLM_MIN_ATTEMPT = 15$", "    LLM_MIN_ATTEMPT = 0.2"),
    ])


def brief(text):
    """What qwen3 returns under the node's JSON schema."""
    return json.dumps({"brief": text})


def briefs_body(result):
    return http_body(WF2, "discord_briefs", {"score_and_brief": result})


def descriptions(result):
    return [e["description"] for e in briefs_body(result)["embeds"]]


FALLBACK_TAIL = " - use score factors and verify link."

# ---------------------------------------------------------------- format_digest


def test_hostile_names_still_yield_valid_discord_json(lab_factory):
    lab = lab_factory(mitre_agents=('DC"01', "WS\\01"))
    result = run_format_digest(lab)

    data = http_body(WF2, "discord_post", {"format_digest": result})["content"]
    analysis = http_body(WF2, "discord_analysis", {"format_digest": result})["content"]
    assert "ET POLICY 'Suspicious' UA C:Temp (10)" in data
    assert "#7 [Med] Case 'quoted' title second line" in data
    assert "T1078: 42 alerts on DC'01,WS01" in analysis


def test_format_digest_reports_evidence_without_an_llm_call(lab_factory):
    lab = lab_factory()
    result = run_format_digest(lab)

    analysis = http_body(WF2, "discord_analysis", {"format_digest": result})["content"]
    assert analysis.startswith("**WATCH OFFICER EVIDENCE -- ")
    assert "__Observed volume__: 1,234 alerts, 1 returned open cases." in analysis
    assert lab.requests == []


# The data post is "<header lines>\\n  <rule> (10)\\n...". Find where the rule name
# starts, then size the name so the 1947-char cut lands on, or next to, the backslash
# of the separator that follows the rule line.
@pytest.mark.parametrize("offset", range(-3, 4))
def test_truncation_never_leaves_a_dangling_escape(lab_factory, offset):
    lab = lab_factory()
    probe = run_format_digest(lab, dict(WAZUH_DATA, top_rules=[{"rule": "RULEMARK", "count": 10}]))
    start = probe["digest_data"].index("RULEMARK")
    length = 1946 - len(" (10)") - start + offset  # offset 0 puts the backslash at index 1946

    result = run_format_digest(lab, dict(WAZUH_DATA, top_rules=[{"rule": "A" * length, "count": 10}]))
    content = http_body(WF2, "discord_post", {"format_digest": result})["content"]  # raises on a bad escape
    assert content.endswith("...")
    assert len(result["digest_data"]) <= 1950
    if offset == 0:
        assert len(result["digest_data"]) == 1949  # the lone backslash was dropped


def test_oversized_evidence_block_is_clipped_and_valid(lab_factory):
    lab = lab_factory(mitre_agents=("A" * 3000,))
    result = run_format_digest(lab)
    assert len(result["digest_analysis"]) <= 1950
    assert http_body(WF2, "discord_analysis", {"format_digest": result})["content"].endswith("...")


# ---------------------------------------------------------------- score_and_brief


def test_briefs_survive_hostile_text_and_disable_thinking(lab_factory):
    lab = lab_factory([("ok", brief('<think>plan</think>Logons "failed" on DC01\nfrom C:\\Temp\\x.')),
                       ("ok", brief("Elastic rule fired on WS01."))])
    result, _ = run_score_and_brief(lab)

    body = briefs_body(result)
    assert [e["title"].split("] ", 1)[1] for e in body["embeds"]] == [
        'sshd: "invalid" user from C:\\Temp', 'Suspicious "PowerShell" download', "pf: blocked inbound"]
    assert descriptions(result)[:2] == ["Logons 'failed' on DC01 from C:Tempx.", "Elastic rule fired on WS01."]
    assert descriptions(result)[2].startswith("Blocked firewall traffic observed by collector opnsense")

    # Two LLM calls, not three: the firewall block never reaches the model.
    assert len(lab.requests) == 2
    assert [r["think"] for r in lab.requests] == [False, False]
    assert all(r["model"] == "qwen3:8b" and r["format"]["required"] == ["brief"] for r in lab.requests)
    debug = result["llm_debug"]
    assert [(d["brief"], d["attempt"], d["ok"]) for d in debug] == [(1, 1, True), (2, 1, True)]
    assert debug[0]["load_duration_s"] == 2.5 and debug[0]["done_reason"] == "stop"


def test_slow_first_attempt_is_retried(lab_factory):
    lab = lab_factory([("hang", 2), ("ok", brief("First.")), ("ok", brief("Second."))])
    result, _ = run_score_and_brief(lab, timeout=1, budget=10)

    assert descriptions(result)[:2] == ["First.", "Second."]
    first = result["llm_debug"][0]
    assert (first["brief"], first["attempt"], first["ok"]) == (1, 1, False)
    assert "timed out" in first["error"]


def test_empty_reply_is_retried_then_reported(lab_factory):
    lab = lab_factory([("ok", ""), ("ok", "<think>x</think>"), ("ok", brief("Second."))])
    result, _ = run_score_and_brief(lab)

    assert descriptions(result)[:2] == [
        "LLM brief unavailable (empty brief, done_reason stop)" + FALLBACK_TAIL, "Second."]
    assert len(lab.requests) == 3


def test_reply_that_is_not_json_is_retried(lab_factory):
    lab = lab_factory([("ok", "Sure, here is the brief"), ("ok", brief("First.")), ("ok", brief("Second."))])
    result, _ = run_score_and_brief(lab)

    assert descriptions(result)[:2] == ["First.", "Second."]
    assert result["llm_debug"][0]["error"].startswith("JSONDecodeError:")


def test_model_missing_is_not_retried_and_says_why(lab_factory):
    lab = lab_factory([("http", (404, "model 'qwen3:8b' not found")),
                       ("http", (404, "model 'qwen3:8b' not found"))])
    result, _ = run_score_and_brief(lab)

    assert descriptions(result)[0] == (
        "LLM brief unavailable (HTTP 404 model 'qwen3:8b' not found)" + FALLBACK_TAIL)
    assert len(lab.requests) == 2  # one per brief, no retry on a 4xx


def test_server_error_is_retried(lab_factory):
    lab = lab_factory([("http", (500, "model requires more system memory")), ("ok", brief("First.")),
                       ("ok", brief("Second."))])
    result, _ = run_score_and_brief(lab)

    assert descriptions(result)[:2] == ["First.", "Second."]
    assert result["llm_debug"][0]["error"] == "HTTP 500 model requires more system memory"


def test_hung_ollama_stays_inside_the_budget(lab_factory):
    lab = lab_factory([("hang", 5)] * 6)
    result, elapsed = run_score_and_brief(lab, timeout=1, budget=2.5)

    got = descriptions(result)
    assert got[0].startswith("LLM brief unavailable (") and got[1].startswith("LLM brief unavailable (")
    assert got[2].startswith("Blocked firewall traffic")  # the rest of the post still goes out
    assert any("budget" in d.get("error", "") for d in result["llm_debug"])
    assert elapsed < 2.5 + 3  # budget plus the search queries and slack


def test_unreachable_ollama_reports_connection_error(lab_factory):
    dead = MockLab()
    dead_url = dead.url
    dead.close()  # nothing listens on this port now
    lab = lab_factory()  # the search backends stay up
    result, _ = run_score_and_brief(lab, ollama_url=dead_url, budget=10)

    assert all(d.startswith("LLM brief unavailable (URLError:") for d in descriptions(result)[:2])
    assert len(result["llm_debug"]) == 4  # connection errors are retried once per brief
