"""WF2 Watch Turnover: run the exported format_digest node against a mock Ollama.

The node's Python lives inside the Shuffle export, so this test pulls it out of
shuffle/workflows/wf2-watch-turnover.json, substitutes the $variables the way
Shuffle does, and executes it with a fake `self.full_execution`. The two Discord
nodes splice the node's output raw into {"content":"..."}; every scenario checks
that both resulting bodies are still valid JSON, because an invalid body is a
silent Discord 400 and a missing turnover message.
"""
import contextlib
import io
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

WF2 = Path(__file__).resolve().parents[1] / "shuffle" / "workflows" / "wf2-watch-turnover.json"

MITRE_AGGS = {
    "aggregations": {
        "techniques": {
            "buckets": [
                {
                    "key": "T1078",
                    "doc_count": 42,
                    "tactic": {"buckets": [{"key": "Defense Evasion"}]},
                    "technique_name": {"buckets": [{"key": "Valid Accounts"}]},
                    "agents": {"buckets": [{"key": "DC01"}, {"key": "WS01"}]},
                }
            ]
        }
    }
}

WAZUH_DATA = {
    "total_alerts": 1234, "critical": 0, "high": 3, "medium": 200, "low": 1031,
    # Quote and backslash in a rule name: real Wazuh/Suricata descriptions can carry both.
    "top_rules": [{"rule": 'ET POLICY "Suspicious" UA C:\\Temp', "count": 10}],
    "top_src_ips": [{"ip": "203.0.113.9", "count": 50}],
    "top_agents": [{"agent": "smokehouse", "count": 900}],
    "top_mitre": [{"technique": "Valid Accounts", "count": 42}],
    "hours_back": 12,
}
THEHIVE_DATA = {"open_cases": [{"id": 7, "title": 'Case "quoted"\ttitle', "severity": 2}], "total_open": 1}


class MockLab:
    """One HTTP server standing in for both OpenSearch and brisket's Ollama."""

    def __init__(self, ollama_script):
        self.script = list(ollama_script)  # one entry per /api/generate call
        self.requests = []
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path.endswith("/_search"):
                    return self._send(200, MITRE_AGGS)
                lab.requests.append(json.loads(body))
                step = lab.script.pop(0) if lab.script else ("ok", "fallback")
                kind, arg = step
                if kind == "hang":
                    time.sleep(arg)
                    return self._send(200, {"response": "too late", "done_reason": "stop"})
                if kind == "http":
                    return self._send(arg[0], {"error": arg[1]})
                return self._send(200, {"response": arg, "done_reason": "stop", "eval_count": 9,
                                        "load_duration": 2_500_000_000, "total_duration": 4_000_000_000})

            def _send(self, code, obj):
                data = json.dumps(obj).encode()
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # client already timed out

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def node_code(label="format_digest"):
    wf = json.loads(WF2.read_text(encoding="utf-8"))
    action = next(a for a in wf["actions"] if a["label"] == label)
    return next(p["value"] for p in action["parameters"] if p["name"] == "code")


def run_format_digest(lab, timeout=1, budget=3.5, ollama_url=None):
    code = node_code()
    # Shrink the production timings so the suite stays fast; fail loudly if they move.
    for old, new in ((r"^LLM_TIMEOUT = 150$", f"LLM_TIMEOUT = {timeout}"),
                     (r"^LLM_BUDGET = 360$", f"LLM_BUDGET = {budget}"),
                     (r"^LLM_MIN_ATTEMPT = 15\b", "LLM_MIN_ATTEMPT = 0.2")):
        code, n = re.subn(old, new, code, flags=re.M)
        assert n == 1, old
    env = {"ollama_url": ollama_url or lab.url, "opensearch_url": lab.url,
           "opensearch_user": "u", "opensearch_pass": "p"}
    code = re.sub(r"\$(ollama_url|opensearch_url|opensearch_user|opensearch_pass)",
                  lambda m: env[m.group(1)], code)

    class FakeSelf:
        full_execution = {"results": [
            {"action": {"label": "query_wazuh"}, "result": json.dumps({"success": True, "message": WAZUH_DATA})},
            {"action": {"label": "query_thehive"}, "result": json.dumps({"success": True, "message": THEHIVE_DATA})},
        ]}

    out = io.StringIO()
    started = time.monotonic()
    with contextlib.redirect_stdout(out):
        exec(compile(code, "format_digest", "exec"), {"self": FakeSelf()})
    elapsed = time.monotonic() - started
    return json.loads(out.getvalue()), elapsed


def discord_body(result, key):
    """What the discord_post / discord_analysis nodes send: raw substitution, then JSON."""
    body = '{"content":"$format_digest.message.%s"}' % key
    return json.loads(body.replace("$format_digest.message." + key, result[key]))


@pytest.fixture
def lab_factory():
    labs = []

    def make(script):
        lab = MockLab(script)
        labs.append(lab)
        return lab

    yield make
    for lab in labs:
        lab.close()


def test_hostile_llm_text_still_yields_valid_discord_json(lab_factory):
    reply = '<think>\nplan\n</think>Valid Accounts (T1078) on "DC01" is\tnormal.\nPath C:\\x\\y\r\x07 done.'
    lab = lab_factory([("ok", reply), ("ok", 'Posture "NORMAL". No action items. Steady state.')])
    result, _ = run_format_digest(lab)

    analysis = discord_body(result, "digest_analysis")["content"]
    data = discord_body(result, "digest_data")["content"]
    assert "__MITRE Assessment__\nValid Accounts (T1078) on 'DC01' is normal. Path C:xy done." in analysis
    assert "Posture 'NORMAL'. No action items. Steady state." in analysis
    assert "<think>" not in analysis and "plan" not in analysis
    assert "ET POLICY 'Suspicious' UA C:Temp (10)" in data
    assert "Case 'quoted' title" in data

    # Both calls disable thinking through the API as well as the prompt prefix.
    assert [r["think"] for r in lab.requests] == [False, False]
    assert all(r["prompt"].startswith("/no_think ") for r in lab.requests)
    assert [d["ok"] for d in result["llm_debug"]] == [True, True]
    assert result["llm_debug"][0]["load_duration_s"] == 2.5


def test_slow_first_attempt_is_retried(lab_factory):
    lab = lab_factory([("hang", 2), ("ok", "MITRE fine."), ("ok", "Turnover fine.")])
    result, _ = run_format_digest(lab, timeout=1, budget=10)

    analysis = discord_body(result, "digest_analysis")["content"]
    assert "MITRE fine." in analysis and "Turnover fine." in analysis
    assert "unavailable" not in analysis
    first = result["llm_debug"][0]
    assert (first["section"], first["attempt"], first["ok"]) == ("mitre", 1, False)
    assert "timed out" in first["error"]


def test_empty_reply_is_retried_then_reported(lab_factory):
    lab = lab_factory([("ok", ""), ("ok", "<think>x</think>"), ("ok", "Turnover fine.")])
    result, _ = run_format_digest(lab)

    analysis = discord_body(result, "digest_analysis")["content"]
    assert "__MITRE Assessment__: LLM unavailable (empty response, done_reason stop)" in analysis
    assert "Turnover fine." in analysis
    assert len(lab.requests) == 3


def test_model_missing_is_not_retried_and_says_why(lab_factory):
    lab = lab_factory([("http", (404, "model 'qwen3:8b' not found")),
                       ("http", (404, "model 'qwen3:8b' not found"))])
    result, _ = run_format_digest(lab)

    analysis = discord_body(result, "digest_analysis")["content"]
    assert "LLM unavailable (HTTP 404 model 'qwen3:8b' not found)" in analysis
    assert len(lab.requests) == 2  # one per section, no retry on a 4xx


def test_server_error_is_retried(lab_factory):
    lab = lab_factory([("http", (500, "model requires more system memory")), ("ok", "MITRE fine."),
                       ("ok", "Turnover fine.")])
    result, _ = run_format_digest(lab)
    assert "unavailable" not in discord_body(result, "digest_analysis")["content"]
    assert result["llm_debug"][0]["error"] == "HTTP 500 model requires more system memory"


def test_hung_ollama_stays_inside_the_budget(lab_factory):
    lab = lab_factory([("hang", 5)] * 6)
    result, elapsed = run_format_digest(lab, timeout=1, budget=2.5)

    analysis = discord_body(result, "digest_analysis")["content"]
    assert "__MITRE Assessment__: LLM unavailable (" in analysis
    assert "__Turnover__: LLM unavailable (" in analysis
    assert "Data section above is complete." in analysis
    assert elapsed < 2.5 + 2  # budget plus the OpenSearch query and slack


def test_unreachable_ollama_reports_connection_error(lab_factory):
    dead = MockLab([])
    dead_url = dead.url
    dead.close()  # nothing listens on this port now
    lab = lab_factory([])  # OpenSearch stays up so the MITRE section still runs
    result, _ = run_format_digest(lab, ollama_url=dead_url)

    analysis = discord_body(result, "digest_analysis")["content"]
    assert "__MITRE Assessment__: LLM unavailable (URLError:" in analysis
    assert "__Turnover__: LLM unavailable (URLError:" in analysis
    assert len(result["llm_debug"]) == 4  # connection errors are retried once per section


# The analysis is "<header 40>\\n__MITRE Assessment__\\n<reply>\\n__Turnover__...", so the
# separator after a reply of length L starts at 64 + L and the 1947-char cut splits it
# at L = 1882. Sweep around that point.
@pytest.mark.parametrize("length", range(1876, 1890))
def test_truncation_never_leaves_a_dangling_escape(lab_factory, length):
    lab = lab_factory([("ok", "A" * length), ("ok", "x" * 50)])
    result, _ = run_format_digest(lab)
    assert result["digest_analysis"].index("A" * 8) == 64
    assert len(result["digest_analysis"]) <= 1950
    content = discord_body(result, "digest_analysis")["content"]  # raises on a bad escape
    assert content.endswith("...")
