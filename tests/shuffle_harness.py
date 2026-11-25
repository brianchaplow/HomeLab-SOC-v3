"""Run Shuffle execute_python nodes straight out of the exported workflow JSON.

The node code lives inside shuffle/workflows/*.json, so the tests pull it out,
substitute the $variables the way Shuffle does, and execute it with a fake
`self.full_execution` against one local HTTP server that stands in for
OpenSearch, Elastic and brisket's Ollama. `http_body` then builds an http node's
request body the way Shuffle does (raw substitution), because a body that is not
valid JSON is a silent Discord 400 and a missing message.
"""
import contextlib
import io
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / "shuffle" / "workflows"


class MockLab:
    """One HTTP server for every backend a node talks to.

    `ollama_script` holds one entry per /api/generate call:
      ("ok", text)             200 with that response text
      ("hang", seconds)        sleep, then answer (the client has timed out by then)
      ("http", (code, error))  an Ollama error body
    `search` maps a path fragment to the JSON returned for that search call.
    """

    def __init__(self, ollama_script=(), search=None):
        self.script = list(ollama_script)
        self.search = dict(search or {})
        self.requests = []  # parsed /api/generate bodies, in order
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if not self.path.endswith("/api/generate"):
                    return self._send(200, lab.search_reply(self.path, body))
                lab.requests.append(json.loads(body))
                kind, arg = lab.script.pop(0) if lab.script else ("ok", "fallback")
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
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass  # client already timed out

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def search_reply(self, path, body):
        if path.endswith("/_msearch"):
            # One (header, query) pair per candidate: answer "never seen before" for each.
            pairs = len([line for line in body.decode().split("\n") if line.strip()]) // 2
            return {"responses": [{"hits": {"total": {"value": 0}}} for _ in range(pairs)]}
        for fragment, reply in self.search.items():
            if fragment in path:
                return reply
        return {}

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def load_workflow(filename):
    return json.loads((WORKFLOWS / filename).read_text(encoding="utf-8"))


def node_param(wf, label, name):
    action = next(a for a in wf["actions"] if a["label"] == label)
    return next(p["value"] for p in action["parameters"] if p["name"] == name)


def upstream(label, message):
    """An upstream node result as Shuffle stores it."""
    return {"action": {"label": label}, "result": json.dumps({"success": True, "message": message})}


def run_node(filename, label, variables, results=(), execution_argument="", retime=()):
    """Execute one node. Returns (parsed stdout, elapsed seconds).

    `retime` is a list of (regex, replacement) pairs that shrink the production
    timings so the suite stays fast; each must match exactly once, so a renamed or
    retuned constant fails loudly instead of silently running at production speed.
    """
    code = node_param(load_workflow(filename), label, "code")
    for old, new in retime:
        code, n = re.subn(old, new, code, flags=re.M)
        assert n == 1, old
    names = "|".join(sorted(map(re.escape, variables), key=len, reverse=True))
    code = re.sub(r"\$(%s)\b" % names, lambda m: variables[m.group(1)], code)

    class FakeSelf:
        full_execution = {"execution_argument": execution_argument, "results": list(results)}

    out = io.StringIO()
    started = time.monotonic()
    with contextlib.redirect_stdout(out):
        exec(compile(code, label, "exec"), {"self": FakeSelf()})
    return json.loads(out.getvalue()), time.monotonic() - started


def http_body(filename, label, results):
    """The request body an http node sends: $node.message.key spliced in raw, then parsed."""
    template = node_param(load_workflow(filename), label, "body")

    def splice(m):
        value = results[m.group(1)][m.group(2)]
        return value if isinstance(value, str) else json.dumps(value)

    return json.loads(re.sub(r"\$(\w+)\.message\.(\w+)", splice, template))
