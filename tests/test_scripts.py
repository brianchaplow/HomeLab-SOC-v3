"""Shell trigger scripts and helper scripts outside the automation package."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import load_module_from_path

ROOT = Path(__file__).resolve().parent.parent
SHELL_SCRIPTS = sorted(ROOT.glob("shuffle/trigger-scripts/*.sh")) + [
    ROOT / "scripts/automation/entrypoint.sh",
    ROOT / "scripts/automation/backup-local.sh",
    ROOT / "adversary-simulation/attack-scripts/run_attack.sh",
]


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_shell_syntax(path):
    # `bash -n` only parses; nothing is executed.
    subprocess.run(["bash", "-n", str(path)], check=True)


@pytest.mark.parametrize("path", sorted(ROOT.glob("shuffle/trigger-scripts/*")), ids=lambda p: p.name)
def test_trigger_scripts_have_no_host_specific_values(path):
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"webhook_[0-9a-f]{8}-[0-9a-f]{4}-", text), "per-install webhook id committed"
    assert not re.search(r"/home/[a-z][a-z0-9_-]*/", text), "hard-coded home directory"
    token = re.search(r"Bearer ([A-Za-z0-9_-]{20,})", text)
    assert not token or token.group(1).startswith("YOUR_"), "literal bearer token"


@pytest.fixture
def honeypot_import():
    return load_module_from_path("honeypot_import", ROOT / "honeypot/scripts/honeypot-import.py")


def test_honeypot_import_runs_ssh_without_a_shell(honeypot_import, monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")

    monkeypatch.setattr(honeypot_import.subprocess, "run", fake_run)
    monkeypatch.setattr(honeypot_import, "BRISKET_OS_PASS", 'pa"ss $(id) `x` \\')
    honeypot_import.brisket_search("/_search/scroll", {"scroll_id": 'a"b'})
    argv, kw = calls[0]
    assert isinstance(argv, list) and argv[0] == "ssh"
    assert kw.get("shell") is not True
    assert "pa" not in " ".join(argv), "credential leaked onto the command line"
    assert 'user = "admin:pa\\"ss $(id) `x` \\\\"' in kw["input"]
    assert 'data-binary = "{\\"scroll_id\\": \\"a\\\\\\"b\\"}"' in kw["input"]


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
def test_honeypot_curl_config_is_accepted_by_curl(honeypot_import, tmp_path):
    """Feed the generated config to a real curl (pointed at a closed local port
    via a file:// URL) to prove curl parses every line."""
    cfg = tmp_path / "c.cfg"
    target = tmp_path / "out.json"
    target.write_text("{}")
    q = honeypot_import._curl_config_quote
    cfg.write_text(f"url = {q(target.as_uri())}\nuser = {q('a:p\"q')}\n")
    out = subprocess.run(["curl", "-s", "-K", str(cfg)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout == "{}"


def test_sync_inventory_puts_every_asset_by_host(monkeypatch, tmp_path):
    import io
    import json as _json

    mod = load_module_from_path("sync_inventory", ROOT / "inventory/sync-inventory.py")
    monkeypatch.setenv("ELK_PASS", "pw")
    sent = []

    def fake_urlopen(request, context=None, timeout=None):
        sent.append(request)
        if request.full_url.endswith("/_search"):
            body = {"hits": {"total": {"value": len(sent) - 1}}}
        else:
            body = {"result": "created"}
        return io.BytesIO(_json.dumps(body).encode())

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    mod.main()
    assets = _json.loads((ROOT / "inventory/asset-inventory.json").read_text(encoding="utf-8"))["assets"]
    puts = [r for r in sent if r.get_method() == "PUT"]
    assert len(puts) == len(assets)
    assert puts[0].full_url == f"{mod.ES}/soc-asset-inventory/_doc/{assets[0]['host']}"
    assert _json.loads(puts[0].data) == assets[0]
    assert puts[0].headers["Authorization"].startswith("Basic ")
