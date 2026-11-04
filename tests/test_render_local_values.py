import json
import subprocess

import pytest

from conftest import REPO_ROOT, load_module_from_path

render = load_module_from_path("render_local_values", REPO_ROOT / "tools/render_local_values.py")

MAPPING = {
    "hosts": {"soc-01": "alpha", "admin-ws": "BRAVO"},
    "addresses": {"172.20.2.1": "198.51.100.1", "172.20.2.14": "198.51.100.14"},
    "literals": {"lab.local": "corp.test"},
}


@pytest.fixture
def repl():
    return render.build_replacements(MAPPING)


def test_host_variants(repl):
    text = "ssh soc-01; $soc01_ssh_key; SOC01_HOST; node SOC01[x]; Soc01 key; ADMIN-WS and admin-ws"
    assert render.render_text(text, repl) == (
        "ssh alpha; $alpha_ssh_key; ALPHA_HOST; node ALPHA[x]; Alpha key; BRAVO and BRAVO")


def test_addresses_respect_boundaries(repl):
    text = "gw 172.20.2.1, host 172.20.2.14:9200, cidr 172.20.2.1/24, other 172.20.2.140, 172.20.2.1."
    assert render.render_text(text, repl) == (
        "gw 198.51.100.1, host 198.51.100.14:9200, cidr 198.51.100.1/24, other 172.20.2.140, 198.51.100.1.")


def test_no_partial_word_matches(repl):
    assert render.render_text("soc-012 xsoc-01 lab.locals", repl) == "soc-012 xsoc-01 lab.locals"


def test_empty_mapping_is_identity():
    assert render.render_text("soc-01", {}) == "soc-01"


def test_refuses_output_inside_repo(tmp_path):
    m = tmp_path / "m.json"
    m.write_text(json.dumps(MAPPING))
    with pytest.raises(SystemExit):
        render.main(["--map", str(m), "--out", str(REPO_ROOT / "tmp-render")])


def test_renders_files_and_paths(tmp_path):
    m = tmp_path / "m.json"
    m.write_text(json.dumps({"hosts": {"soc-01": "alpha"}, "addresses": {"172.20.2.14": "198.51.100.14"}}))
    out = tmp_path / "out"
    render.main(["--map", str(m), "--out", str(out), "infrastructure/docker/"])
    files = sorted(p.name for p in out.rglob("*.yml"))
    assert files and all("soc-01" not in f for f in files)
    assert any(f.startswith("alpha-") for f in files)
    text = "".join(p.read_text() for p in out.rglob("*.yml"))
    assert "172.20.2.14" not in text


def test_literals_are_substrings_applied_first(repl):
    literals = {"wf-elk": "wf-real", "172.20.4.x": "198.51.4.x"}
    text = "wf-elk1-trigger.sh targets 172.20.4.x and soc-01"
    assert render.render_text(text, repl, literals=literals) == "wf-real1-trigger.sh targets 198.51.4.x and alpha"


def test_example_mapping_covers_every_host_placeholder_in_tree():
    import re
    example = json.loads((REPO_ROOT / "network.example.json").read_text())
    hosts = set(example["hosts"])
    used = set()
    for rel in subprocess.check_output(["git", "-C", str(REPO_ROOT), "ls-files"]).decode().split():
        try:
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        used |= set(re.findall(r"(?<![A-Za-z0-9])(?:soc|elk|sensor|attack|pve)-0\d|admin-ws", text, re.I))
    assert {u.lower() for u in used} <= hosts
