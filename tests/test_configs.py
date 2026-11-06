"""Static validation of the configuration, rule and export files in the repo.

These catch the most common breakage in an infra repo: a hand-edited YAML,
JSON, XML or NDJSON file that no longer parses, or a rule ID collision.
"""
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


def tracked(pattern):
    return sorted(p for p in ROOT.glob(pattern) if ".git" not in p.parts)


class _SuricataLoader(yaml.SafeLoader):
    """suricata.yaml starts with a %YAML 1.1 directive; SafeLoader handles it."""


YAML_FILES = [p for p in tracked("**/*.y*ml") if p.suffix in (".yml", ".yaml")]
JSON_FILES = tracked("**/*.json")
NDJSON_FILES = tracked("**/*.ndjson")


@pytest.mark.parametrize("path", YAML_FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_yaml_parses(path):
    docs = list(yaml.load_all(path.read_text(encoding="utf-8"), Loader=_SuricataLoader))
    assert docs, f"{path} is empty"


@pytest.mark.parametrize("path", JSON_FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_json_parses(path):
    json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", NDJSON_FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_ndjson_every_line_parses(path):
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines
    for n, line in enumerate(lines, 1):
        try:
            json.loads(line)
        except json.JSONDecodeError as e:  # pragma: no cover - failure path
            pytest.fail(f"{path.name}:{n}: {e}")


def _wazuh_xml(path):
    # Wazuh rule/decoder files have several top-level elements; wrap them.
    return ET.fromstring("<root>" + path.read_text(encoding="utf-8") + "</root>")


def test_wazuh_rules_parse_and_ids_are_unique_and_custom_range():
    root = _wazuh_xml(ROOT / "wazuh" / "rules" / "local_rules.xml")
    ids = [int(r.get("id")) for r in root.iter("rule")]
    assert ids, "no rules found"
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate Wazuh rule ids: {sorted(dupes)}"
    # Wazuh reserves 100000-120000 for user-defined rules.
    out_of_range = [i for i in ids if not 100000 <= i <= 120000]
    assert not out_of_range, f"custom rule ids outside 100000-120000: {out_of_range}"
    for rule in root.iter("rule"):
        assert rule.find("description") is not None, f"rule {rule.get('id')} has no description"
        level = int(rule.get("level"))
        assert 0 <= level <= 16


def test_wazuh_decoders_parse():
    root = _wazuh_xml(ROOT / "wazuh" / "decoders" / "local_decoder.xml")
    for dec in root.iter("decoder"):
        assert dec.get("name")


def test_wazuh_ossec_conf_parses():
    _wazuh_xml(ROOT / "wazuh" / "configs" / "ossec.conf")


SID_RE = re.compile(r"\bsid:(\d+);")


def test_suricata_local_rules_have_unique_sids_and_balanced_options():
    sids = []
    for n, line in enumerate((ROOT / "infrastructure/configs/suricata/local.rules").read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        assert re.match(r"^(alert|drop|pass|reject)\s", line), f"line {n}: unknown action"
        assert line.endswith(")"), f"line {n}: rule options not closed"
        assert line.count("(") >= 1 and "msg:" in line, f"line {n}: no msg"
        m = SID_RE.search(line)
        assert m, f"line {n}: no sid"
        sids.append(int(m.group(1)))
    assert sids
    assert len(sids) == len(set(sids)), "duplicate Suricata sids"
    # Local rules should stay in the reserved local range (>= 1,000,000).
    assert all(s >= 1_000_000 for s in sids)


def test_elastic_detection_rules_have_required_fields_and_unique_rule_ids():
    rule_ids = []
    for line in (ROOT / "elastic/detection-rules/all-rules.ndjson").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rule = json.loads(line)
        if "rule_id" not in rule:  # trailing export summary line
            assert "exported_count" in rule or "exported_rules_count" in rule
            continue
        for key in ("name", "type", "severity", "risk_score"):
            assert key in rule, f"{rule.get('rule_id')} missing {key}"
        assert 0 <= rule["risk_score"] <= 100
        rule_ids.append(rule["rule_id"])
    assert len(rule_ids) > 1000
    assert len(rule_ids) == len(set(rule_ids)), "duplicate Elastic rule_id"


@pytest.mark.parametrize(
    "path", tracked("shuffle/workflows/*.json"), ids=lambda p: p.name
)
def test_shuffle_workflow_exports_are_well_formed(path):
    wf = json.loads(path.read_text(encoding="utf-8"))
    assert wf.get("name"), "workflow has no name"
    actions = wf.get("actions", [])
    assert actions, "workflow has no actions"
    ids = [a["id"] for a in actions]
    assert len(ids) == len(set(ids)), "duplicate action ids"
    # Every branch must connect two nodes that exist in the workflow.
    nodes = set(ids) | {t["id"] for t in wf.get("triggers", [])}
    for b in wf.get("branches", []):
        assert b["source_id"] in nodes and b["destination_id"] in nodes, (
            f"branch {b.get('id')} references a missing node"
        )


def test_asset_inventory_schema():
    inv = json.loads((ROOT / "inventory/asset-inventory.json").read_text(encoding="utf-8"))
    scale = ["critical", "high", "medium", "low"]
    hosts = [a["host"] for a in inv["assets"]]
    assert len(hosts) == len(set(hosts)), "host is the OpenSearch doc id; it must be unique"
    for a in inv["assets"]:
        assert set(a) >= {"host", "ip", "criticality", "role"}
        assert a["criticality"] in scale
        assert re.fullmatch(r"[A-Za-z0-9._-]+", a["host"]), f"unsafe doc id {a['host']!r}"


def test_grafana_dashboards_have_panels():
    for path in tracked("infrastructure/grafana/*.json"):
        dash = json.loads(path.read_text(encoding="utf-8"))
        dash = dash.get("dashboard", dash)
        assert dash.get("title")
        assert dash.get("panels"), f"{path.name} has no panels"


def test_prometheus_scrape_configs():
    cfg = yaml.safe_load((ROOT / "infrastructure/prometheus/prometheus.yml").read_text())
    jobs = [j["job_name"] for j in cfg["scrape_configs"]]
    assert len(jobs) == len(set(jobs)), "duplicate Prometheus job_name"
