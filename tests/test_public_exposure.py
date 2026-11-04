"""Guards for a public repository: real internal network values must not come back.

These checks are generic on purpose, so the test file itself never names a real
address or host:

* every internal (RFC 1918 / CGNAT) IPv4 *host* address in the tree must be a documented
  placeholder (a key in network.example.json, i.e. inside 172.20.0.0/16 for the
  lab VLANs or 172.21.0.0/16 for the home segments). Generic RFC 1918 blocks
  (prefix /16 or shorter), loopback and link-local are allowed;
* every placeholder address used in the tree must be listed in
  network.example.json, so tools/render_local_values.py can restore it;
* if you have a local network.local.json (gitignored), none of its real values
  may appear anywhere in the tracked tree. This one only runs where that file
  exists, e.g. on the owner's machine.
"""
import ipaddress
import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER_NETS = [ipaddress.ip_network("172.20.0.0/16"), ipaddress.ip_network("172.21.0.0/16")]
# Address space that maps a real internal network: RFC 1918 + CGNAT (Tailscale).
INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]
# Third-party content shipped verbatim (Elastic prebuilt rules, Suricata stock
# config comments) contains vendor example addresses.
VENDOR_FILES = {"elastic/detection-rules/all-rules.ndjson", "infrastructure/configs/suricata/suricata.yaml"}
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?![\d])")


def tracked_text_files():
    names = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"]).decode().split("\0")
    for rel in filter(None, names):
        try:
            yield rel, (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue


def private_literals():
    for rel, text in tracked_text_files():
        for m in IPV4.finditer(text):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            prefix = int(m.group(2)[1:]) if m.group(2) else 32
            yield rel, ip, prefix


def example_addresses():
    return set(json.loads((ROOT / "network.example.json").read_text())["addresses"])


def test_private_addresses_are_placeholders():
    bad = []
    for rel, ip, prefix in private_literals():
        if not any(ip in net for net in INTERNAL_NETS):
            continue
        if prefix <= 16:          # generic RFC 1918 block, e.g. 10.0.0.0/8
            continue
        if any(ip in net for net in PLACEHOLDER_NETS):
            continue
        if rel in VENDOR_FILES:
            continue
        bad.append(f"{rel}: {ip}/{prefix}")
    assert not bad, "non-placeholder private addresses (see network.example.json):\n" + "\n".join(sorted(set(bad)))


def test_every_placeholder_address_is_documented_for_rendering():
    documented = example_addresses()
    undocumented = sorted({f"{rel}: {ip}" for rel, ip, prefix in private_literals()
                           if prefix > 16 and not rel.startswith("tests/")  # tests use synthetic values
                           and any(ip in n for n in PLACEHOLDER_NETS) and str(ip) not in documented})
    assert not undocumented, "add these to network.example.json:\n" + "\n".join(undocumented)


def test_local_mapping_is_gitignored():
    out = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "network.local.json"])
    assert out.returncode == 0, "network.local.json must be gitignored"


LOCAL = ROOT / "network.local.json"


@pytest.mark.skipif(not LOCAL.exists(), reason="no network.local.json (owner-only check)")
def test_real_values_from_local_mapping_do_not_appear_in_tree():
    mapping = json.loads(LOCAL.read_text(encoding="utf-8"))
    real = set()
    for section in ("hosts", "addresses", "literals"):
        for ph, value in mapping.get(section, {}).items():
            if value and value != ph:
                real.add(value)
    patterns = [re.compile(r"(?<![A-Za-z0-9.])" + re.escape(v) + r"(?![A-Za-z0-9])", re.I) for v in real]
    hits = sorted({rel for rel, text in tracked_text_files() for p in patterns if p.search(text)})
    assert not hits, f"real values from network.local.json found in: {hits}"
