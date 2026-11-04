#!/usr/bin/env python3
"""Render a deployable copy of this repo with your real network values.

The committed tree uses placeholder hostnames (soc-01, elk-01, ...) and
placeholder addresses (172.20.0.0/16 for the lab VLANs, 172.21.0.0/16 for the
home segments). Your real values live in a gitignored ``network.local.json``
(start from ``network.example.json``). This script copies tracked files into an
output directory, substituting placeholders -> real values in file contents
and in file names, so the repo itself never holds them.

    cp network.example.json network.local.json   # then edit
    python tools/render_local_values.py --out ../soc-deploy
    python tools/render_local_values.py --out ../soc-deploy shuffle/ infrastructure/docker/

Mapping file format (all sections optional):
    {
      "hosts":     {"soc-01": "myhost", ...},       # case/identifier variants derived
      "addresses": {"172.20.2.14": "192.0.2.5", ...},
      "literals":  {"lab.local": "corp.example", "172.20.4.x": "192.0.2.x", ...}
    }
Literals are plain substring replacements applied first (subnet prefixes in
prose and LLM prompts, VLAN labels, workflow label prefixes).
For each host, the identifier form without the hyphen (soc01, SOC01, Soc01) and
the upper-case form (SOC-01) are mapped too, so workflow variable names such as
$elk01_ssh_key and env names such as SOC01_HOST come back correctly.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def build_replacements(mapping):
    """Return {placeholder: real} for token-bounded replacement (hosts and
    addresses, including derived host variants). Literals are handled
    separately by render_literals()."""
    out = {}
    for ph, real in mapping.get("hosts", {}).items():
        ident, real_ident = ph.replace("-", ""), re.sub(r"[^A-Za-z0-9]", "", real)
        variants = {
            ph: real, ph.upper(): real.upper(),
            ident: real_ident.lower(), ident.upper(): real_ident.upper(),
            ident.capitalize(): real_ident.capitalize(),
        }
        for k, v in variants.items():
            out.setdefault(k, v)
    out.update(mapping.get("addresses", {}))
    return out


def render_literals(text, literals):
    """Plain substring replacement, longest first (e.g. subnet prefixes such as
    "172.20.4.x", workflow labels such as "wf-elk" inside "wf-elk1")."""
    for ph in sorted(literals, key=len, reverse=True):
        text = text.replace(ph, literals[ph])
    return text


def compile_pattern(replacements):
    """One alternation, longest placeholder first, with token boundaries so that
    172.20.2.1 never matches inside 172.20.2.14 and soc01 never inside soc012."""
    keys = sorted(replacements, key=len, reverse=True)
    if not keys:
        return None
    alt = "|".join(re.escape(k) for k in keys)
    return re.compile(r"(?<![A-Za-z0-9])(?:" + alt + r")(?![A-Za-z0-9]|\.\d)")


def render_text(text, replacements, pattern=None, literals=None):
    if literals:
        text = render_literals(text, literals)
    pattern = pattern or compile_pattern(replacements)
    if pattern is None:
        return text
    return pattern.sub(lambda m: replacements[m.group(0)], text)


def tracked_files(paths):
    cmd = ["git", "-C", str(REPO), "ls-files", "-z", "--", *paths]
    return [p for p in subprocess.check_output(cmd).decode().split("\0") if p]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--map", default=str(REPO / "network.local.json"))
    ap.add_argument("--out", required=True, help="output directory (must not be inside the repo)")
    ap.add_argument("paths", nargs="*", help="limit to these repo paths")
    args = ap.parse_args(argv)

    out = Path(args.out).resolve()
    if out == REPO or REPO in out.parents:
        ap.error("--out must be outside the repository so real values are never committed")
    mapping = json.loads(Path(args.map).read_text(encoding="utf-8"))
    repl = build_replacements(mapping)
    pattern = compile_pattern(repl)
    literals = mapping.get("literals", {})

    count = 0
    for rel in tracked_files(args.paths):
        src = REPO / rel
        dst = out / render_text(rel, repl, pattern, literals)
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            text = src.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            shutil.copy2(src, dst)
        else:
            dst.write_text(render_text(text, repl, pattern, literals), encoding="utf-8")
        count += 1
    print(f"rendered {count} files into {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
