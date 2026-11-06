"""Load asset-inventory.json into the soc-asset-inventory index on brisket OpenSearch.

Doc id = host name, so re-running is an idempotent refresh. The Shuffle
score_and_brief action reads this index at runtime.

Environment overrides (defaults match the original PITBOSS setup):
  SOC_INVENTORY_ES    OpenSearch base URL          (default https://10.10.20.30:9200)
  SOC_INVENTORY_USER  OpenSearch user              (default admin)
  SOC_ENV_FILE        .env file holding ELK_PASS   (default C:\\Projects\\.env)
  ELK_PASS            used directly if set, instead of reading SOC_ENV_FILE
"""
import base64
import json
import os
import ssl
import urllib.parse
import urllib.request
from pathlib import Path

ES = os.environ.get("SOC_INVENTORY_ES", "https://10.10.20.30:9200")
USER = os.environ.get("SOC_INVENTORY_USER", "admin")
INDEX = "soc-asset-inventory"
SRC = Path(__file__).resolve().parent / "asset-inventory.json"
ENV_FILE = os.environ.get("SOC_ENV_FILE", r"C:\Projects\.env")

# brisket's OpenSearch uses a self-signed certificate.
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def load_pass(env_file=ENV_FILE):
    if os.environ.get("ELK_PASS"):
        return os.environ["ELK_PASS"]
    with open(env_file, encoding="utf-8") as f:
        for line in f:
            if line.startswith("ELK_PASS="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("ELK_PASS not found")


def req(method, path, password, body=None, user=USER):
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    r = urllib.request.Request(
        ES + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        method=method,
    )
    resp = urllib.request.urlopen(r, context=ctx, timeout=20)
    return json.loads(resp.read().decode())


def main(src=SRC):
    password = load_pass()

    with open(src, encoding="utf-8") as f:
        inv = json.load(f)

    for asset in inv["assets"]:
        doc_id = urllib.parse.quote(asset["host"], safe="")
        out = req("PUT", f"/{INDEX}/_doc/{doc_id}", password, asset)
        print(f"{asset['host']}: {out.get('result')}")

    count = req("POST", f"/{INDEX}/_search", password, {"size": 0, "track_total_hits": True})
    print(f"index doc count: {count['hits']['total']['value']}")


if __name__ == "__main__":
    main()
