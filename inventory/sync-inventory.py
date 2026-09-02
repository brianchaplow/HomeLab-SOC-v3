"""Load asset-inventory.json into the soc-asset-inventory index on brisket OpenSearch.

Doc id = host name, so re-running is an idempotent refresh. The Shuffle
score_and_brief action reads this index at runtime.
"""
import json
import ssl
import base64
import urllib.request

ES = "https://10.10.20.30:9200"
INDEX = "soc-asset-inventory"
SRC = r"C:\Projects\homelab-soc-portfolio\inventory\asset-inventory.json"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def load_pass():
    with open(r"C:\Projects\.env", encoding="utf-8") as f:
        for line in f:
            if line.startswith("ELK_PASS="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("ELK_PASS not found")

def req(method, path, body=None, user="admin"):
    auth = base64.b64encode(f"{user}:{PASS}".encode()).decode()
    r = urllib.request.Request(
        ES + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        method=method,
    )
    resp = urllib.request.urlopen(r, context=ctx, timeout=20)
    return json.loads(resp.read().decode())

PASS = load_pass()

with open(SRC, encoding="utf-8") as f:
    inv = json.load(f)

for asset in inv["assets"]:
    out = req("PUT", f"/{INDEX}/_doc/{asset['host']}", asset)
    print(f"{asset['host']}: {out.get('result')}")

count = req("POST", f"/{INDEX}/_search", {"size": 0, "track_total_hits": True})
print(f"index doc count: {count['hits']['total']['value']}")
