import os, sys, json
from elasticsearch import Elasticsearch

ES_URL = os.getenv("ES_URL", "https://40.81.225.56:9200")
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")

def die(msg): print(f"[X] {msg}"); sys.exit(1)

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), verify_certs=False, request_timeout=30)

info = es.info()
print("[OK] Connected:", info.get("name"), info.get("version", {}).get("number"))
idx = "logs-system.auth-*"
count = es.count(index=idx)["count"]
print(f"[OK] Index: {idx} → {count} docs")

q = {
  "size": 0,
  "aggs": {
    "has_user": {"filter": {"exists": {"field": "user.name"}}},
    "has_outcome": {"filter": {"exists": {"field": "event.outcome"}}},
    "has_ip": {"filter": {"exists": {"field": "source.ip"}}}
  }
}
res = es.search(index=idx, body=q)
print("[OK] Field coverage (sample):",
      "user:", res["aggregations"]["has_user"]["doc_count"],
      "outcome:", res["aggregations"]["has_outcome"]["doc_count"],
      "ip:", res["aggregations"]["has_ip"]["doc_count"])
