import os, datetime, json, ssl, urllib.request, uuid
from typing import Any, Optional, Tuple
from fastapi import FastAPI, Request
from fastapi.responses import Response
from elasticsearch import Elasticsearch
from pydantic import BaseModel, Field
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

try:
    import boto3
    from botocore.client import Config
    _MINIO_AVAILABLE = True
except Exception:
    boto3 = None
    Config = None
    _MINIO_AVAILABLE = False

MINIO_ENDPOINT   = os.getenv("MINIO_ENDPOINT", "http://10.0.0.8:9000")
MINIO_BUCKET     = os.getenv("MINIO_BUCKET",   "citadel-alerts")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")

class Rule(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
class Agent(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
class Source(BaseModel):
    ip: Optional[str] = None
class Host(BaseModel):
    name: Optional[str] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None
class ElasticAlert(BaseModel):
    timestamp: datetime.datetime = Field(alias="@timestamp")
    rule: Rule
    agent: Optional[Agent] = None
    source: Optional[Source] = None
    host: Optional[Host] = None
    message: Optional[str] = None

app = FastAPI(title="Project Citadel SOAR Engine", version="1.2.0",
              description="Receives Elastic webhooks, indexes, and triggers demo playbooks.")

ES_USER = os.getenv("ES_USER") or "elastic"
ES_PASS = os.getenv("ES_PASS") or "changeme"
es_client = Elasticsearch(["https://10.0.0.4:9200"], basic_auth=(ES_USER, ES_PASS), verify_certs=False)

TENANT1_AGENT_URL = os.getenv("TENANT1_AGENT_URL") or "http://10.0.0.10:5000"
TENANT2_AGENT_URL = os.getenv("TENANT2_AGENT_URL") or "http://10.0.0.11:5000"
AGENT_TOKEN       = os.getenv("AGENT_TOKEN")       or "change-me"
PUBLIC_BASE_URL   = os.getenv("PUBLIC_BASE_URL")   or "http://10.0.0.7:30484"

def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def _to_dict_safe(x: Any) -> dict:
    if isinstance(x, dict): return x
    try:
        return json.loads(json.dumps(x, default=str))
    except Exception:
        return {"value": str(x)}

def _post_json(url: str, body: dict, headers: Optional[dict] = None, timeout: int = 5) -> Tuple[int, str]:
    data = json.dumps(body).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if headers: hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        return resp.getcode(), resp.read().decode("utf-8", errors="ignore")

def _choose_agent_url(tenant_id: Optional[str]) -> str:
    if tenant_id and tenant_id.lower() in ("tenant1", "tenant-a", "t1"): return TENANT1_AGENT_URL
    if tenant_id and tenant_id.lower() in ("tenant2", "tenant-b", "t2"): return TENANT2_AGENT_URL
    return TENANT1_AGENT_URL

def _block_ip_via_agent(tenant_id: Optional[str], ip: str) -> dict:
    agent = _choose_agent_url(tenant_id)
    url = f"{agent.rstrip('/')}/act/block-ip"
    try:
        status, text = _post_json(url, {"ip": ip}, headers={"X-Agent-Token": AGENT_TOKEN}, timeout=5)
        return {"agent_call": "ok", "agent_status": status, "agent_response": text[:200]}
    except Exception as e:
        return {"agent_call": "error", "error": str(e)[:200]}

def _minio_put(tenant: str, doc: dict) -> None:
    if not _MINIO_AVAILABLE:
        return
    try:
        s3 = boto3.client(
            "s3",
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
            config=Config(signature_version="s3v4"),
        )
        now = datetime.datetime.utcnow()
        key = f"{tenant}/{now:%Y}/{now:%m}/{now:%d}/{int(now.timestamp()*1000)}_{uuid.uuid4().hex}.json"
        body = json.dumps(doc, default=str, ensure_ascii=False).encode("utf-8")
        s3.put_object(Bucket=MINIO_BUCKET, Key=key, Body=body, ContentType="application/json")
    except Exception:
        pass

@app.get("/")
def health():
    return {
        "status": "online",
        "es": "configured",
        "public_base_url": PUBLIC_BASE_URL,
        "tenants": {
            "tenant1_agent_url": TENANT1_AGENT_URL,
            "tenant2_agent_url": TENANT2_AGENT_URL,
        },
    }

@app.post("/ingest/elastic")
async def ingest_elastic_alert(request: Request):
    raw_bytes = await request.body()
    text = raw_bytes.decode("utf-8", errors="ignore")
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        try:
            es_client.index(index="alerts-elastic-raw", document={"@timestamp": _now_iso(), "raw": text})
        except Exception: pass
        return {"status": "success", "playbook_triggered": False, "note": "no-json"}

    json_str = text[start:end+1].strip()
    try:
        try: data = json.loads(json_str)
        except Exception: data = json.loads(json_str.strip('"'))
    except Exception:
        try:
            es_client.index(index="alerts-elastic-raw", document={"@timestamp": _now_iso(), "raw": text})
        except Exception: pass
        data = {"@timestamp": _now_iso(), "rule": {"id": "unknown", "name": "Unknown"}, "message": "Unparsed payload"}

    ts = data.get("@timestamp") or _now_iso()
    rule = _to_dict_safe(data.get("rule") or {})
    agent = _to_dict_safe(data.get("agent") or {})
    source = _to_dict_safe(data.get("source") or {})
    host = _to_dict_safe(data.get("host") or {})
    tenant_id = (data.get("tenant_id") or data.get("labels", {}).get("tenant_id") or host.get("name") or "tenant1")

    alert_doc = {
        "@timestamp": ts,
        "rule": {"id": rule.get("id") or "unknown", "name": rule.get("name") or "Unknown"},
        "agent": agent,
        "source": {"ip": source.get("ip") or source.get("address") or source.get("client_ip") or "unknown"},
        "host": {
            "ip": host.get("ip") or host.get("ipv4") or host.get("ipv6") or "unknown",
            "name": host.get("name") or "unknown",
            "hostname": host.get("hostname") or host.get("name") or "unknown",
        },
        "message": data.get("message") or "",
        "tenant_id": tenant_id,
        "raw": data,
    }

    try:
        es_client.index(index="alerts-elastic-ingested", document=alert_doc)
    except Exception:
        pass

    try:
        _minio_put(str(tenant_id), alert_doc)
    except Exception:
        pass

    rule_name_l = (alert_doc["rule"]["name"] or "").lower()
    if "brute" in rule_name_l and "force" in rule_name_l:
        target_ip = alert_doc["source"].get("ip") or "unknown"
        result = {}
        if target_ip and target_ip != "unknown":
            result = _block_ip_via_agent(str(tenant_id), target_ip)

        action_doc = {
            "@timestamp": _now_iso(),
            "action": "Block IP",
            "target": target_ip,
            "tenant": tenant_id,
            "reason": f"Playbook triggered by alert: '{alert_doc['rule']['name']}'",
            "status": "completed" if result.get("agent_call") == "ok" else "error",
            "details": result,
        }
        try:
            es_client.index(index="citadel-actions", document=action_doc)
        except Exception:
            pass

        return {"status": "success", "playbook_triggered": True, "action": "Block IP", **result}

    return {"status": "success", "playbook_triggered": False}

@app.get("/api/agents")
def api_agents():
    return [
        {"agent_id": "tenant1", "host": TENANT1_AGENT_URL, "version": "1.0.0", "status": "unknown"},
        {"agent_id": "tenant2", "host": TENANT2_AGENT_URL, "version": "1.0.0", "status": "unknown"},
    ]

@app.get("/api/alerts")
def api_alerts():
    body = {"size": 25, "sort": [{"@timestamp": {"order": "desc"}}]}
    try:
        res = es_client.search(index="alerts-elastic-ingested", body=body)
        return [h.get("_source", {}) for h in res.get("hits", {}).get("hits", [])]
    except Exception:
        return []

@app.get("/api/actions")
def api_actions():
    body = {"size": 25, "sort": [{"@timestamp": {"order": "desc"}}]}
    try:
        res = es_client.search(index="citadel-actions", body=body)
        return [h.get("_source", {}) for h in res.get("hits", {}).get("hits", [])]
    except Exception:
        return []

@app.get("/ui")
def ui():
    html = """<!doctype html><html><head><meta charset="utf-8" />
  <title>SOAR Engine</title>
  <style>body{font-family:system-ui,Arial,sans-serif;margin:24px}h1,h2{margin:12px 0}
  table{border-collapse:collapse;width:100%;margin:8px 0 24px}th,td{border:1px solid #ddd;padding:6px 8px;font-size:14px}
  th{text-align:left;background:#f5f5f5}.pill{display:inline-block;padding:2px 8px;border-radius:10px;background:#eee}</style>
</head><body>
  <h1>Project Citadel — SOAR Engine</h1>
  <h2>Agents</h2><table id="agents"><thead><tr><th>Agent ID</th><th>Last</th><th>Host</th><th>Version</th><th>Status</th></tr></thead><tbody id="agents_tbody"></tbody></table>
  <h2>Recent Alerts</h2><table id="alerts"><thead><tr><th>@timestamp</th><th>rule.name</th><th>source.ip</th><th>host.name</th><th>host.ip</th><th>message</th></tr></thead><tbody id="alerts_tbody"></tbody></table>
  <h2>Recent Actions</h2><table id="actions"><thead><tr><th>@timestamp</th><th>action</th><th>target</th><th>tenant</th><th>status</th><th>details</th></tr></thead><tbody id="actions_tbody"></tbody></table>
  <script>
    async function j(u){return (await fetch(u)).json()} function sv(v){return v? v: ""} function td(v){return "<td>"+sv(v)+"</td>"}
    (async()=>{
      const [agents,alerts,actions]=await Promise.all([j('/api/agents'),j('/api/alerts'),j('/api/actions')]);
      document.querySelector('#agents_tbody').innerHTML=(agents||[]).map(a=>`<tr>${td(a.agent_id)}${td(a['@timestamp'])}${td(a.host)}${td(a.version)}<td><span class="pill">${sv(a.status)}</span></td></tr>`).join('');
      document.querySelector('#alerts_tbody').innerHTML=(alerts||[]).map(h=>`<tr>${td(h['@timestamp'])}${td(h.rule&&h.rule.name)}${td(h.source&&h.source.ip)}${td(h.host&&(h.host.name||h.host.hostname))}${td(h.host&&h.host.ip)}${td(h.message)}</tr>`).join('');
      document.querySelector('#actions_tbody').innerHTML=(actions||[]).map(a=>`<tr>${td(a['@timestamp'])}${td(a.action)}${td(a.target)}${td(a.tenant||'')}${td(a.status)}${td(a.reason||a.details||'')}</tr>`).join('');
    })();
  </script></body></html>"""
    return Response(content=html, media_type="text/html")
