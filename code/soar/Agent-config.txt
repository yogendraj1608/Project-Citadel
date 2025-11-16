from flask import Flask, jsonify, request
import ipaddress, subprocess, shlex

app = Flask(__name__)

AGENT_TOKEN = "change-me"

def run(cmd):
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True, check=False)

def ensure_filter_chain():
    run("nft list table inet filter").returncode == 0 or run("nft add table inet filter")
    rc = run("nft list chain inet filter input").returncode
    if rc != 0:
        run("nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'")

def is_ip_blocked(ip):
    res = run(f"nft list chain inet filter input")
    return (res.returncode == 0) and (f"ip saddr {ip} drop" in res.stdout)

def block_ip(ip):
    ensure_filter_chain()
    if not is_ip_blocked(ip):
        run(f'nft insert rule inet filter input ip saddr {ip} log prefix "SOAR-BLOCK " level info')
        res = run(f"nft add rule inet filter input ip saddr {ip} drop")
        return res.returncode == 0, res.stdout + res.stderr
    return True, "already present"

@app.get("/")
def root():
    return jsonify(status="ok", name="tenant1-agent")

@app.get("/health")
def health():
    return jsonify(status="healthy")

@app.post("/act/block-ip")
def act_block_ip():
    token = request.headers.get("X-Agent-Token", "")
    if AGENT_TOKEN and token != AGENT_TOKEN:
        return jsonify(status="forbidden"), 403

    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify(status="error", error="invalid_ip", detail=ip), 400

    ok, detail = block_ip(ip)
    return jsonify(status="success" if ok else "error", action="block-ip", ip=ip, detail=detail), (200 if ok else 500)
