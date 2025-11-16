# Project Citadel – Deployment & Configuration Guide

## 1. Infrastructure Overview

| VM | Role | Components |
|----|------|-------------|
| citadel-elk | SIEM | Elasticsearch, Logstash, Kibana, Wazuh, Suricata |
| citadel-ueba | UEBA Engine | Python, Streamlit, Isolation Forest |
| citadel-soar | SOAR Engine | FastAPI, Vault, MinIO client |
| citadel-vault | Secrets Mgmt | Vault server |
| citadel-minio | Evidence Store | MinIO S3 server |
| citadel-mon | Monitoring | Prometheus, Grafana |
| tenants | Agents | Wazuh / Elastic Agent |

---

## 2. Prerequisites
- Ubuntu 22.04 on all VMs
- Minimum 2 vCPU, 4GB RAM each
- Python 3.10+, Docker, Git, OpenSSL
- API keys: Mailgun, VirusTotal
- Network ports open: 9200, 5601, 8200, 9000, 3000, 9090

---

## 3. Deployment Steps

### Step 1 – Setup SIEM (citadel-elk)
```bash
sudo apt update && sudo apt install elasticsearch logstash kibana wazuh-manager suricata -y
sudo systemctl enable elasticsearch logstash kibana wazuh-manager suricata
```
Edit `/etc/elasticsearch/elasticsearch.yml`:
```yaml
network.host: 0.0.0.0
discovery.type: single-node
```
Start services:
```bash
sudo systemctl start elasticsearch logstash kibana
```

---

### Step 2 – Deploy UEBA (citadel-ueba)
```bash
unzip UEBA.zip && cd UEBA
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python main.py
```
Configuration:
```yaml
elasticsearch:
  host: http://citadel-elk:9200
  index: logs-system.auth-*
mail:
  smtp: smtp.mailgun.org
  sender: alerts@citadel.local
vt_api_key: <YOUR_VT_KEY>
```

---

### Step 3 – Deploy SOAR (citadel-soar)
```bash
unzip SOAR-Engine.zip && cd SOAR-Engine
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python main.py
```
Environment Variables:
```
MINIO_ENDPOINT=http://citadel-minio:9000
MINIO_ACCESS_KEY=admin
MINIO_SECRET_KEY=password
VAULT_ADDR=http://citadel-vault:8200
MAILGUN_KEY=<YOUR_KEY>
```

---

### Step 4 – Configure Vault (citadel-vault)
```bash
vault server -config=config.hcl &
vault secrets enable kv
vault kv put secret/mailgun api_key=<mailgun_key>
vault kv put secret/soar minio_key=admin minio_secret=password
```

---

### Step 5 – Deploy MinIO (citadel-minio)
```bash
docker run -d -p 9000:9000 -p 9001:9001   -e MINIO_ROOT_USER=admin   -e MINIO_ROOT_PASSWORD=password   quay.io/minio/minio server /data --console-address ":9001"
```

---

### Step 6 – Setup Monitoring (citadel-mon)
```bash
docker run -d --name prometheus -p 9090:9090 prom/prometheus
docker run -d --name grafana -p 3000:3000 grafana/grafana
```
Add Prometheus datasource in Grafana → import dashboards for Wazuh, Suricata, Node Exporter.

---

### Step 7 – Integrate Agents (tenant VMs)
```bash
sudo ./elastic-agent install --url=http://citadel-elk:8220 --enrollment-token <TOKEN>
```

---

## 4. Validation Checklist

| Component | Validation |
|------------|-------------|
| ELK | Dashboards visible in Kibana |
| UEBA | Alerts generated for anomalies |
| SOAR | Playbook executes & logs evidence |
| Vault | Secrets retrievable via API |
| MinIO | Evidence objects appear under /alerts |
| Grafana | Metrics from Prometheus visible |

---

## 5. Maintenance
- Rotate Vault secrets every 30 days  
- Re-train UEBA models monthly  
- Review SOAR playbook logs weekly  
- Apply Elasticsearch ILM policies  

---

## 6. Authors
Gardiyan Labs – Security Engineering & Research (SER)  
Maintainer: Naveen Bana  
Contributors: Himadri, Sourabh Kumar, Harshita, Yogendra  
License: MIT
