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

## 6. POC

# 1️⃣ Management

<div align="left">
  <img width="944" height="438" alt="image" src="https://github.com/user-attachments/assets/daef4585-52f6-4171-8cbc-ca85dcf6cf86" />
  <p>Secrets visible in Vault include MinIO credentials, Elasticsearch credentials, and application-specific secrets.</p>
</div>

<br>

<div align="left">
  <img width="940" height="475" alt="image" src="https://github.com/user-attachments/assets/8d3f0349-dc7d-44e8-8fd8-9197be6a41f4" />
  <p>Screenshot of Keycloak admin console showing two realms: tenant1 and tenant2</p>
</div>

<br>

<div align="left">
  <img width="944" height="314" alt="image" src="https://github.com/user-attachments/assets/e518f9b7-ad35-4a21-9aba-a116276548c9" />
  <p>Buckets created per tenant and function were verified via MinIO Console</p>
</div>

<br>

# 2️⃣ Monitoring

<div align="left">
  <img width="945" height="236" alt="image" src="https://github.com/user-attachments/assets/9654c270-67ba-4505-b438-115d33f24614" />
  <p>Cluster Node Status</p>
</div>

<br>
<div align="left">
  <img width="939" height="295" alt="image" src="https://github.com/user-attachments/assets/90d65195-8821-43ba-948f-043dc2bfd651" />
  <p>cert-manager status</p>
</div>

<br>

<div align="left">
  <img width="940" height="397" alt="image" src="https://github.com/user-attachments/assets/e083533a-7482-450b-a561-f39f11e51973" />
  <p>NGINX Ingress status</p>
</div>

<br>

<div align="left">
  <img width="940" height="450" alt="image" src="https://github.com/user-attachments/assets/3c810285-9701-44d9-bb69-a59889d1216f" />
  <p>Falco was configured in detection mode</p>
</div>

<br>

<div align="left">
  <img width="939" height="451" alt="image" src="https://github.com/user-attachments/assets/2a063f83-4dc3-4b21-843f-40bdab158876" />
  <p>Prometheus Target Verification</p>
</div>

<br>

<div align="left">
  <img width="951" height="457" alt="image" src="https://github.com/user-attachments/assets/f4d07fbb-092d-46be-a139-cb73ab301eb4" />
  <p>Grafana Node Exporter Full (ID: 1860) displays real-time CPU, memory, disk, and network utilization for all Citadel nodes. Instance filters enable per-VM analysis.</p>
</div>

<br>

<div align="left">
  <img width="929" height="562" alt="image" src="https://github.com/user-attachments/assets/0524b367-9fb5-4efe-b64d-6ba78895aa26" />
  <p>Elasticsearch Exporter Dashboard (ID: 4358) shows Alert dashboard form elasticsearch, and node statistics for the ELK stack.</p>
</div>

<br>


<div align="left">
  <img width="944" height="468" alt="image" src="https://github.com/user-attachments/assets/04c4d40a-4d24-4b99-9dcc-e65de9cd14fa" />
  <p>Alert dashboard form Wazuh (via opensearch).</p>
</div>

<br>

<div align="left">
  <img width="938" height="381" alt="image" src="https://github.com/user-attachments/assets/9a8a954f-6ca3-4aea-b0f0-6ddba8c527c7" />
  <p>A NodeDown alert was triggered by stopping a node exporter service temporarily. The alert appeared in the Prometheus /alerts page with the correct severity and labels.</p>
</div>

<br>

<div align="left">
  <img width="944" height="480" alt="image" src="https://github.com/user-attachments/assets/0c91adc4-d92a-4c87-875b-70e05aa1b1c7" />
  <p>Alertmanager forwarded the alert to the dedicated Slack #alerts channel, demonstrating end- to-end notification delivery into SOC workflows</p>
</div>

<br>

# 3️⃣ SIEM

<div align="left">
  <img width="944" height="481" alt="image" src="https://github.com/user-attachments/assets/e245f491-bc4e-4d58-93ef-546ab368fe81" />
  <p>Screenshots show successful agent registration for both Tenant 1 and Tenant 2 on the Wazuh server.</p>
</div>

<br>

<div align="left">
  <img width="944" height="477" alt="image" src="https://github.com/user-attachments/assets/db1de5b3-de73-45c9-b58c-6a022a0fb861" />
  <p>Log extracts confirm syslog, file integrity monitoring (FIM), and security events.</p>
</div>

<br>

<div align="left">
  <img width="944" height="478" alt="image" src="https://github.com/user-attachments/assets/b23cd66e-c3ee-4e1d-86b8-2a897fce7771" />
  <p>EVE JSON logs from Suricata are successfully picked up by Elastic Agent and forwarded to Elasticsearch and Index inspection confirms fields such as src_ip, dest_ip, alert.signature, and geoip.country_name are properly parsed.</p>
</div>

<br>

<div align="left">
  <img width="944" height="474" alt="image" src="https://github.com/user-attachments/assets/4c2f878b-699d-4bcc-b4b9-5393eb55d857" />
  <p>EVE JSON logs from Suricata are successfully picked up by Wazuh agent and forwarded to Wazuh manager.</p>
</div>

<br>

<div align="left">
  <img width="944" height="483" alt="image" src="https://github.com/user-attachments/assets/52e11899-1080-49a5-bf00-248a7ac32a17" />
  <p>Keycloak Authentication Log Ingestion</p>
</div>

<br>

<div align="left">
  <img width="944" height="429" alt="image" src="https://github.com/user-attachments/assets/eae7b3bd-73c0-49fd-bd0b-e8fcd7c8fdce" />
  <p>Kubernetes Telemetry Ingestion</p>
</div>

<br>


<div align="left">
  <img width="944" height="479" alt="image" src="https://github.com/user-attachments/assets/70883234-da5d-4f2a-97d6-4697661d004e" />
  <p>Detection Rule Validation</p>
</div>

<br>

<div align="left">
  <img width="944" height="476" alt="image" src="https://github.com/user-attachments/assets/a5a82d82-7ec4-465d-b7c1-9c137965200d" />
  <p>SSH Login Activity Dashboard</p>
</div>

<br>

<div align="left">
  <img width="944" height="483" alt="image" src="https://github.com/user-attachments/assets/2017f98b-f82a-46a3-ba3a-ecb4a297ba7d" />
  <p>Keycloak Authentication Dashboard</p>
</div>

<br>

<div align="left">
  <img width="944" height="482" alt="image" src="https://github.com/user-attachments/assets/c568b3a0-509c-4565-95d2-c4ebc1f7dff6" />
  <p>Suricata IDS Dashboard</p>
</div>

<br>

<div align="left">
  <img width="944" height="371" alt="image" src="https://github.com/user-attachments/assets/ee602238-8b42-44c9-9793-fa9449487bdb" />
  <p>Kubernetes Monitoring Dashboard</p>
</div>

<br>

# 4️⃣ SOAR

<div align="left">
<img width="944" height="371" alt="image" src="https://github.com/user-attachments/assets/b83130c5-8b91-4e5b-8a92-231e8779a124" />
<img width="944" height="292" alt="image" src="https://github.com/user-attachments/assets/c1ae9764-7ae6-4243-8010-5ce5154aa042" />
  <p>The following screenshots show the alert rule configuration in ELK and the corresponding
webhook trigger to the SOAR engine.
</p>
</div>

<br>

<div align="left">
  <img width="944" height="444" alt="image" src="https://github.com/user-attachments/assets/dfb8756b-8ed2-4c1d-a686-8987d2f0ec6d" />
  <p>Alert Rule in ELK</p>
</div>

<br>


<div align="left">
  <img width="935" height="273" alt="image" src="https://github.com/user-attachments/assets/7757bc7c-8b97-4d8c-82d8-27afd284310a" />
  <p>SOAR Engine Webhook Receiver Logs and SOAR agent status</p>
</div>

<br>

<div align="left">
  <img width="940" height="557" alt="image" src="https://github.com/user-attachments/assets/28a22b96-75b5-4cc2-a4c9-264611f56e54" />
  <p>This demonstrates end-to-end automation: alert reception, secret retrieval from Vault, action execution, and notification.</p>
</div>

<br>

<div align="left">
  <img width="944" height="315" alt="image" src="https://github.com/user-attachments/assets/7440dbe3-b568-4684-a9b2-6ad158b59224" />
  <p>Evidence Storage in MinIO </p>
</div>

<br>

<div align="left">
  <img width="944" height="502" alt="image" src="https://github.com/user-attachments/assets/97af115d-658b-4896-b4ba-f0b03fec87e3" />
  <p>SOAR Operations Dashboard</p>
</div>

<br>


<div align="left">
  <img width="944" height="475" alt="image" src="https://github.com/user-attachments/assets/533fe925-c7de-4f5b-989b-c0be6fedfcbb" />
  <p>Email Notification</p>
</div>

<br>

# 5️⃣ UEBA

<div align="left">
  <img width="939" height="401" alt="image" src="https://github.com/user-attachments/assets/8384e188-7b91-4d0e-b1fe-4e3e2a8e72e6" />
  <p>Data Ingestion & Feature Extraction Validation</p>
</div>

<br>

<div align="left">
  <img width="944" height="486" alt="image" src="https://github.com/user-attachments/assets/6e1fd74c-5743-475d-aaca-f3b1a6c25378" />
  <p>Dashboard Visualization Evidence</p>
</div>

<br>

<div align="left">
  <img width="944" height="497" alt="image" src="https://github.com/user-attachments/assets/13b79234-4131-4dd7-b8d7-a3b5285a384c" />
  <p>Analyst anomaly table with explanation badges.</p>
</div>

<br>

<div align="left">
  <img width="944" height="499" alt="image" src="https://github.com/user-attachments/assets/40e835bf-94df-4e72-a50a-516a5911e05d" />
  <p>Drill-down user timeline and geo map visualization.</p>
</div>

<br>

<div align="left">
  <img width="944" height="544" alt="image" src="https://github.com/user-attachments/assets/52e55717-4eb7-44b9-a61a-f44d4377dfd0" />
  <p>SOC mailbox displaying multiple structured UEBA alerts with distinct Incident IDs.
 
</p>
</div>

<br>

