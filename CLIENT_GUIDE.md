# CyberSentinel WAF — Client Deployment & Operations Guide

Welcome to the **CyberSentinel Web Application Firewall (WAF)** deployment guide. This document outlines system requirements, installation instructions, gateway routing architecture, TLS customization, custom rules modification, and troubleshooting diagnostics.

---

## 📋 System Requirements & Prerequisites

The WAF is completely containerized. The target host machine only requires the following software:
1. **Operating System**: Linux (Ubuntu 22.04 LTS recommended, or any system supporting Docker).
2. **Container Engine**:
   - **Docker** (v20.10.0 or later)
   - **Docker Compose** (v2.0.0 or later, installed as the `docker-compose-plugin` or standalone binary)
3. **Hardware Requirements**:
   - **Minimum**: 2 Cores CPU, 4 GB RAM, 10 GB Disk space.
   - **Recommended**: 4 Cores CPU, 8 GB RAM (to handle high concurrent throughput and active ML classification queue).
4. **Networking**: Ensure ports `80`, `443`, and `3001` are not bound by any processes on the host.

---

## 🚀 Quick Start Deployment

1. Clone or copy the CyberSentinel WAF repository into your deployment folder (e.g., `/opt/cybersentinel/WAF_GUI/`).
2. Navigate to the project root directory:
   ```bash
   cd /opt/cybersentinel/WAF_GUI/
   ```
3. Run the automated interactive installer script:
   ```bash
   ./setup.sh
   ```
   *The installer script will verify dependencies, generate secure Redis and JWT secret keys inside `.env`, compile ModSecurity v3.0.14+ from source inside dynamic builders, set up self-signed TLS certificates for development, configure custom admin credentials, start the containers, and run health verification checks.*

---

## 🌐 Network Architecture & Port Mapping

Once the setup finishes, the WAF exposes three primary entry points:

| Port | Protocol | Intercepted? | Purpose |
|------|----------|--------------|---------|
| **`3001`** | HTTP | **WAF Inspected** | Administrative WAF dashboard. ModSecurity and ML checking are active, but exclusions are loaded specifically to let WAF administrators configure rules and domains without triggering false positive blocks. |
| **`80`** | HTTP | No | Automatically catches plain HTTP traffic and issues a `301 Moved Permanently` redirect to HTTPS on port `443`. |
| **`443`** | HTTPS | **WAF Gateway** | Main WAF Gateway. Inspects incoming headers, parameters, and bodies using both ModSecurity (OWASP CRS v4) and the XGBoost ML Threat Engine, proxying clean traffic to upstreams. |

---

## 🔐 Custom Production SSL/TLS Certificates

By default, the setup script generates a self-signed TLS certificate for localhost testing. For production deployments behind a valid CA-signed certificate (e.g., Let's Encrypt, DigiCert):

1. Place your CA-signed certificate and private key files into the local SSL config folder:
   - **Certificate file**: `configs/nginx/ssl/cybersentinel.crt`
   - **Private key file**: `configs/nginx/ssl/cybersentinel.key`
2. Validate the configuration and reload the OpenResty container:
   ```bash
   # Test Nginx syntax
   sudo docker exec waf-openresty openresty -t
   
   # Gracefully reload the configuration
   sudo docker exec waf-openresty openresty -s reload
   ```

---

## 🖥️ Managing Protected Applications & Upstreams

Protected applications are managed dynamically through the dashboard:
1. Log in to the dashboard at `http://<host-ip>:3001/`.
2. Go to the **Apps Control** tab.
3. Add a new application by specifying:
   - **Domain (Virtual Host)**: The domain name the client uses (e.g., `app.mycompany.com`). If this is the main or default gateway, use `_`.
   - **Upstream Host & Port**: The internal target container name or IP (e.g., `my-backend-service` or `172.18.0.5:8080`).
   - **Protocol**: HTTP/HTTPS.
   - **Rate Limiting**: Custom Requests Per Second (RPS) limit and burst tolerance.
4. Click **Save** and **Apply**.
   *The WAF backend dynamically regenerates the virtual hosts configuration inside the shared volume at `configs/nginx/sites-enabled/mssp` and triggers an OpenResty reload.*

---

## ✍️ Custom Rules & Exclusions

You can configure custom blocking policies, paranoia levels, and exclusions without modifying the core rule set. All modifications should be made in the files located under `configs/nginx/modsec/`:

* **`rules-override.conf`**: Use this file to define rule exclusions or whitelist specific variables if ModSecurity blocks legitimate application features (false positives).
* **`custom-dlp.conf`**: Configure data loss prevention or custom signature matches (e.g., blocking requests containing specific header flags).
* **`custom-ml.conf`**: Custom rules related to the XGBoost/Anomaly ML engine overrides.

Always test and reload Nginx after editing these configuration files:
```bash
sudo docker exec waf-openresty openresty -t && sudo docker exec waf-openresty openresty -s reload
```

---

## 🧪 Log Inspection & Diagnostics

All container logs are redirected to local directories for persistent host analysis:

* **Nginx Access Logs**: `logs/nginx/access.log` (Contains all traffic stats).
* **Nginx Error Logs**: `logs/nginx/error.log` (Contains OpenResty warnings and ModSecurity block events).
* **ModSecurity Audit Logs**: `logs/modsecurity/audit/` (Contains detailed multi-part JSON records of blocked attacks, sorted by date).
* **ML Telemetry Events**: `logs/ml-waf/` (Contains prediction logs and retraining drift telemetry).

### Essential Debugging Cheat Sheet:

```bash
# View real-time security events
tail -f logs/nginx/error.log | grep -i "ModSecurity"

# Check container health status
sudo docker compose ps

# View container logs
sudo docker compose logs -f waf-backend
sudo docker compose logs -f waf-openresty
sudo docker compose logs -f waf-ml

# Force manual ML model retraining
docker exec -it waf-ml /app/retrain.sh
```
