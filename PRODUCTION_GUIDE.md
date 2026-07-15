# CyberSentinel WAF — Production Deployment Guide

This guide walks you through deploying CyberSentinel WAF to a production environment with proper SSL certificates and CORS configuration.

---

## 🚀 Quick Production Setup

### Option 1: Fresh Installation (Recommended)

Run the interactive setup script which now includes production options:

```bash
sudo ./setup.sh
```

**During setup, you'll be prompted for:**

1. **SSL Certificate Configuration**:
   - Option 1: Self-signed (development only)
   - **Option 2: Use existing certificate files (RECOMMENDED for production)**
   - Option 3: Generate Let's Encrypt certificate (requires domain)

2. **CORS Configuration**:
   - Enter your production domain (e.g., `waf.company.com`)
   - Script will automatically configure: `https://waf.company.com`, `http://waf.company.com`, etc.

### Option 2: Update Existing Deployment

If you already have CyberSentinel running, use the production configuration tool:

```bash
sudo ./scripts/configure-production.sh
```

This interactive script allows you to:
- Update SSL certificates (existing files or Let's Encrypt)
- Update CORS origins
- Automatically restart services
- Validate configuration

---

## 🔐 SSL Certificate Setup (Detailed)

### Method 1: Using Your Own SSL Certificates (Recommended)

If you have SSL certificates from your CA (e.g., DigiCert, GoDaddy, Sectigo):

```bash
# Run the configuration script
sudo ./scripts/configure-production.sh

# Select: [1] Update SSL/TLS Certificates
# Then: [1] Use existing certificate files

# When prompted, provide paths:
Enter full path to certificate file: /path/to/your/certificate.crt
Enter full path to private key file: /path/to/your/privatekey.key
```

**Manual Method:**

```bash
# Copy your certificates to the WAF directory
sudo cp /path/to/your/certificate.crt configs/nginx/ssl/cybersentinel.crt
sudo cp /path/to/your/privatekey.key configs/nginx/ssl/cybersentinel.key

# Set proper permissions
sudo chmod 644 configs/nginx/ssl/cybersentinel.crt
sudo chmod 600 configs/nginx/ssl/cybersentinel.key

# Restart OpenResty
sudo docker compose restart openresty
```

### Method 2: Let's Encrypt (Free SSL)

**Prerequisites:**
- A registered domain name pointing to your server's IP
- Port 80 must be accessible from the internet
- Certbot installed (script can install it automatically)

```bash
# Run the configuration script
sudo ./scripts/configure-production.sh

# Select: [1] Update SSL/TLS Certificates
# Then: [2] Generate Let's Encrypt certificate

# Provide:
Enter your domain name: waf.company.com
Enter your email: admin@company.com
```

**Set up automatic renewal** (certificate expires in 90 days):

```bash
# Add to crontab
sudo crontab -e

# Add this line to auto-renew at 3 AM daily:
0 3 * * * certbot renew --quiet --deploy-hook 'docker exec waf-openresty openresty -s reload'
```

### Method 3: Using Wildcard Certificates

If you have a wildcard certificate (e.g., `*.company.com`):

```bash
# Copy wildcard certificate
sudo cp /path/to/wildcard.crt configs/nginx/ssl/cybersentinel.crt
sudo cp /path/to/wildcard.key configs/nginx/ssl/cybersentinel.key

# Restart OpenResty
sudo docker compose restart openresty
```

### Verify SSL Certificate

```bash
# Check certificate details
openssl x509 -in configs/nginx/ssl/cybersentinel.crt -noout -text -dates -subject -issuer

# Test HTTPS connection
curl -v https://your-domain.com:443 2>&1 | grep "SSL certificate verify"

# Check from browser
# Navigate to: https://your-domain.com:3001
# Click padlock icon → Certificate details
```

---

## 🌐 CORS Configuration (Detailed)

CORS (Cross-Origin Resource Sharing) controls which domains can access your WAF API.

### Method 1: Single Production Domain

```bash
# Run configuration script
sudo ./scripts/configure-production.sh

# Select: [2] Update CORS Origins
# Then: [1] Configure for single production domain

# Enter: waf.company.com
```

This automatically configures:
- `https://waf.company.com`
- `http://waf.company.com`
- `https://waf.company.com:3001`
- `http://waf.company.com:3001`

### Method 2: Multiple Domains

```bash
# Run configuration script
sudo ./scripts/configure-production.sh

# Select: [2] Update CORS Origins
# Then: [2] Configure for multiple domains

# Enter comma-separated origins:
https://waf.company.com,https://admin.company.com,https://soc.company.com
```

### Method 3: Manual Configuration

Edit `.env` file directly:

```bash
nano .env
```

Update the `BACKEND_CORS_ORIGINS` line:

```env
BACKEND_CORS_ORIGINS=https://waf.company.com,https://admin.company.com,https://soc.company.com
```

**Important:**
- Use `https://` for production (not `http://`)
- No trailing slashes
- Comma-separated, no spaces
- Include port numbers if non-standard (e.g., `:3001`)

Restart backend:

```bash
sudo docker compose restart backend
```

### Verify CORS Configuration

```bash
# Check current CORS settings
grep BACKEND_CORS_ORIGINS .env

# Test CORS from browser console
fetch('http://your-waf-ip:3001/api/health', {
  method: 'GET',
  credentials: 'include'
}).then(r => r.json()).then(console.log)

# Check backend logs for CORS errors
sudo docker compose logs backend | grep -i cors
```

---

## 🔒 Production Security Checklist

Before deploying to production, ensure you complete these critical tasks:

### ✅ Must Do (Critical)

- [ ] **Change default passwords**
  ```bash
  # Use password reset script
  sudo ./scripts/reset-password.py
  
  # Or reset via backend container
  sudo docker exec -it waf-backend python3 /app/scripts/reset-password.py
  ```

- [ ] **Install valid SSL certificates** (not self-signed)
  ```bash
  sudo ./scripts/configure-production.sh
  ```

- [ ] **Configure production CORS origins**
  ```bash
  sudo ./scripts/configure-production.sh
  ```

- [ ] **Update Redis password**
  ```bash
  # Generate strong password
  REDIS_PASS=$(openssl rand -hex 32)
  
  # Update .env
  sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${REDIS_PASS}|" .env
  
  # Restart services
  sudo docker compose restart redis backend ml-engine
  ```

- [ ] **Regenerate JWT secret**
  ```bash
  # Generate new secret
  JWT_SECRET=$(openssl rand -hex 32)
  
  # Update .env
  sed -i "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${JWT_SECRET}|" .env
  
  # Restart backend
  sudo docker compose restart backend
  ```

### ✅ Should Do (Recommended)

- [ ] **Configure firewall rules**
  ```bash
  # Allow WAF dashboard (restrict to admin IPs)
  sudo ufw allow from 203.0.113.0/24 to any port 3001 proto tcp
  
  # Allow HTTP/HTTPS from anywhere
  sudo ufw allow 80/tcp
  sudo ufw allow 443/tcp
  
  # Enable firewall
  sudo ufw enable
  ```

- [ ] **Set up log rotation**
  ```bash
  # Create logrotate config
  sudo tee /etc/logrotate.d/cybersentinel <<EOF
  /opt/ModSecurity/WAF_GUI/logs/nginx/*.log {
      daily
      rotate 14
      compress
      delaycompress
      missingok
      notifempty
      sharedscripts
      postrotate
          docker exec waf-openresty openresty -s reload
      endscript
  }
  EOF
  ```

- [ ] **Configure automated backups**
  ```bash
  # Create backup script
  sudo tee /root/backup-waf.sh <<'EOF'
  #!/bin/bash
  BACKUP_DIR="/backup/waf/$(date +%Y%m%d)"
  mkdir -p "$BACKUP_DIR"
  
  # Backup databases
  cp /opt/ModSecurity/WAF_GUI/backend/app/config/*.db "$BACKUP_DIR/"
  cp /opt/ModSecurity/WAF_GUI/backend/app/config/*.json "$BACKUP_DIR/"
  cp /opt/ModSecurity/WAF_GUI/.env "$BACKUP_DIR/"
  
  # Backup ML models
  cp -r /opt/ModSecurity/WAF_GUI/ml-waf/models "$BACKUP_DIR/"
  
  # Compress
  tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
  rm -rf "$BACKUP_DIR"
  
  # Keep only last 30 days
  find /backup/waf/ -name "*.tar.gz" -mtime +30 -delete
  EOF
  
  sudo chmod +x /root/backup-waf.sh
  
  # Add to crontab (daily at 2 AM)
  (crontab -l 2>/dev/null; echo "0 2 * * * /root/backup-waf.sh") | crontab -
  ```

- [ ] **Set up monitoring**
  ```bash
  # Install Prometheus Node Exporter (optional)
  # Configure health check monitoring
  # Set up alerts for service failures
  ```

- [ ] **Configure email alerts** (via settings.json)
  ```json
  {
    "alerts": {
      "enabled": true,
      "smtp_host": "smtp.company.com",
      "smtp_port": 587,
      "smtp_user": "alerts@company.com",
      "smtp_password": "your-password",
      "recipient": "soc@company.com"
    }
  }
  ```

### ✅ Nice to Have (Optional)

- [ ] Enable two-factor authentication (TOTP)
- [ ] Set up centralized logging (Splunk/ELK)
- [ ] Configure high availability (multi-node)
- [ ] Implement rate limiting at infrastructure level
- [ ] Set up automated ML model retraining

---

## 🧪 Testing Your Production Configuration

### 1. Test SSL Certificate

```bash
# Test SSL handshake
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Check certificate expiry
echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates

# Online SSL test
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.com
```

### 2. Test CORS Configuration

```bash
# Test from command line
curl -H "Origin: https://your-domain.com" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: X-Requested-With" \
     -X OPTIONS --verbose \
     http://your-waf-ip:3001/api/health
     
# Should see: Access-Control-Allow-Origin: https://your-domain.com
```

### 3. Test WAF Protection

```bash
# Test basic functionality
curl https://your-domain.com:3001/api/health

# Test ModSecurity blocking (should be blocked)
curl "https://your-domain.com/?id=1' OR '1'='1"

# Test ML-WAF (check logs)
curl -X POST https://your-domain.com/api/test \
     -H "User-Agent: sqlmap/1.0" \
     -d "payload=<script>alert(1)</script>"
```

### 4. Load Testing

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Basic load test (100 requests, 10 concurrent)
ab -n 100 -c 10 https://your-domain.com:3001/api/health

# Monitor during test
watch -n 1 'docker stats --no-stream'
```

---

## 🔧 Troubleshooting

### SSL Certificate Issues

**Problem:** "Certificate verification failed" error

```bash
# Check certificate chain
openssl verify -CAfile /path/to/ca-bundle.crt configs/nginx/ssl/cybersentinel.crt

# If using Let's Encrypt, ensure fullchain.pem is used (not cert.pem)
sudo cp /etc/letsencrypt/live/domain/fullchain.pem configs/nginx/ssl/cybersentinel.crt
```

**Problem:** "Private key does not match certificate"

```bash
# Verify modulus match
openssl x509 -noout -modulus -in configs/nginx/ssl/cybersentinel.crt | openssl md5
openssl rsa -noout -modulus -in configs/nginx/ssl/cybersentinel.key | openssl md5
# Both should output identical MD5 hashes
```

### CORS Issues

**Problem:** "CORS policy blocked" in browser

```bash
# Check backend logs
sudo docker compose logs backend | tail -50

# Verify CORS setting
grep BACKEND_CORS_ORIGINS .env

# Ensure origin includes protocol and port
# ✅ Correct: https://waf.company.com:3001
# ❌ Wrong: waf.company.com
```

**Problem:** CORS works on localhost but not production

```bash
# Ensure production domain is in CORS origins
# Update .env and restart backend
sudo ./scripts/configure-production.sh
```

### Service Won't Start After Configuration

```bash
# Check all logs
sudo docker compose logs

# Specific service logs
sudo docker compose logs openresty
sudo docker compose logs backend

# Validate Nginx config
sudo docker exec waf-openresty openresty -t

# Check certificate permissions
ls -l configs/nginx/ssl/
# Certificate should be 644, key should be 600
```

---

## 📞 Support & Maintenance

### Regular Maintenance Tasks

| Task | Frequency | Command |
|------|-----------|---------|
| Check logs | Daily | `sudo docker compose logs --tail=100` |
| Review blocked attacks | Daily | Access dashboard → Security Logs |
| Update OWASP CRS | Monthly | `sudo ./scripts/update-crs.sh` |
| Retrain ML models | 15-20 days | `sudo docker exec waf-ml /app/retrain.sh` |
| Backup databases | Daily | `sudo /root/backup-waf.sh` |
| Check certificate expiry | Weekly | `openssl x509 -in configs/nginx/ssl/cybersentinel.crt -noout -dates` |
| Review false positives | Weekly | Dashboard → False Positives tab |
| Update Docker images | Monthly | `sudo docker compose pull && sudo docker compose up -d` |

### Emergency Procedures

**If WAF is blocking legitimate traffic:**

```bash
# Temporary: Switch to detection-only mode
sudo docker exec waf-backend python3 -c "
import json
with open('/app/app/config/settings.json', 'r+') as f:
    data = json.load(f)
    data['waf']['mode'] = 'DetectionOnly'
    f.seek(0)
    json.dump(data, f, indent=2)
"
sudo docker exec waf-openresty openresty -s reload
```

**If services are down:**

```bash
# Quick restart
sudo docker compose restart

# Full rebuild if needed
sudo docker compose down
sudo docker compose up -d --build
```

---

## 📚 Additional Resources

- **Let's Encrypt Documentation**: https://letsencrypt.org/docs/
- **OWASP ModSecurity Core Rule Set**: https://coreruleset.org/
- **SSL Configuration Generator**: https://ssl-config.mozilla.org/
- **CORS Best Practices**: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

---

**Last Updated:** 2026-07-15  
**Version:** 1.0.0
