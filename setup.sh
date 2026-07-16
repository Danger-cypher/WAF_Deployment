#!/bin/bash
# =============================================================================
# CyberSentinel WAF — Automated Zero-Dependency Installer Script
# =============================================================================
# Automates:
#   1. System dependency checks (Docker & Docker Compose)
#   2. Secure random environment variables generation (.env)
#   3. Local self-signed SSL/TLS certificate generation
#   4. GeoIP Database download (MaxMind API or public mirror fallback)
#   5. User credential customization (seeding settings.json inside container)
#   6. Docker Compose build & start with automatic health verification
# =============================================================================

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Helper functions for structured output
log() { echo -e "${BLUE}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!] WARNING:${NC} $1"; }
error() { echo -e "${RED}[x] ERROR:${NC} $1" >&2; exit 1; }
success() { echo -e "${GREEN}[+]${NC} $1"; }

# Clear screen and display banner
clear
echo -e "${CYAN}=======================================================================${NC}"
echo -e "${CYAN}     CyberSentinel Web Application Firewall (WAF) Installer            ${NC}"
echo -e "${CYAN}=======================================================================${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: System Dependency Verification
# ─────────────────────────────────────────────────────────────────────────────
log "Verifying system requirements..."

# Check Docker installation
if ! command -v docker &> /dev/null; then
    warn "Docker is not installed. Attempting automated Docker installation..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg lsb-release
        sudo mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
        error "Supported package manager (apt-get) not found. Please install Docker manually."
    fi
fi
success "Docker is installed: $(docker --version)"

# Add current user to docker group if running via sudo
if [ -n "${SUDO_USER:-}" ]; then
    log "Adding user $SUDO_USER to the docker group..."
    sudo usermod -aG docker "$SUDO_USER" || true
fi

# Check Docker Compose (v2 plugin or v1 binary)
COMPOSE_CMD=""
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    warn "Docker Compose is not installed. Attempting automated Docker Compose plugin installation..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y docker-compose-plugin
        COMPOSE_CMD="docker compose"
    else
        error "Could not install Docker Compose automatically. Please install manually."
    fi
fi
success "Docker Compose command verified: $COMPOSE_CMD"

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Environment File Initialization (.env)
# ─────────────────────────────────────────────────────────────────────────────
log "Initializing environment configuration..."

ENV_FILE=".env"
ENV_TEMPLATE=".env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_TEMPLATE" ]; then
        log "Creating local .env from example template..."
        cp "$ENV_TEMPLATE" "$ENV_FILE"
    else
        log "Creating fresh .env configuration file..."
        cat > "$ENV_FILE" <<EOF
REDIS_PASSWORD=
JWT_SECRET_KEY=
BACKEND_CORS_ORIGINS=http://localhost:3001,http://127.0.0.1:3001
GEOIP_DATA_DIR=/etc/nginx/geoip
EOF
    fi
fi

# Load existing environment variables
# Set default values if not defined or empty
REDIS_PW=$(grep -E "^REDIS_PASSWORD=" "$ENV_FILE" | cut -d'=' -f2- || echo "")
JWT_KEY=$(grep -E "^JWT_SECRET_KEY=" "$ENV_FILE" | cut -d'=' -f2- || echo "")
CORS_ORIGINS=$(grep -E "^BACKEND_CORS_ORIGINS=" "$ENV_FILE" | cut -d'=' -f2- || echo "")

if [ -z "$REDIS_PW" ]; then
    log "Generating cryptographically secure password for Redis..."
    # Generate random 32-char hex string
    REDIS_PW=$(openssl rand -hex 16)
    # Replace in .env
    sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${REDIS_PW}|" "$ENV_FILE"
fi

if [ -z "$JWT_KEY" ]; then
    log "Generating secure JWT signing key..."
    JWT_KEY=$(openssl rand -hex 16)
    sed -i "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${JWT_KEY}|" "$ENV_FILE"
fi

if [ -z "$CORS_ORIGINS" ]; then
    echo ""
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}           CORS (Cross-Origin) Configuration                   ${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo ""
    log "Configure allowed origins for the WAF dashboard API..."
    echo -n "  Enter production domain (e.g., waf.company.com) or press ENTER for localhost: "
    read -r PROD_DOMAIN
    
    if [ -n "$PROD_DOMAIN" ]; then
        # Production deployment with custom domain
        CORS_ORIGINS="https://${PROD_DOMAIN},http://${PROD_DOMAIN},https://${PROD_DOMAIN}:3001,http://${PROD_DOMAIN}:3001"
        log "Production CORS configured for: $PROD_DOMAIN"
    else
        # Local development deployment
        CORS_ORIGINS="http://localhost:3001,http://127.0.0.1:3001,https://localhost,https://127.0.0.1"
        log "Development CORS configured for localhost"
    fi
    
    sed -i "s|^BACKEND_CORS_ORIGINS=.*|BACKEND_CORS_ORIGINS=${CORS_ORIGINS}|" "$ENV_FILE"
    success "CORS origins saved to $ENV_FILE"
fi

success "Environment variables generated and saved in $ENV_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: SSL/TLS Certificate Configuration
# ─────────────────────────────────────────────────────────────────────────────
log "Configuring SSL/TLS Certificates..."

CERT_DIR="configs/nginx/ssl"
CERT_FILE="${CERT_DIR}/cybersentinel.crt"
KEY_FILE="${CERT_DIR}/cybersentinel.key"

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo ""
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}                SSL/TLS Certificate Setup                      ${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${BLUE}[1]${NC} Generate self-signed certificate (development/testing)"
    echo -e "  ${BLUE}[2]${NC} Use existing certificate files (production)"
    echo -e "  ${BLUE}[3]${NC} Generate Let's Encrypt certificate (requires domain & port 80 open)"
    echo ""
    echo -n "  Select option [1-3]: "
    read -r SSL_CHOICE
    echo ""

    case "$SSL_CHOICE" in
        2)
            log "Using existing certificate files..."
            echo -n "  Enter path to certificate file (.crt or .pem): "
            read -r USER_CERT
            echo -n "  Enter path to private key file (.key): "
            read -r USER_KEY
            
            if [ -f "$USER_CERT" ] && [ -f "$USER_KEY" ]; then
                cp "$USER_CERT" "$CERT_FILE"
                cp "$USER_KEY" "$KEY_FILE"
                chmod 644 "$CERT_FILE"
                chmod 600 "$KEY_FILE"
                success "Production certificates copied to $CERT_DIR"
            else
                error "Certificate or key file not found. Please check paths and try again."
            fi
            ;;
        3)
            log "Setting up Let's Encrypt certificate via Certbot..."
            echo -n "  Enter your domain name (e.g., waf.example.com): "
            read -r DOMAIN_NAME
            echo -n "  Enter your email address for renewal notifications: "
            read -r CERT_EMAIL
            
            if ! command -v certbot &> /dev/null; then
                warn "Certbot not found. Installing..."
                if command -v apt-get &> /dev/null; then
                    sudo apt-get update && sudo apt-get install -y certbot
                elif command -v yum &> /dev/null; then
                    sudo yum install -y certbot
                else
                    error "Cannot install certbot automatically. Please install manually."
                fi
            fi
            
            log "Obtaining Let's Encrypt certificate for $DOMAIN_NAME..."
            sudo certbot certonly --standalone --non-interactive --agree-tos \
                --email "$CERT_EMAIL" -d "$DOMAIN_NAME" \
                --preferred-challenges http --http-01-port 80
            
            if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
                sudo cp "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" "$CERT_FILE"
                sudo cp "/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem" "$KEY_FILE"
                sudo chmod 644 "$CERT_FILE"
                sudo chmod 600 "$KEY_FILE"
                success "Let's Encrypt certificate installed for $DOMAIN_NAME"
                warn "Remember to set up auto-renewal: sudo certbot renew --dry-run"
            else
                warn "Let's Encrypt certificate generation failed. Falling back to self-signed."
                SSL_CHOICE="1"
            fi
            ;;
        *)
            SSL_CHOICE="1"
            ;;
    esac

    if [ "$SSL_CHOICE" = "1" ]; then
        log "Generating self-signed TLS certificates for development/testing..."
        warn "Self-signed certificates should NOT be used in production environments!"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
          -keyout "$KEY_FILE" \
          -out "$CERT_FILE" \
          -subj "/C=US/ST=State/L=City/O=CyberSentinel/CN=localhost" &>/dev/null
        success "Self-signed certificate written: $CERT_FILE"
    fi
else
    success "Existing TLS certificates found in $CERT_DIR. Skipping generation."
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: GeoIP2 Database Acquisition
# ─────────────────────────────────────────────────────────────────────────────
log "Verifying GeoIP2 Databases..."

GEOIP_DIR="backend/app/data"
GEOIP_FILE="${GEOIP_DIR}/GeoLite2-Country.mmdb"
mkdir -p "$GEOIP_DIR"

if [ ! -f "$GEOIP_FILE" ]; then
    warn "GeoLite2-Country.mmdb database is missing."
    echo -e -n "${YELLOW}[?]${NC} Please enter your MaxMind License Key (press ENTER to use public mirror fallback): "
    read -r LICENSE_KEY

    if [ -n "$LICENSE_KEY" ]; then
        log "Downloading GeoLite2-Country database from MaxMind API..."
        TEMP_TAR="/tmp/geoip.tar.gz"
        if wget -qO "$TEMP_TAR" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${LICENSE_KEY}&suffix=tar.gz"; then
            tar -xzf "$TEMP_TAR" -C /tmp
            mv /tmp/GeoLite2-Country_*/GeoLite2-Country.mmdb "$GEOIP_FILE"
            rm -f "$TEMP_TAR"
            success "MaxMind GeoIP Country Database downloaded successfully."
        else
            warn "MaxMind download failed. Attempting fallback mirror..."
            LICENSE_KEY=""
        fi
    fi

    if [ -z "$LICENSE_KEY" ]; then
        log "Downloading GeoLite2-Country database from public mirror fallback..."
        if wget -qO "$GEOIP_FILE" "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"; then
            success "Fallback GeoIP Country Database downloaded successfully."
        else
            warn "Failed to download GeoIP database. Geographic location metrics will be disabled."
            # Create a dummy empty database to avoid mount errors
            touch "$GEOIP_FILE"
        fi
    fi
else
    success "GeoIP database already present: $GEOIP_FILE"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: User Credential Setup
# ─────────────────────────────────────────────────────────────────────────────
log "Configuring administrative accounts..."

echo -n "  Enter Admin password (default: admin123): "
read -s ADMIN_PASS
echo ""
if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS="admin123"
fi

echo -n "  Enter Analyst password (default: analyst123): "
read -s ANALYST_PASS
echo ""
if [ -z "$ANALYST_PASS" ]; then
    ANALYST_PASS="analyst123"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Docker Compose Build & Deploy
# ─────────────────────────────────────────────────────────────────────────────
log "Building and starting containerized WAF services..."
# Clean up log ownership so containers can write immediately
sudo mkdir -p logs/nginx logs/modsecurity/audit configs/nginx/conf.d configs/nginx/sites-enabled
sudo chmod -R 777 logs configs

# Pre-create empty Nginx config files to prevent parser errors on first reload
cat > configs/nginx/conf.d/waf_ddos.conf <<EOF
# Auto-generated by CyberSentinel WAF GUI DDoS settings
# This file is overwritten at runtime — do not edit manually
EOF

cat > configs/nginx/conf.d/waf_hardening.conf <<EOF
# Auto-generated by CyberSentinel WAF GUI hardening settings
# This file is overwritten at runtime — do not edit manually
EOF

sudo chmod 666 configs/nginx/conf.d/waf_ddos.conf configs/nginx/conf.d/waf_hardening.conf

# Run compose build and up
sudo $COMPOSE_CMD build
sudo $COMPOSE_CMD up -d

# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Post-Boot Database and Credential Sync
# ─────────────────────────────────────────────────────────────────────────────
log "Applying credentials to the WAF database..."

# Wait for backend to become healthy (up to 60 seconds)
log "Waiting for backend container to become healthy..."
BACKEND_READY=false
for i in $(seq 1 20); do
    BACKEND_STATUS=$(sudo docker inspect --format='{{.State.Health.Status}}' waf-backend 2>/dev/null || echo "unknown")
    if [ "$BACKEND_STATUS" = "healthy" ]; then
        BACKEND_READY=true
        break
    fi
    log "  Backend not ready yet (status: $BACKEND_STATUS)... attempt $i/20"
    sleep 3
done

if [ "$BACKEND_READY" = "false" ]; then
    warn "Backend did not become healthy within 60 seconds. Attempting credential seeding anyway..."
fi

# Set passwords inside settings.json by executing an inline python command inside the running backend container
# This completely avoids installing bcrypt or other libraries on the host system
sudo docker exec -t waf-backend python3 -c "
import json
import bcrypt

path = '/app/app/config/settings.json'
try:
    with open(path, 'r') as f:
        data = json.load(f)

    # Hash admin password
    admin_hash = bcrypt.hashpw(b'${ADMIN_PASS}', bcrypt.gensalt()).decode('utf-8')
    data['auth']['password_hash'] = admin_hash

    # Hash analyst password
    analyst_hash = bcrypt.hashpw(b'${ANALYST_PASS}', bcrypt.gensalt()).decode('utf-8')
    data['auth']['analyst_password_hash'] = analyst_hash

    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print('SUCCESS')
except Exception as e:
    print(f'ERROR: {e}')
" | grep "SUCCESS" &>/dev/null && success "Credentials synchronized successfully." || warn "Could not seed passwords automatically. Default credentials remain."

# ─────────────────────────────────────────────────────────────────────────────
# Step 8: Health Verification Loop
# ─────────────────────────────────────────────────────────────────────────────
log "Verifying health check endpoints..."

MAX_RETRIES=20
RETRY_COUNT=0
HEALTHY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:3001/api/health || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        HEALTHY=true
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    log "  Waiting for services to become healthy... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 3
done

if [ "$HEALTHY" = "true" ]; then
    success "WAF Dashboard API is HEALTHY and listening on port 3001!"
else
    warn "Health checks are slow. Check logs manually using: sudo docker compose logs -f"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Installation Complete Banner
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}=======================================================================${NC}"
echo -e "${GREEN}             CYBERSENTINEL WAF DEPLOYMENT COMPLETE!                     ${NC}"
echo -e "${GREEN}=======================================================================${NC}"
echo ""
echo -e "  🚀 ${BLUE}WAF Dashboard URL:${NC} http://localhost:3001/"
echo -e "  🔐 ${BLUE}Credentials:${NC}"
echo -e "     - ${GREEN}Administrator:${NC} admin  /  (your custom password)"
echo -e "     - ${GREEN}Security Analyst:${NC} analyst  /  (your custom password)"
echo ""
echo -e "  🌐 ${BLUE}Port Mapping Structure:${NC}"
echo -e "     - ${CYAN}Port 3001${NC} : Direct Administrative Dashboard Access (WAF-Inspected)"
echo -e "     - ${CYAN}Port 80  ${NC} : HTTP Redirector (Redirects traffic to HTTPS 443)"
echo -e "     - ${CYAN}Port 443 ${NC} : HTTPS WAF Interception Gateway proxying to your apps"
echo ""
echo -e "  For diagnostic log files, inspect: ${BLUE}./logs/nginx/${NC} and ${BLUE}./logs/modsecurity/audit/${NC}"
echo -e "${GREEN}=======================================================================${NC}"
echo ""
