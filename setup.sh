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

# Use set -uo (not -e) so we control error handling explicitly with our own trap
set -uo pipefail

# ── Global Error Trap ─────────────────────────────────────────────────────────
# Trap any unexpected error and print a user-friendly message instead of
# exiting silently. The installer will still abort, but the admin will know
# exactly where it failed and what to check.
trap 'echo -e "\n${RED}[x] INSTALLER FAILED at line ${LINENO}.${NC}" \
     "\n    Check the error above and re-run setup.sh after fixing the issue." \
     "\n    Tip: Run: sudo docker compose logs -f   to inspect container state." >&2' ERR

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

# ── Dynamic Resource Scaling Detection ───────────────────────────────────────
log "Auto-detecting server resources to optimize WAF resource limits..."
CORES=$(nproc 2>/dev/null || echo "1")
log "  CPU Cores detected: $CORES"

# Total Memory in KB
MEM_TOTAL_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "4194304")
MEM_TOTAL_MB=$((MEM_TOTAL_KB / 1024))
log "  Total Memory detected: ${MEM_TOTAL_MB}MB"

# Calculate CPU limits and reservations based on detected cores
if [ "$CORES" -le 1 ]; then
    BACKEND_CPU_LIMIT="1.0"
    BACKEND_CPU_RESERVE="0.1"
    ML_CPU_LIMIT="1.0"
    ML_CPU_RESERVE="0.1"
    REDIS_CPU_LIMIT="1.0"
    REDIS_CPU_RESERVE="0.1"
    OPENRESTY_CPU_LIMIT="1.0"
    OPENRESTY_CPU_RESERVE="0.1"
    FRONTEND_CPU_LIMIT="1.0"
    FRONTEND_CPU_RESERVE="0.1"
elif [ "$CORES" -eq 2 ]; then
    BACKEND_CPU_LIMIT="1.0"
    BACKEND_CPU_RESERVE="0.2"
    ML_CPU_LIMIT="1.0"
    ML_CPU_RESERVE="0.2"
    REDIS_CPU_LIMIT="1.0"
    REDIS_CPU_RESERVE="0.2"
    OPENRESTY_CPU_LIMIT="1.0"
    OPENRESTY_CPU_RESERVE="0.2"
    FRONTEND_CPU_LIMIT="0.5"
    FRONTEND_CPU_RESERVE="0.1"
elif [ "$CORES" -eq 4 ]; then
    BACKEND_CPU_LIMIT="2.0"
    BACKEND_CPU_RESERVE="0.5"
    ML_CPU_LIMIT="2.0"
    ML_CPU_RESERVE="1.0"
    REDIS_CPU_LIMIT="1.0"
    REDIS_CPU_RESERVE="0.25"
    OPENRESTY_CPU_LIMIT="2.0"
    OPENRESTY_CPU_RESERVE="0.5"
    FRONTEND_CPU_LIMIT="0.5"
    FRONTEND_CPU_RESERVE="0.1"
else
    # 8+ cores
    BACKEND_CPU_LIMIT="4.0"
    BACKEND_CPU_RESERVE="1.0"
    ML_CPU_LIMIT="4.0"
    ML_CPU_RESERVE="1.0"
    REDIS_CPU_LIMIT="2.0"
    REDIS_CPU_RESERVE="0.5"
    OPENRESTY_CPU_LIMIT="4.0"
    OPENRESTY_CPU_RESERVE="1.0"
    FRONTEND_CPU_LIMIT="1.0"
    FRONTEND_CPU_RESERVE="0.2"
fi

# Calculate Memory limits and reservations based on total memory
if [ "$MEM_TOTAL_MB" -lt 3000 ]; then
    # < 3GB RAM (Small Server)
    BACKEND_MEM_LIMIT="512M"
    BACKEND_MEM_RESERVE="128M"
    ML_MEM_LIMIT="1G"
    ML_MEM_RESERVE="256M"
    REDIS_MEM_LIMIT="256M"
    REDIS_MEM_RESERVE="64M"
    OPENRESTY_MEM_LIMIT="512M"
    OPENRESTY_MEM_RESERVE="128M"
    FRONTEND_MEM_LIMIT="128M"
    FRONTEND_MEM_RESERVE="32M"
elif [ "$MEM_TOTAL_MB" -lt 15000 ]; then
    # 3GB - 15GB RAM (Standard Server)
    BACKEND_MEM_LIMIT="1G"
    BACKEND_MEM_RESERVE="256M"
    ML_MEM_LIMIT="2G"
    ML_MEM_RESERVE="512M"
    REDIS_MEM_LIMIT="512M"
    REDIS_MEM_RESERVE="128M"
    OPENRESTY_MEM_LIMIT="1G"
    OPENRESTY_MEM_RESERVE="256M"
    FRONTEND_MEM_LIMIT="256M"
    FRONTEND_MEM_RESERVE="64M"
else
    # 15GB+ RAM (High-Performance Server)
    BACKEND_MEM_LIMIT="2G"
    BACKEND_MEM_RESERVE="512M"
    ML_MEM_LIMIT="4G"
    ML_MEM_RESERVE="1G"
    REDIS_MEM_LIMIT="1G"
    REDIS_MEM_RESERVE="256M"
    OPENRESTY_MEM_LIMIT="2G"
    OPENRESTY_MEM_RESERVE="512M"
    FRONTEND_MEM_LIMIT="512M"
    FRONTEND_MEM_RESERVE="128M"
fi

log "  Configured CPU Limit: Backend=$BACKEND_CPU_LIMIT, ML=$ML_CPU_LIMIT, OpenResty=$OPENRESTY_CPU_LIMIT"
log "  Configured Mem Limit: Backend=$BACKEND_MEM_LIMIT, ML=$ML_MEM_LIMIT, OpenResty=$OPENRESTY_MEM_LIMIT"

# Remove existing resource configuration keys from .env to avoid duplicates
for key in BACKEND_CPU_LIMIT BACKEND_CPU_RESERVE BACKEND_MEM_LIMIT BACKEND_MEM_RESERVE \
           ML_CPU_LIMIT ML_CPU_RESERVE ML_MEM_LIMIT ML_MEM_RESERVE \
           REDIS_CPU_LIMIT REDIS_CPU_RESERVE REDIS_MEM_LIMIT REDIS_MEM_RESERVE \
           OPENRESTY_CPU_LIMIT OPENRESTY_CPU_RESERVE OPENRESTY_MEM_LIMIT OPENRESTY_MEM_RESERVE \
           FRONTEND_CPU_LIMIT FRONTEND_CPU_RESERVE FRONTEND_MEM_LIMIT FRONTEND_MEM_RESERVE; do
    sed -i "/^$key=/d" "$ENV_FILE" 2>/dev/null || true
done

# Append calculated config to .env
cat >> "$ENV_FILE" <<EOF

# Dynamic Resource Auto-Scaling Settings (Auto-generated by setup.sh)
BACKEND_CPU_LIMIT=$BACKEND_CPU_LIMIT
BACKEND_CPU_RESERVE=$BACKEND_CPU_RESERVE
BACKEND_MEM_LIMIT=$BACKEND_MEM_LIMIT
BACKEND_MEM_RESERVE=$BACKEND_MEM_RESERVE
ML_CPU_LIMIT=$ML_CPU_LIMIT
ML_CPU_RESERVE=$ML_CPU_RESERVE
ML_MEM_LIMIT=$ML_MEM_LIMIT
ML_MEM_RESERVE=$ML_MEM_RESERVE
REDIS_CPU_LIMIT=$REDIS_CPU_LIMIT
REDIS_CPU_RESERVE=$REDIS_CPU_RESERVE
REDIS_MEM_LIMIT=$REDIS_MEM_LIMIT
REDIS_MEM_RESERVE=$REDIS_MEM_RESERVE
OPENRESTY_CPU_LIMIT=$OPENRESTY_CPU_LIMIT
OPENRESTY_CPU_RESERVE=$OPENRESTY_CPU_RESERVE
OPENRESTY_MEM_LIMIT=$OPENRESTY_MEM_LIMIT
OPENRESTY_MEM_RESERVE=$OPENRESTY_MEM_RESERVE
FRONTEND_CPU_LIMIT=$FRONTEND_CPU_LIMIT
FRONTEND_CPU_RESERVE=$FRONTEND_CPU_RESERVE
FRONTEND_MEM_LIMIT=$FRONTEND_MEM_LIMIT
FRONTEND_MEM_RESERVE=$FRONTEND_MEM_RESERVE
EOF

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

# ── ASN Database (for ISP/Organization attribution) ──────────────────────────
ASN_FILE="${GEOIP_DIR}/GeoLite2-ASN.mmdb"
if [ ! -f "$ASN_FILE" ]; then
    log "Downloading GeoLite2-ASN database (enables ISP/Organization tracking)..."
    if [ -n "${LICENSE_KEY:-}" ]; then
        TEMP_TAR_ASN="/tmp/geoip_asn.tar.gz"
        if wget -qO "$TEMP_TAR_ASN" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${LICENSE_KEY}&suffix=tar.gz" 2>/dev/null; then
            tar -xzf "$TEMP_TAR_ASN" -C /tmp
            mv /tmp/GeoLite2-ASN_*/GeoLite2-ASN.mmdb "$ASN_FILE" 2>/dev/null || true
            rm -f "$TEMP_TAR_ASN"
            success "MaxMind GeoIP ASN Database downloaded successfully."
        else
            warn "MaxMind ASN download failed. Attempting public mirror fallback..."
        fi
    fi
    # Fallback to public mirror if MaxMind key was not used or download failed
    if [ ! -f "$ASN_FILE" ]; then
        if wget -qO "$ASN_FILE" "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb" 2>/dev/null; then
            success "Fallback GeoIP ASN Database downloaded successfully."
        else
            warn "Failed to download GeoIP ASN database. ISP/Organization metrics will be disabled."
            touch "$ASN_FILE" || true
        fi
    fi
else
    success "GeoIP ASN database already present: $ASN_FILE"
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

echo -e -n "  ${YELLOW}[?]${NC} Enter AbuseIPDB API Key (press ENTER to skip/configure later): "
read -r ABUSEIPDB_KEY

# ── SMTP Email Alert Configuration ───────────────────────────────────────────
echo ""
echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}               Email Alert Configuration (SMTP)               ${NC}"
echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
echo -e "  Configure SMTP to send email alerts when attacks are detected."
echo -e "  ${BLUE}Common SMTP Hosts:${NC} smtp.gmail.com (587), smtp.office365.com (587)"
echo ""
echo -n "  Enter SMTP Host (press ENTER to skip/configure later): "
read -r SMTP_HOST

SMTP_PORT="587"
SMTP_USERNAME=""
SMTP_PASSWORD=""
SMTP_FROM=""
SMTP_TO=""

if [ -n "$SMTP_HOST" ]; then
    echo -n "  Enter SMTP Port (default: 587): "
    read -r SMTP_PORT_INPUT
    if [ -n "$SMTP_PORT_INPUT" ]; then SMTP_PORT="$SMTP_PORT_INPUT"; fi

    echo -n "  Enter SMTP Username / Email: "
    read -r SMTP_USERNAME

    echo -n "  Enter SMTP Password: "
    read -s SMTP_PASSWORD
    echo ""

    echo -n "  Enter From Address (e.g. waf@company.com): "
    read -r SMTP_FROM

    echo -n "  Enter Alert Recipient Email (e.g. security-team@company.com): "
    read -r SMTP_TO

    success "SMTP configuration collected. Will be saved after containers start."
else
    warn "SMTP skipped. You can configure email alerts later from the WAF Dashboard → Alerts tab."
fi


# ── Step 5b: Initialize OWASP Core Rule Set on Host ────────────────────────
CRS_DIR="configs/nginx/modsec/coreruleset"
if [ ! -f "$CRS_DIR/crs-setup.conf" ]; then
    log "OWASP Core Rule Set not found on host. Downloading and extracting latest release..."
    mkdir -p "$CRS_DIR"
    
    # Fetch latest release tag from GitHub API
    CRS_LATEST=$(curl -sf https://api.github.com/repos/coreruleset/coreruleset/releases/latest \
        | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/' || echo "v4.0.0")
    log "  Latest Core Rule Set release detected: ${CRS_LATEST}"
    
    # Download and extract to temporary directory
    curl -sL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_LATEST}.tar.gz" -o /tmp/crs.tar.gz
    tar -xzf /tmp/crs.tar.gz -C /tmp
    
    # Move files to config directory
    CRS_TEMP_DIR=$(ls /tmp | grep coreruleset- | head -1)
    if [ -n "$CRS_TEMP_DIR" ]; then
        # Copy contents of extracted folder to coreruleset directory
        cp -r /tmp/${CRS_TEMP_DIR}/* "$CRS_DIR/"
        # Copy example configuration if crs-setup.conf doesn't exist
        if [ ! -f "$CRS_DIR/crs-setup.conf" ]; then
            cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf" 2>/dev/null || true
        fi
        success "OWASP Core Rule Set successfully installed to $CRS_DIR"
    else
        error "Failed to extract OWASP Core Rule Set. Check internet connection."
    fi
    
    # Clean up temp files
    rm -rf /tmp/crs.tar.gz /tmp/coreruleset-*
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Firewall Configuration
# ─────────────────────────────────────────────────────────────────────────────
log "Configuring host firewall rules for WAF service ports..."
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1 || echo "inactive")
    if echo "$UFW_STATUS" | grep -qi "active"; then
        log "  UFW firewall is active. Opening required ports..."
        sudo ufw allow 80/tcp   &>/dev/null && success "  Port 80  (HTTP)       — opened" || warn "  Failed to open port 80"
        sudo ufw allow 443/tcp  &>/dev/null && success "  Port 443 (HTTPS)      — opened" || warn "  Failed to open port 443"
        sudo ufw allow 3001/tcp &>/dev/null && success "  Port 3001 (Dashboard) — opened" || warn "  Failed to open port 3001"
        sudo ufw reload &>/dev/null || true
    else
        warn "  UFW is installed but inactive. No firewall rules changed."
        warn "  If you enable UFW later, manually run: sudo ufw allow 80,443,3001/tcp"
    fi
elif command -v firewall-cmd &>/dev/null; then
    log "  firewalld detected. Opening required ports..."
    sudo firewall-cmd --permanent --add-port=80/tcp   &>/dev/null && success "  Port 80 opened" || warn "  Failed to open port 80"
    sudo firewall-cmd --permanent --add-port=443/tcp  &>/dev/null && success "  Port 443 opened" || warn "  Failed to open port 443"
    sudo firewall-cmd --permanent --add-port=3001/tcp &>/dev/null && success "  Port 3001 opened" || warn "  Failed to open port 3001"
    sudo firewall-cmd --reload &>/dev/null || true
else
    warn "  No known firewall manager (ufw/firewalld) found. Ensure ports 80, 443, 3001 are open manually."
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Docker Compose Build & Deploy
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

    # Save AbuseIPDB key if specified during setup
    abuse_key = '${ABUSEIPDB_KEY}'.strip()
    if abuse_key:
        if 'abuseipdb' not in data:
            data['abuseipdb'] = {}
        data['abuseipdb']['enabled'] = True
        data['abuseipdb']['api_key'] = abuse_key

    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print('SUCCESS')
except Exception as e:
    print(f'ERROR: {e}')
" | grep "SUCCESS" &>/dev/null && success "Credentials synchronized successfully." || warn "Could not seed passwords automatically. Default credentials remain."

# ── SMTP Alert Channel Seeding ────────────────────────────────────────────────
# If SMTP was configured interactively, register it as an alert channel via the
# backend API so it appears in the dashboard immediately after install.
if [ -n "${SMTP_HOST:-}" ] && [ -n "${SMTP_TO:-}" ]; then
    log "Registering SMTP email alert channel in the WAF alert system..."
    sleep 2  # brief pause to ensure API is fully ready

    # Obtain a session cookie from the login endpoint
    LOGIN_RESP=$(curl -sc /tmp/waf_setup.cookies -s -X POST \
        "http://localhost:3001/api/auth/login" \
        -d "username=admin&password=${ADMIN_PASS}" 2>/dev/null || echo "")

    if echo "$LOGIN_RESP" | grep -q "successful"; then
        XSRF_TOKEN=$(grep XSRF /tmp/waf_setup.cookies 2>/dev/null | awk '{print $7}' || echo "")
        CHANNEL_PAYLOAD=$(cat <<PAYLOAD
{
  "name": "Setup Email Alerts",
  "channel_type": "email",
  "enabled": true,
  "config": {
    "smtp_host": "${SMTP_HOST}",
    "smtp_port": ${SMTP_PORT},
    "username": "${SMTP_USERNAME}",
    "password": "${SMTP_PASSWORD}",
    "from_addr": "${SMTP_FROM}",
    "to_addrs": ["${SMTP_TO}"],
    "use_tls": true,
    "use_ssl": false
  }
}
PAYLOAD
)
        CREATE_RESP=$(curl -s -b /tmp/waf_setup.cookies \
            -H "Content-Type: application/json" \
            -H "X-XSRF-TOKEN: ${XSRF_TOKEN}" \
            -X POST "http://localhost:3001/api/alerts/channels" \
            -d "$CHANNEL_PAYLOAD" 2>/dev/null || echo "")
        
        if echo "$CREATE_RESP" | grep -q "\"id\""; then
            success "SMTP email alert channel registered successfully in the WAF dashboard!"
        else
            warn "Could not auto-register SMTP channel. Configure manually in Dashboard → Alerts & Integrations."
        fi
        rm -f /tmp/waf_setup.cookies 2>/dev/null || true
    else
        warn "Could not login to register SMTP channel automatically. Configure manually in the dashboard."
    fi
fi

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
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="localhost"
fi

echo ""
echo -e "${GREEN}=======================================================================${NC}"
echo -e "${GREEN}             CYBERSENTINEL WAF DEPLOYMENT COMPLETE!                     ${NC}"
echo -e "${GREEN}=======================================================================${NC}"
echo ""
echo -e "  🚀 ${BLUE}WAF Dashboard URL:${NC} http://${SERVER_IP}:3001/"
echo -e "  🔐 ${BLUE}Credentials:${NC}"
echo -e "     - ${GREEN}Administrator:${NC} admin  /  (your custom password)"
echo -e "     - ${GREEN}Security Analyst:${NC} analyst  /  (your custom password)"
echo ""
echo -e "  🌐 ${BLUE}Port Mapping Structure:${NC}"
echo -e "     - ${CYAN}Port 3001${NC} : Direct Administrative Dashboard Access (WAF-Inspected)"
echo -e "     - ${CYAN}Port 80  ${NC} : HTTP Redirector (Redirects traffic to HTTPS 443)"
echo -e "     - ${CYAN}Port 443 ${NC} : HTTPS WAF Interception Gateway proxying to your apps"
echo ""
echo -e "  📁 ${BLUE}Configuration Paths:${NC}"
echo -e "     - ${CYAN}Nginx Main Configs:${NC}   ./configs/nginx/"
echo -e "     - ${CYAN}Protected Apps VHosts:${NC} ./configs/nginx/sites-enabled/"
echo -e "     - ${CYAN}ModSecurity Rules:${NC}     ./configs/nginx/modsec/main.conf"
echo -e "     - ${CYAN}WAF UI Configs:${NC}        ./backend/app/config/settings.json"
echo -e "     - ${CYAN}GeoIP & SQLite Data:${NC}   ./backend/app/data/"
echo ""
echo -e "  📜 ${BLUE}Log Directories:${NC}"
echo -e "     - ${CYAN}Nginx Access & Error Logs:${NC} ./logs/nginx/"
echo -e "     - ${CYAN}ModSecurity Audit Logs:${NC}    ./logs/modsecurity/audit/"
echo -e "     - ${CYAN}WAF Dashboard API Logs:${NC}    (View via docker logs: sudo docker compose logs -f waf-backend)"
echo -e "${GREEN}=======================================================================${NC}"
echo ""
