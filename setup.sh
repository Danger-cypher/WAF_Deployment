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

# Always operate relative to this script's own directory so the installer
# behaves consistently no matter where it's invoked from.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1

# ── Global Error Trap ─────────────────────────────────────────────────────────
# Trap any unexpected error and print a diagnostic message. NOTE: because we
# deliberately run without `set -e`, this trap does NOT abort the script by
# itself — most commands below are individually guarded and explicitly call
# error() (which does exit) at genuinely fatal steps. This trap exists purely
# to surface unexpected non-zero exits that aren't already handled.
trap 'echo -e "\n${YELLOW}[!] WARNING: a step failed at line ${LINENO}.${NC}" \
     "\n    The installer is continuing — review the message above." \
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

# Returns true (0) if a value is empty OR still a "CHANGE_ME*" placeholder
# left over from .env.example — used to decide whether a secret needs to be
# auto-generated.
is_unset_or_placeholder() {
    local val="$1"
    [ -z "$val" ] && return 0
    case "$val" in
        CHANGE_ME*) return 0 ;;
    esac
    return 1
}

# Check if a port is in use on the host (ignores if it is in use by our own WAF containers)
is_port_in_use() {
    local port=$1
    local in_use=1
    
    if command -v ss &>/dev/null; then
        sudo ss -tuln | grep -E -q ":$port\b"
        in_use=$?
    elif command -v netstat &>/dev/null; then
        sudo netstat -tuln | grep -E -q ":$port\b"
        in_use=$?
    else
        # Fallback to bash TCP check
        if timeout 1 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/$port" &>/dev/null; then
            in_use=0
        fi
    fi

    if [ $in_use -eq 0 ]; then
        # Check if our own running docker container is the one listening
        if command -v docker &>/dev/null; then
            local ours=$(docker ps --format '{{.Names}} {{.Ports}}' | grep -E "^waf-" | grep -q ":$port->" && echo "yes" || echo "no")
            if [ "$ours" = "yes" ]; then
                # It is our own running container, so it's not a conflict
                return 1
            fi
        fi
        return 0 # Port is in use by another application
    fi
    return 1 # Port is free
}

# Prompt the user for an alternative port or auto-select one if default port is in use
get_free_port() {
    local default_port=$1
    local port_name=$2
    local port=$default_port

    if is_port_in_use "$port"; then
        warn "Port $port (required for $port_name) is already in use by another process!"
        while true; do
            echo -e -n "${YELLOW}[?]${NC} Enter a different port for $port_name (or press ENTER to auto-find): "
            read -r user_port
            if [ -z "$user_port" ]; then
                # Auto-find a free port starting from default_port + 1
                port=$((default_port + 1))
                while is_port_in_use "$port"; do
                    port=$((port + 1))
                done
                success "Auto-selected free port: $port"
                break
            else
                # Validate user input is a valid port number
                if [[ "$user_port" =~ ^[0-9]+$ ]] && [ "$user_port" -le 65535 ] && [ "$user_port" -gt 0 ]; then
                    if is_port_in_use "$user_port"; then
                        warn "Port $user_port is also in use! Please try another one."
                    else
                        port=$user_port
                        break
                    fi
                else
                    warn "Invalid port number. Must be between 1 and 65535."
                fi
            fi
        done
    fi
    echo "$port"
}

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
        (sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg lsb-release) \
            || error "Failed to install Docker prerequisite packages. Check network access and re-run."
        sudo mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg \
            || error "Failed to fetch/install Docker's GPG signing key."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        (sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin) \
            || error "Failed to install Docker Engine packages."
    else
        error "Supported package manager (apt-get) not found. Please install Docker manually."
    fi

    if ! command -v docker &> /dev/null; then
        error "Docker installation appears to have failed (docker command still not found). Please install Docker manually and re-run this script."
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
        (sudo apt-get update && sudo apt-get install -y docker-compose-plugin) \
            || error "Failed to install Docker Compose plugin."
        if docker compose version &> /dev/null; then
            COMPOSE_CMD="docker compose"
        else
            error "Docker Compose installation appears to have failed. Please install manually."
        fi
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
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
INTERNAL_ALERT_TRIGGER_KEY=
WAF_SSO_SECRET=
SIEM_JWKS_URL=
BACKEND_CORS_ORIGINS=http://localhost:3020,http://127.0.0.1:3020
GEOIP_DATA_DIR=/etc/nginx/geoip
CLICKHOUSE_HOST=waf-clickhouse
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=wafuser
CLICKHOUSE_PASSWORD=
CLICKHOUSE_DB=cybersentinel
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

# Calculate dynamic CPU limits and reservations based on detected cores
# OpenResty WAF can scale to utilize all host cores during traffic spikes
OPENRESTY_CPU_LIMIT=$(python3 -c "print(round(max(1.0, float($CORES)), 1))")
OPENRESTY_CPU_RESERVE=$(python3 -c "print(round(max(0.25, $CORES * 0.25), 2))")

# Backend application (up to 75% of host cores, minimum 1)
BACKEND_CPU_LIMIT=$(python3 -c "print(round(max(1.0, $CORES * 0.75), 1))")
BACKEND_CPU_RESERVE=$(python3 -c "print(round(max(0.25, $CORES * 0.15), 2))")

# ML Engine (up to 75% of host cores, minimum 1)
ML_CPU_LIMIT=$BACKEND_CPU_LIMIT
ML_CPU_RESERVE=$BACKEND_CPU_RESERVE

# Redis cache (low overhead, up to 25% of host cores, minimum 0.5)
REDIS_CPU_LIMIT=$(python3 -c "print(round(max(0.5, $CORES * 0.25), 1))")
REDIS_CPU_RESERVE=$(python3 -c "print(round(max(0.1, $CORES * 0.05), 2))")

# Frontend SPA server (low overhead, up to 25% of host cores, minimum 0.5)
FRONTEND_CPU_LIMIT=$REDIS_CPU_LIMIT
FRONTEND_CPU_RESERVE=$REDIS_CPU_RESERVE


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

# Load existing ports or default them
DASHBOARD_PORT=$(grep -E "^DASHBOARD_PORT=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || echo "")
HTTP_PORT=$(grep -E "^HTTP_PORT=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || echo "")
HTTPS_PORT=$(grep -E "^HTTPS_PORT=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || echo "")
CLICKHOUSE_HOST_PORT=$(grep -E "^CLICKHOUSE_HOST_PORT=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || echo "")

[ -z "$DASHBOARD_PORT" ] && DASHBOARD_PORT=3020
[ -z "$HTTP_PORT" ] && HTTP_PORT=80
[ -z "$HTTPS_PORT" ] && HTTPS_PORT=443
[ -z "$CLICKHOUSE_HOST_PORT" ] && CLICKHOUSE_HOST_PORT=8123

log "Checking WAF port availability on the host..."
DASHBOARD_PORT=$(get_free_port "$DASHBOARD_PORT" "WAF Dashboard")
HTTP_PORT=$(get_free_port "$HTTP_PORT" "HTTP gateway")
HTTPS_PORT=$(get_free_port "$HTTPS_PORT" "HTTPS WAF gateway")
CLICKHOUSE_HOST_PORT=$(get_free_port "$CLICKHOUSE_HOST_PORT" "ClickHouse HTTP API")

# Remove existing resource configuration keys from .env to avoid duplicates
for key in BACKEND_CPU_LIMIT BACKEND_CPU_RESERVE BACKEND_MEM_LIMIT BACKEND_MEM_RESERVE \
           ML_CPU_LIMIT ML_CPU_RESERVE ML_MEM_LIMIT ML_MEM_RESERVE \
           REDIS_CPU_LIMIT REDIS_CPU_RESERVE REDIS_MEM_LIMIT REDIS_MEM_RESERVE \
           OPENRESTY_CPU_LIMIT OPENRESTY_CPU_RESERVE OPENRESTY_MEM_LIMIT OPENRESTY_MEM_RESERVE \
           FRONTEND_CPU_LIMIT FRONTEND_CPU_RESERVE FRONTEND_MEM_LIMIT FRONTEND_MEM_RESERVE \
           DASHBOARD_PORT HTTP_PORT HTTPS_PORT CLICKHOUSE_HOST_PORT; do
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

# Confirmed Free Ports Configuration
DASHBOARD_PORT=$DASHBOARD_PORT
HTTP_PORT=$HTTP_PORT
HTTPS_PORT=$HTTPS_PORT
CLICKHOUSE_HOST_PORT=$CLICKHOUSE_HOST_PORT
EOF

# Load existing environment variables
# Set default values if not defined, empty, or still a CHANGE_ME placeholder
REDIS_PW=$(grep -E "^REDIS_PASSWORD=" "$ENV_FILE" | cut -d'=' -f2- || echo "")
JWT_KEY=$(grep -E "^JWT_SECRET_KEY=" "$ENV_FILE" | cut -d'=' -f2- || echo "")
CH_PW=$(grep -E "^CLICKHOUSE_PASSWORD=" "$ENV_FILE" | cut -d'=' -f2- || echo "")
INTERNAL_KEY=$(grep -E "^INTERNAL_ALERT_TRIGGER_KEY=" "$ENV_FILE" | cut -d'=' -f2- || echo "")
SSO_SECRET=$(grep -E "^WAF_SSO_SECRET=" "$ENV_FILE" | cut -d'=' -f2- || echo "")
JWKS_URL=$(grep -E "^SIEM_JWKS_URL=" "$ENV_FILE" | cut -d'=' -f2- || echo "")
CORS_ORIGINS=$(grep -E "^BACKEND_CORS_ORIGINS=" "$ENV_FILE" | cut -d'=' -f2- || echo "")

if is_unset_or_placeholder "$REDIS_PW"; then
    log "Generating cryptographically secure password for Redis..."
    # Generate random 32-char hex string
    REDIS_PW=$(openssl rand -hex 16)
    # Replace in .env
    sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${REDIS_PW}|" "$ENV_FILE"
fi

if is_unset_or_placeholder "$JWT_KEY"; then
    log "Generating secure JWT signing key..."
    JWT_KEY=$(openssl rand -hex 16)
    sed -i "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${JWT_KEY}|" "$ENV_FILE"
fi

if is_unset_or_placeholder "$CH_PW"; then
    log "Generating cryptographically secure password for ClickHouse..."
    CH_PW=$(openssl rand -hex 32)
    sed -i "s|^CLICKHOUSE_PASSWORD=.*|CLICKHOUSE_PASSWORD=${CH_PW}|" "$ENV_FILE"
fi

if is_unset_or_placeholder "$INTERNAL_KEY"; then
    log "Generating secure internal service-to-service alert trigger key..."
    # Shared secret used by the ml-engine container to authenticate its
    # POST /alerts/trigger calls to the backend — must be identical for
    # both containers, which is guaranteed since both read it from this
    # same .env file via docker-compose.
    INTERNAL_KEY=$(openssl rand -hex 32)
    if grep -q "^INTERNAL_ALERT_TRIGGER_KEY=" "$ENV_FILE"; then
        sed -i "s|^INTERNAL_ALERT_TRIGGER_KEY=.*|INTERNAL_ALERT_TRIGGER_KEY=${INTERNAL_KEY}|" "$ENV_FILE"
    else
        echo "INTERNAL_ALERT_TRIGGER_KEY=${INTERNAL_KEY}" >> "$ENV_FILE"
    fi
fi

if is_unset_or_placeholder "$SSO_SECRET"; then
    # This is OUR half of the SIEM SSO shared secret (HS256 phase) — safe
    # to generate ourselves since only WE need to know it until we hand
    # it to the SIEM team (see the SSO summary printed at the end of this
    # script). Unlike the JWKS URL below, there's nothing to ask the user
    # for here.
    log "Generating SIEM SSO shared secret (WAF_SSO_SECRET)..."
    SSO_SECRET=$(openssl rand -hex 32)
    if grep -q "^WAF_SSO_SECRET=" "$ENV_FILE"; then
        sed -i "s|^WAF_SSO_SECRET=.*|WAF_SSO_SECRET=${SSO_SECRET}|" "$ENV_FILE"
    else
        echo "WAF_SSO_SECRET=${SSO_SECRET}" >> "$ENV_FILE"
    fi
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
        CORS_ORIGINS="https://${PROD_DOMAIN},http://${PROD_DOMAIN},https://${PROD_DOMAIN}:${DASHBOARD_PORT},http://${PROD_DOMAIN}:${DASHBOARD_PORT}"
        log "Production CORS configured for: $PROD_DOMAIN"
    else
        # Local development deployment
        CORS_ORIGINS="http://localhost:${DASHBOARD_PORT},http://127.0.0.1:${DASHBOARD_PORT},https://localhost,https://127.0.0.1"
        log "Development CORS configured for localhost"
    fi
    
    sed -i "s|^BACKEND_CORS_ORIGINS=.*|BACKEND_CORS_ORIGINS=${CORS_ORIGINS}|" "$ENV_FILE"
    success "CORS origins saved to $ENV_FILE"
else
    # Update existing CORS_ORIGINS to ensure the correct dashboard port is configured
    CORS_ORIGINS=$(echo "$CORS_ORIGINS" | sed -E "s/:(3020|3001|[0-9]+)\b/:${DASHBOARD_PORT}/g")
    sed -i "s|^BACKEND_CORS_ORIGINS=.*|BACKEND_CORS_ORIGINS=${CORS_ORIGINS}|" "$ENV_FILE"
fi

# ── SIEM SSO Configuration ────────────────────────────────────────────────────
# WAF_SSO_SECRET was auto-generated above — that's fine, it's our half of a
# shared secret and nobody outside this deployment needs to have chosen it.
# SIEM_JWKS_URL is different: it's issued BY the SIEM team (their RS256
# key-publishing endpoint) and doesn't exist until they've onboarded this
# deployment, so we deliberately ASK for it here instead of generating or
# guessing a value — there's nothing to generate, and defaulting it to
# something would silently disable RS256 without the operator noticing.
# Leaving it blank is fine: the exchange endpoint stays on HS256 (using the
# secret generated above) until this is filled in and the containers are
# rebuilt.
if [ -z "$JWKS_URL" ]; then
    echo ""
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}                 SIEM SSO Configuration                        ${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo ""
    log "This deployment's SSO audience name is fixed: cybersentinel-waf"
    log "A shared HS256 secret was just generated for you — it will be printed"
    log "  at the end of this script so you can send it to your SIEM team."
    echo ""
    echo -e "  ${YELLOW}[?]${NC} SIEM JWKS URL enables the stronger RS256 verification phase."
    echo -e "      This is issued by your SIEM team, not something we can generate —"
    echo -e "      if you don't have it yet, just press ENTER and configure it later"
    echo -e "      by setting SIEM_JWKS_URL in .env and re-running:"
    echo -e "      ${CYAN}sudo ${COMPOSE_CMD} up -d --build backend${NC}"
    echo -n "  Enter SIEM JWKS URL (e.g. https://siem.company.com/api/sso/jwks.json), or press ENTER to skip: "
    read -r JWKS_URL_INPUT

    if [ -n "$JWKS_URL_INPUT" ]; then
        JWKS_URL="$JWKS_URL_INPUT"
        if grep -q "^SIEM_JWKS_URL=" "$ENV_FILE"; then
            sed -i "s|^SIEM_JWKS_URL=.*|SIEM_JWKS_URL=${JWKS_URL}|" "$ENV_FILE"
        else
            echo "SIEM_JWKS_URL=${JWKS_URL}" >> "$ENV_FILE"
        fi
        success "SIEM_JWKS_URL saved. RS256 verification will be active once containers start."
    else
        warn "SIEM_JWKS_URL skipped — SSO will run HS256-only until you add it."
    fi
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
        if wget -qO "$TEMP_TAR" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${LICENSE_KEY}&suffix=tar.gz" \
            && tar -xzf "$TEMP_TAR" -C /tmp \
            && mv /tmp/GeoLite2-Country_*/GeoLite2-Country.mmdb "$GEOIP_FILE"; then
            rm -f "$TEMP_TAR"
            success "MaxMind GeoIP Country Database downloaded successfully."
        else
            warn "MaxMind download failed. Attempting fallback mirror..."
            rm -f "$TEMP_TAR"
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

echo -n "  Enter ClickHouse username (default: wafuser): "
read -r CH_USER_INPUT
if [ -n "$CH_USER_INPUT" ]; then
    sed -i "s|^CLICKHOUSE_USER=.*|CLICKHOUSE_USER=${CH_USER_INPUT}|" "$ENV_FILE"
fi

echo -n "  Enter ClickHouse password (default: auto-generated secure key): "
read -s CH_PASS_INPUT
echo ""
if [ -n "$CH_PASS_INPUT" ]; then
    CH_PW="$CH_PASS_INPUT"
    sed -i "s|^CLICKHOUSE_PASSWORD=.*|CLICKHOUSE_PASSWORD=${CH_PW}|" "$ENV_FILE"
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
        sudo ufw allow ${HTTP_PORT}/tcp   &>/dev/null && success "  Port ${HTTP_PORT}  (HTTP)       — opened" || warn "  Failed to open port ${HTTP_PORT}"
        sudo ufw allow ${HTTPS_PORT}/tcp  &>/dev/null && success "  Port ${HTTPS_PORT} (HTTPS)      — opened" || warn "  Failed to open port ${HTTPS_PORT}"
        sudo ufw allow ${DASHBOARD_PORT}/tcp &>/dev/null && success "  Port ${DASHBOARD_PORT} (Dashboard) — opened" || warn "  Failed to open port ${DASHBOARD_PORT}"
        sudo ufw reload &>/dev/null || true
    else
        warn "  UFW is installed but inactive. No firewall rules changed."
        warn "  If you enable UFW later, manually run: sudo ufw allow ${HTTP_PORT},${HTTPS_PORT},${DASHBOARD_PORT}/tcp"
    fi
elif command -v firewall-cmd &>/dev/null; then
    log "  firewalld detected. Opening required ports..."
    sudo firewall-cmd --permanent --add-port=${HTTP_PORT}/tcp   &>/dev/null && success "  Port ${HTTP_PORT} opened" || warn "  Failed to open port ${HTTP_PORT}"
    sudo firewall-cmd --permanent --add-port=${HTTPS_PORT}/tcp  &>/dev/null && success "  Port ${HTTPS_PORT} opened" || warn "  Failed to open port ${HTTPS_PORT}"
    sudo firewall-cmd --permanent --add-port=${DASHBOARD_PORT}/tcp &>/dev/null && success "  Port ${DASHBOARD_PORT} opened" || warn "  Failed to open port ${DASHBOARD_PORT}"
    sudo firewall-cmd --reload &>/dev/null || true
else
    warn "  No known firewall manager (ufw/firewalld) found. Ensure ports ${HTTP_PORT}, ${HTTPS_PORT}, ${DASHBOARD_PORT} are open manually."
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
sudo $COMPOSE_CMD build || error "Docker Compose build failed. Check the output above for details."
sudo $COMPOSE_CMD up -d || error "Failed to start containers. Check the output above, then run: sudo docker compose logs -f"

# ─────────────────────────────────────────────────────────────────────────────
# Step 8: Post-Boot Database and Credential Sync
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
#
# Credentials are passed via `docker exec -e` (process environment) rather than
# interpolated into the Python source string, so passwords containing quotes,
# backslashes, or other shell/Python-special characters can't break out of the
# literal or inject code.
sudo docker exec -t \
    -e SETUP_ADMIN_PASS="${ADMIN_PASS}" \
    -e SETUP_ANALYST_PASS="${ANALYST_PASS}" \
    -e SETUP_ABUSEIPDB_KEY="${ABUSEIPDB_KEY}" \
    waf-backend python3 -c "
import json
import os
import bcrypt

path = '/app/app/config/settings.json'
try:
    with open(path, 'r') as f:
        data = json.load(f)

    # Hash admin password
    admin_hash = bcrypt.hashpw(os.environb[b'SETUP_ADMIN_PASS'], bcrypt.gensalt()).decode('utf-8')
    data['auth']['password_hash'] = admin_hash

    # Hash analyst password
    analyst_hash = bcrypt.hashpw(os.environb[b'SETUP_ANALYST_PASS'], bcrypt.gensalt()).decode('utf-8')
    data['auth']['analyst_password_hash'] = analyst_hash

    # Save AbuseIPDB key if specified during setup
    abuse_key = os.environ.get('SETUP_ABUSEIPDB_KEY', '').strip()
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

# Run one-time database migration from SQLite to ClickHouse
log "Running SQLite to ClickHouse data migration script..."
sudo docker exec waf-backend python3 /app/scripts/migrate_sqlite_to_clickhouse.py \
    --ch-host waf-clickhouse \
    --ch-user wafuser \
    --ch-password "${CH_PW}" \
    --ch-db cybersentinel || warn "ClickHouse database migration failed to run automatically."

# ── SMTP Alert Channel Seeding ────────────────────────────────────────────────
# If SMTP was configured interactively, register it as an alert channel via the
# backend API so it appears in the dashboard immediately after install.
if [ -n "${SMTP_HOST:-}" ] && [ -n "${SMTP_TO:-}" ]; then
    log "Registering SMTP email alert channel in the WAF alert system..."
    sleep 2  # brief pause to ensure API is fully ready

    # Obtain a session cookie from the login endpoint. --data-urlencode ensures
    # special characters in the password can't corrupt the form body.
    LOGIN_RESP=$(curl -sc /tmp/waf_setup.cookies -s -X POST \
        "http://localhost:${DASHBOARD_PORT}/api/auth/login" \
        --data-urlencode "username=admin" \
        --data-urlencode "password=${ADMIN_PASS}" 2>/dev/null || echo "")

    if echo "$LOGIN_RESP" | grep -q "successful"; then
        XSRF_TOKEN=$(grep XSRF /tmp/waf_setup.cookies 2>/dev/null | awk '{print $7}' || echo "")
        # Built with python3's json.dumps (via env vars, not string interpolation)
        # so special characters (quotes, backslashes) in any SMTP field can't
        # corrupt or inject into the JSON payload.
        CHANNEL_PAYLOAD=$(SMTP_HOST="$SMTP_HOST" SMTP_PORT="$SMTP_PORT" SMTP_USERNAME="$SMTP_USERNAME" \
            SMTP_PASSWORD="$SMTP_PASSWORD" SMTP_FROM="$SMTP_FROM" SMTP_TO="$SMTP_TO" python3 -c "
import json, os
print(json.dumps({
    'name': 'Setup Email Alerts',
    'channel_type': 'email',
    'enabled': True,
    'config': {
        'smtp_host': os.environ['SMTP_HOST'],
        'smtp_port': int(os.environ['SMTP_PORT']),
        'username': os.environ['SMTP_USERNAME'],
        'password': os.environ['SMTP_PASSWORD'],
        'from_addr': os.environ['SMTP_FROM'],
        'to_addrs': [os.environ['SMTP_TO']],
        'use_tls': True,
        'use_ssl': False,
    },
}))
")
        CREATE_RESP=$(curl -s -b /tmp/waf_setup.cookies \
            -H "Content-Type: application/json" \
            -H "X-XSRF-TOKEN: ${XSRF_TOKEN}" \
            -X POST "http://localhost:${DASHBOARD_PORT}/api/alerts/channels" \
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
# Step 9: Health Verification Loop
# ─────────────────────────────────────────────────────────────────────────────
log "Verifying health check endpoints..."

MAX_RETRIES=20
RETRY_COUNT=0
HEALTHY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://localhost:${DASHBOARD_PORT}/api/health" || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        HEALTHY=true
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    log "  Waiting for services to become healthy... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 3
done

if [ "$HEALTHY" = "true" ]; then
    success "WAF Dashboard API is HEALTHY and listening on port ${DASHBOARD_PORT}!"
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
echo -e "  🚀 ${BLUE}WAF Dashboard URL:${NC} http://${SERVER_IP}:${DASHBOARD_PORT}/"
echo -e "  📊 ${BLUE}ClickHouse Play Console:${NC} http://localhost:${CLICKHOUSE_HOST_PORT}/play"
echo -e "     - ${YELLOW}Note:${NC} To connect, open an SSH Tunnel from your local terminal:"
echo -e "       ${CYAN}ssh -L ${CLICKHOUSE_HOST_PORT}:127.0.0.1:${CLICKHOUSE_HOST_PORT} soc@${SERVER_IP}${NC}"
echo -e "  🔐 ${BLUE}Credentials:${NC}"
echo -e "     - ${GREEN}Administrator:${NC} admin  /  (your custom password)"
echo -e "     - ${GREEN}Security Analyst:${NC} analyst  /  (your custom password)"
echo -e "     - ${GREEN}ClickHouse Database:${NC} Username: (custom username, default: wafuser) / Password: (check your .env file)"
echo ""
echo -e "  🔗 ${BLUE}SIEM SSO Setup${NC} (send this section to your SIEM team to onboard this deployment):"
echo -e "     - ${CYAN}Audience name:${NC}      cybersentinel-waf"
echo -e "     - ${CYAN}Exchange endpoint:${NC}  https://${SERVER_IP}/api/auth/sso/exchange  (or via the dashboard port: http://${SERVER_IP}:${DASHBOARD_PORT}/api/auth/sso/exchange)"
echo -e "     - ${CYAN}Landing page:${NC}       https://${SERVER_IP}/auth/sso"
echo -e "     - ${CYAN}Shared secret (WAF_SSO_SECRET, HS256 phase):${NC} ${SSO_SECRET}"
if [ -n "${JWKS_URL:-}" ]; then
    echo -e "     - ${CYAN}SIEM JWKS URL configured:${NC} ${JWKS_URL} — RS256 verification is active."
else
    echo -e "     - ${YELLOW}SIEM JWKS URL not set yet${NC} — SSO is running HS256-only. Add SIEM_JWKS_URL to"
    echo -e "       .env once your SIEM team provides it, then: sudo ${COMPOSE_CMD} up -d --build backend"
fi
echo -e "     ${YELLOW}⚠  The shared secret above is a credential — send it to your SIEM contact${NC}"
echo -e "     ${YELLOW}   over a secure channel, not plaintext email/chat, and never commit it.${NC}"
echo ""
echo -e "  🌐 ${BLUE}Port Mapping Structure:${NC}"
echo -e "     - ${CYAN}Port ${DASHBOARD_PORT}${NC} : Direct Administrative Dashboard Access (WAF-Inspected)"
echo -e "     - ${CYAN}Port ${HTTP_PORT}  ${NC} : HTTP Redirector (Redirects traffic to HTTPS ${HTTPS_PORT})"
echo -e "     - ${CYAN}Port ${HTTPS_PORT} ${NC} : HTTPS WAF Interception Gateway proxying to your apps"
echo -e "     - ${CYAN}Port ${CLICKHOUSE_HOST_PORT}${NC} : ClickHouse HTTP Interface (Bound to 127.0.0.1 for security)"
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
