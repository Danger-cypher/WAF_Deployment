#!/bin/bash
# =============================================================================
# CyberSentinel WAF — Production Configuration Update Script
# =============================================================================
# Updates existing deployment with:
#   1. Production SSL/TLS certificates
#   2. Production CORS origins
#   3. Validates and restarts services
# =============================================================================

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${BLUE}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!] WARNING:${NC} $1"; }
error() { echo -e "${RED}[x] ERROR:${NC} $1" >&2; exit 1; }
success() { echo -e "${GREEN}[+]${NC} $1"; }

clear
echo -e "${CYAN}=======================================================================${NC}"
echo -e "${CYAN}     CyberSentinel WAF — Production Configuration Tool                 ${NC}"
echo -e "${CYAN}=======================================================================${NC}"
echo ""

# Check if running from correct directory
if [ ! -f "docker-compose.yml" ]; then
    error "Please run this script from the WAF_GUI root directory"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Menu Selection
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${CYAN}What would you like to configure?${NC}"
echo ""
echo -e "  ${BLUE}[1]${NC} Update SSL/TLS Certificates"
echo -e "  ${BLUE}[2]${NC} Update CORS Origins"
echo -e "  ${BLUE}[3]${NC} Both SSL and CORS"
echo -e "  ${BLUE}[4]${NC} Exit"
echo ""
echo -n "Select option [1-4]: "
read -r MENU_CHOICE
echo ""

UPDATE_SSL=false
UPDATE_CORS=false

case "$MENU_CHOICE" in
    1) UPDATE_SSL=true ;;
    2) UPDATE_CORS=true ;;
    3) UPDATE_SSL=true; UPDATE_CORS=true ;;
    4) log "Exiting..."; exit 0 ;;
    *) error "Invalid option selected" ;;
esac

CERT_DIR="configs/nginx/ssl"
CERT_FILE="${CERT_DIR}/cybersentinel.crt"
KEY_FILE="${CERT_DIR}/cybersentinel.key"
ENV_FILE=".env"

# ─────────────────────────────────────────────────────────────────────────────
# SSL Certificate Update
# ─────────────────────────────────────────────────────────────────────────────
if [ "$UPDATE_SSL" = true ]; then
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}              SSL/TLS Certificate Update                       ${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo ""
    
    # Backup existing certificates
    if [ -f "$CERT_FILE" ]; then
        BACKUP_DIR="configs/nginx/ssl/backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp "$CERT_FILE" "$BACKUP_DIR/" 2>/dev/null || true
        cp "$KEY_FILE" "$BACKUP_DIR/" 2>/dev/null || true
        success "Existing certificates backed up to $BACKUP_DIR"
    fi
    
    echo -e "  ${BLUE}[1]${NC} Use existing certificate files (recommended for production)"
    echo -e "  ${BLUE}[2]${NC} Generate Let's Encrypt certificate (requires domain)"
    echo -e "  ${BLUE}[3]${NC} Keep current certificates"
    echo ""
    echo -n "  Select option [1-3]: "
    read -r SSL_CHOICE
    echo ""
    
    case "$SSL_CHOICE" in
        1)
            log "Using existing production certificate files..."
            echo -n "  Enter full path to certificate file (.crt/.pem): "
            read -r USER_CERT
            echo -n "  Enter full path to private key file (.key): "
            read -r USER_KEY
            
            if [ ! -f "$USER_CERT" ]; then
                error "Certificate file not found: $USER_CERT"
            fi
            
            if [ ! -f "$USER_KEY" ]; then
                error "Private key file not found: $USER_KEY"
            fi
            
            # Validate certificate and key match
            log "Validating certificate and key..."
            CERT_MODULUS=$(openssl x509 -noout -modulus -in "$USER_CERT" 2>/dev/null | openssl md5)
            KEY_MODULUS=$(openssl rsa -noout -modulus -in "$USER_KEY" 2>/dev/null | openssl md5)
            
            if [ "$CERT_MODULUS" != "$KEY_MODULUS" ]; then
                error "Certificate and private key do not match!"
            fi
            
            cp "$USER_CERT" "$CERT_FILE"
            cp "$USER_KEY" "$KEY_FILE"
            chmod 644 "$CERT_FILE"
            chmod 600 "$KEY_FILE"
            success "Production certificates installed successfully"
            
            # Display certificate details
            log "Certificate details:"
            openssl x509 -in "$CERT_FILE" -noout -subject -issuer -dates
            ;;
        2)
            log "Setting up Let's Encrypt certificate..."
            echo -n "  Enter your domain name (e.g., waf.company.com): "
            read -r DOMAIN_NAME
            echo -n "  Enter your email for renewal notifications: "
            read -r CERT_EMAIL
            
            if [ -z "$DOMAIN_NAME" ] || [ -z "$CERT_EMAIL" ]; then
                error "Domain and email are required"
            fi
            
            # Check if certbot is installed
            if ! command -v certbot &> /dev/null; then
                warn "Certbot not found. Installing..."
                if command -v apt-get &> /dev/null; then
                    sudo apt-get update && sudo apt-get install -y certbot
                elif command -v yum &> /dev/null; then
                    sudo yum install -y certbot
                else
                    error "Cannot install certbot. Please install manually: https://certbot.eff.org/"
                fi
            fi
            
            # Check if port 80 is available
            warn "Port 80 must be available for Let's Encrypt validation"
            echo -n "  Stop WAF containers temporarily? [y/N]: "
            read -r STOP_CONTAINERS
            
            if [[ "$STOP_CONTAINERS" =~ ^[Yy]$ ]]; then
                log "Stopping OpenResty container..."
                sudo docker stop waf-openresty || true
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
                
                # Set up auto-renewal reminder
                echo ""
                warn "IMPORTANT: Set up automatic certificate renewal!"
                log "Add this to your crontab (sudo crontab -e):"
                echo -e "  ${CYAN}0 3 * * * certbot renew --quiet --deploy-hook 'docker exec waf-openresty openresty -s reload'${NC}"
                echo ""
            else
                error "Let's Encrypt certificate generation failed"
            fi
            
            # Restart container if we stopped it
            if [[ "$STOP_CONTAINERS" =~ ^[Yy]$ ]]; then
                log "Starting OpenResty container..."
                sudo docker start waf-openresty
            fi
            ;;
        3)
            log "Keeping current SSL certificates"
            ;;
        *)
            error "Invalid option"
            ;;
    esac
fi

# ─────────────────────────────────────────────────────────────────────────────
# CORS Origins Update
# ─────────────────────────────────────────────────────────────────────────────
if [ "$UPDATE_CORS" = true ]; then
    echo ""
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}              CORS Origins Configuration                       ${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo ""
    
    # Show current CORS settings
    if [ -f "$ENV_FILE" ]; then
        CURRENT_CORS=$(grep "^BACKEND_CORS_ORIGINS=" "$ENV_FILE" | cut -d'=' -f2- || echo "Not set")
        log "Current CORS origins: $CURRENT_CORS"
    fi
    
    echo ""
    echo -e "  ${BLUE}[1]${NC} Configure for single production domain"
    echo -e "  ${BLUE}[2]${NC} Configure for multiple domains (manual entry)"
    echo -e "  ${BLUE}[3]${NC} Keep current settings"
    echo ""
    echo -n "  Select option [1-3]: "
    read -r CORS_CHOICE
    echo ""
    
    case "$CORS_CHOICE" in
        1)
            echo -n "  Enter production domain (e.g., waf.company.com): "
            read -r PROD_DOMAIN
            
            if [ -z "$PROD_DOMAIN" ]; then
                error "Domain cannot be empty"
            fi
            
            # Generate CORS origins for both HTTP and HTTPS
            NEW_CORS="https://${PROD_DOMAIN},http://${PROD_DOMAIN},https://${PROD_DOMAIN}:3020,http://${PROD_DOMAIN}:3020"
            
            log "Generated CORS origins:"
            echo -e "  ${CYAN}$NEW_CORS${NC}"
            echo ""
            echo -n "  Confirm update? [y/N]: "
            read -r CONFIRM
            
            if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
                sed -i "s|^BACKEND_CORS_ORIGINS=.*|BACKEND_CORS_ORIGINS=${NEW_CORS}|" "$ENV_FILE"
                success "CORS origins updated successfully"
            else
                log "Update cancelled"
            fi
            ;;
        2)
            log "Enter comma-separated origins (e.g., https://domain1.com,https://domain2.com):"
            echo -n "  Origins: "
            read -r CUSTOM_CORS
            
            if [ -z "$CUSTOM_CORS" ]; then
                error "CORS origins cannot be empty"
            fi
            
            sed -i "s|^BACKEND_CORS_ORIGINS=.*|BACKEND_CORS_ORIGINS=${CUSTOM_CORS}|" "$ENV_FILE"
            success "CORS origins updated successfully"
            ;;
        3)
            log "Keeping current CORS settings"
            ;;
        *)
            error "Invalid option"
            ;;
    esac
fi

# ─────────────────────────────────────────────────────────────────────────────
# Service Restart
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}              Apply Changes to Services                         ${NC}"
echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
echo ""

if [ "$UPDATE_SSL" = true ] || [ "$UPDATE_CORS" = true ]; then
    echo -n "  Restart services to apply changes? [y/N]: "
    read -r RESTART
    
    if [[ "$RESTART" =~ ^[Yy]$ ]]; then
        log "Restarting Docker services..."
        
        # Detect compose command
        COMPOSE_CMD=""
        if docker compose version &> /dev/null; then
            COMPOSE_CMD="docker compose"
        elif command -v docker-compose &> /dev/null; then
            COMPOSE_CMD="docker-compose"
        else
            error "Docker Compose not found"
        fi
        
        if [ "$UPDATE_SSL" = true ]; then
            log "Restarting OpenResty (SSL changes)..."
            sudo $COMPOSE_CMD restart openresty
        fi
        
        if [ "$UPDATE_CORS" = true ]; then
            log "Restarting Backend (CORS changes)..."
            sudo $COMPOSE_CMD restart backend
        fi
        
        sleep 3
        
        # Health check
        log "Verifying health status..."
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:3020/api/health || echo "000")
        
        if [ "$HTTP_CODE" = "200" ]; then
            success "Services restarted successfully and are healthy!"
        else
            warn "Services restarted but health check failed. Check logs: sudo docker compose logs -f"
        fi
    else
        warn "Changes saved but NOT applied. Restart services manually:"
        echo -e "  ${CYAN}sudo docker compose restart openresty backend${NC}"
    fi
fi

echo ""
echo -e "${GREEN}=======================================================================${NC}"
echo -e "${GREEN}             Configuration Update Complete!                             ${NC}"
echo -e "${GREEN}=======================================================================${NC}"
echo ""
echo -e "  📋 ${BLUE}Summary:${NC}"
if [ "$UPDATE_SSL" = true ]; then
    echo -e "     ✓ SSL certificates updated in ${CYAN}$CERT_DIR${NC}"
fi
if [ "$UPDATE_CORS" = true ]; then
    echo -e "     ✓ CORS origins updated in ${CYAN}$ENV_FILE${NC}"
fi
echo ""
echo -e "  🔍 ${BLUE}Verification Commands:${NC}"
echo -e "     - Check certificate: ${CYAN}openssl x509 -in $CERT_FILE -noout -dates -subject${NC}"
echo -e "     - Check CORS: ${CYAN}grep BACKEND_CORS_ORIGINS $ENV_FILE${NC}"
echo -e "     - View logs: ${CYAN}sudo docker compose logs -f openresty backend${NC}"
echo ""
echo -e "${GREEN}=======================================================================${NC}"
echo ""
