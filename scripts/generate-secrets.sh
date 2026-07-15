#!/bin/bash
# ============================================================================
# CyberSentinel WAF - Secure Secret Generator
# ============================================================================
# This script generates cryptographically secure random secrets for production
# deployment and updates the .env file with strong values.
#
# Usage: sudo bash scripts/generate-secrets.sh
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    error "openssl is required but not installed. Please install it first."
    exit 1
fi

log "CyberSentinel WAF - Secure Secret Generator"
echo "============================================"
echo ""

# Check if .env already exists
if [ -f "$ENV_FILE" ]; then
    warn ".env file already exists!"
    read -p "Do you want to regenerate all secrets? This will BREAK existing deployments! (yes/no): " -r
    echo
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log "Aborted. No changes made."
        exit 0
    fi
    # Backup existing .env
    BACKUP_FILE="$ENV_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$ENV_FILE" "$BACKUP_FILE"
    log "Backed up existing .env to: $BACKUP_FILE"
fi

# Copy template
if [ -f "$ENV_EXAMPLE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    log "Created .env from .env.example"
else
    error ".env.example not found!"
    exit 1
fi

# Generate secrets
log "Generating cryptographically secure secrets..."
echo ""

# Generate Redis password (32 random alphanumeric characters)
REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
log "✓ Generated REDIS_PASSWORD"

# Generate JWT secret (64 character hex string)
JWT_SECRET=$(openssl rand -hex 32)
log "✓ Generated JWT_SECRET_KEY"

# Update .env file
sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" "$ENV_FILE"
sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/" "$ENV_FILE"

log "✓ Updated .env file with new secrets"
echo ""

# Display secrets (WARNING: Only for initial setup)
echo "============================================"
echo "🔐 GENERATED SECRETS (SAVE SECURELY)"
echo "============================================"
echo ""
echo "REDIS_PASSWORD=$REDIS_PASSWORD"
echo "JWT_SECRET_KEY=$JWT_SECRET"
echo ""
warn "IMPORTANT: Store these secrets in a secure password manager!"
warn "           Never commit .env to version control!"
echo ""

# Set restrictive permissions on .env
chmod 600 "$ENV_FILE"
log "✓ Set restrictive permissions (600) on .env file"
echo ""

# Next steps
echo "============================================"
echo "📋 NEXT STEPS"
echo "============================================"
echo "1. Review and update BACKEND_CORS_ORIGINS in .env"
echo "2. Change default admin/analyst passwords via dashboard"
echo "3. Review backend/app/config/settings.json for sensitive data"
echo "4. Restart all Docker containers: docker compose down && docker compose up -d"
echo ""
log "✅ Secret generation complete!"
