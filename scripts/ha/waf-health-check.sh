#!/usr/bin/env bash
# waf-health-check.sh — CyberSentinel WAF
# =============================================================================
# The vrrp_script target keepalived polls to decide which node holds the
# floating VIP (Phase B of the active-passive HA plan — see
# scripts/ha/README.md). Runs on the HOST, not inside a container: keepalived
# itself is host-level Linux HA tooling, so this has to reach the stack the
# same way an external client would — through OpenResty on the dashboard
# port, not by exec'ing into a container.
#
# Deliberately reuses the backend's existing GET /health (backend/app/routes/
# health.py) rather than inventing a new endpoint — that route already folds
# ClickHouse and SQLite connectivity into one `status` field, exactly the
# signal a failover decision needs, and it's already exempted from ML/WAF
# scoring (ml_check.lua's is_admin_request()), so this check is never itself
# at risk of being rate-limited or challenged by the WAF it's checking.
#
# Exit code convention (keepalived's vrrp_script contract): 0 = healthy,
# keep/take MASTER; non-zero = unhealthy, release the VIP to the peer.
set -euo pipefail

WAF_HEALTH_URL="${WAF_HEALTH_URL:-http://127.0.0.1:3020/api/health}"
WAF_HEALTH_TIMEOUT="${WAF_HEALTH_TIMEOUT:-3}"

response="$(curl -fsS --max-time "$WAF_HEALTH_TIMEOUT" "$WAF_HEALTH_URL" 2>/dev/null)" || {
  echo "waf-health-check: request to $WAF_HEALTH_URL failed" >&2
  exit 1
}

# Deliberately a plain grep, not a jq dependency — this runs on the bare
# host, possibly before any config-management step has guaranteed jq is
# installed there, and the field we need is a simple top-level string.
if echo "$response" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
  exit 0
fi

echo "waf-health-check: backend reported non-ok status: $response" >&2
exit 1
