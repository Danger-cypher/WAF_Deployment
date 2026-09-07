# Auto-maintained security-header override for locations that proxy
# straight to waf-backend (never to waf-frontend). Do not add this to a
# frontend-facing location.
#
# nginx.conf's global add_header block (X-Frame-Options, X-Content-Type-
# Options, Content-Security-Policy, ...) applies to every server{}/location{}
# on this host, and `add_header` does not deduplicate against a header the
# proxied upstream already set — it appends. backend/app/main.py's
# add_security_headers middleware independently sets its own (correct, more
# restrictive) X-Frame-Options: DENY, X-Content-Type-Options: nosniff and a
# tight `default-src 'none'` Content-Security-Policy on every response it
# returns. The result on every /api/, /api/auth/, /socket.io/ and /ws/
# response was two separate values for each of those three headers — for
# Content-Security-Policy specifically, browsers enforce the *intersection*
# of every CSP header present, which is well-defined but was never the
# intended policy for either side to reason about (audit finding P2-05).
#
# `add_header` also doesn't merge across levels — declaring any add_header
# in a location replaces the whole inherited set, not just one entry — so
# this file re-declares every header from the global block that does NOT
# conflict with something the backend already sets, and simply omits the
# three that do, letting the backend's own values reach the client
# untouched. See nginx.conf's header block for why HSTS is never added here
# either (that's also handled per-response by the backend, port-aware).
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
