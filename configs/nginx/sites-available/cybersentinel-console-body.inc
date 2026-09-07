# Auto-extracted shared body for the CyberSentinel admin console vhost —
# included from both the plain-HTTP (:3020) and HTTPS (:3443) server
# blocks in sites-available/cybersentinel, so ModSecurity rules, the
# control-plane marker, rate-limit zones and every location only need to
# be maintained in one place. Do not include this from anything other than
# that console vhost (@proxy_frontend/@proxy_backend assume the upstreams
# this file sets are only ever reached from here).

    resolver 127.0.0.11 valid=30s ipv6=off;
    
    # ✅ ENABLE ModSecurity with selective rule whitelisting for admin dashboard
    modsecurity on;
    modsecurity_rules '
        # Whitelist common false positives for admin JSON payloads
        SecRuleRemoveById 920420
        SecRuleRemoveById 920440
        SecRuleRemoveById 942200
        SecRuleRemoveById 942260
        SecRuleRemoveById 942370
        
        # Allow SQL-like strings in legitimate settings/queries
        SecRuleRemoveById 942100
        SecRuleRemoveById 942150
        SecRuleRemoveById 942410
        SecRuleRemoveById 942430
        SecRuleRemoveById 942440
        
        # Allow special characters in custom HTML responses
        SecRuleRemoveById 941100
        SecRuleRemoveById 941110
        SecRuleRemoveById 941160
        SecRuleRemoveById 941310
        
        # Allow legitimate admin command-like patterns
        SecRuleRemoveById 932100
        SecRuleRemoveById 932105
        SecRuleRemoveById 932110
        SecRuleRemoveById 932115
    ';
    
    # Marks this server block as the CONTROL PLANE (the admin dashboard),
    # as opposed to the data plane (the generated per-app gateway vhosts in
    # sites-enabled/mssp). Read pcall-guarded by ml_check.lua/ml_decide.lua
    # — same pattern as $waf_mtls_mode, since reading an nginx variable that
    # was never `set` anywhere raises a Lua error.
    #
    # Both Lua scripts carry a path exemption list (telemetry endpoints,
    # /api/auth/, /api/ml/, static assets). That list exists purely for this
    # vhost: it stops the dashboard's own 3s polling from being scored,
    # throttled and challenged by the engine it is administering — the exact
    # feedback loop behind the 2026-09-04 admin self-lockout. It was never
    # meant for customer traffic, but it was being applied there too because
    # ml_check.lua is declared once at http level (nginx.conf) and inherited
    # by every server block. That let anyone bypass the exemption-gated
    # checks on a protected application just by suffixing a path with `.js`
    # or prefixing it with /static/ (audit finding P1-03). This variable is
    # what confines the list to where it belongs.
    set $waf_control_plane "1";

    # Keep ML-WAF engine active (full protection)
    access_by_lua_file /opt/ml-waf/ml_check.lua;

    location ~* \.(php|pl|py|jsp|asp|sh|cgi)$ { deny all; }
    location ~* (?:/\.\./|/\.\.$) { deny all; }
    # `return 403;` here used to make this location 403 unconditionally,
    # for every client regardless of source IP — `return` is a rewrite-
    # phase directive, evaluated before `allow`/`deny` (an access-phase
    # check), so it fired before the IP allowlist ever got a chance to
    # match (audit finding P4-04). `deny all;` already returns 403 on its
    # own for anything the `allow` line doesn't match — the explicit
    # `return` was both redundant and the thing making the allow rule dead.
    location /admin/ { allow 192.168.2.0/24; deny all; }
    # location / and location /api/ dispatch through ml_decide.lua (CONTENT
    # phase) rather than proxy_pass directly — see ml_decide.lua's header
    # comment for why (the ACCESS-phase CRS-score read in ml_check.lua
    # can't be trusted, since nginx doesn't guarantee a dynamically-loaded
    # module's access-phase handler — ModSecurity here — runs before a
    # statically-linked one's — Lua here — within the same phase; it only
    # guarantees the whole phase completes before content phase starts).
    # ngx.exec() hands off to the named location's own proxy_pass on allow,
    # same internal-redirect mechanism already used by `error_page 403 =
    # @json_forbidden` elsewhere in this codebase — proxying itself is
    # unchanged. location /api/auth/ and location /socket.io/ don't need
    # this: /api/auth/ is exempted from ML scoring entirely (see
    # is_admin_request in ml_check.lua/ml_decide.lua), so it never read the
    # unreliable score either way; /socket.io/ handles the ML decision at
    # the WebSocket handshake below, same pattern.
    location / {
        limit_except GET POST HEAD PUT PATCH DELETE { deny all; }
        limit_req zone=api_limit burst=100;
        set $waf_upstream_location "@proxy_frontend";
        content_by_lua_file /opt/ml-waf/ml_decide.lua;
    }
    location @proxy_frontend {
        set $frontend_upstream waf-frontend:80;
        proxy_pass http://$frontend_upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $http_connection;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location /api/auth/ {
        limit_except GET POST HEAD PUT PATCH DELETE { deny all; }

        limit_req zone=login_limit burst=5 nodelay;
        include /etc/nginx/conf.d/backend_proxy_headers.inc;
        set $backend_auth_upstream waf-backend:8000;
        rewrite ^/api/auth/(.*) /auth/$1 break;
        proxy_pass http://$backend_auth_upstream;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location /api/ {
        limit_except GET POST HEAD PUT PATCH DELETE { deny all; }

        limit_req zone=api_limit burst=30 nodelay;
        # set must come before rewrite ... break — break halts the whole
        # rewrite-phase directive chain for this location (set included),
        # so a set placed after it never executes (confirmed live: caused
        # every /api/* dashboard request to 500 with "$waf_upstream_location
        # not set").
        set $waf_upstream_location "@proxy_backend";
        rewrite ^/api/(.*) /$1 break;
        content_by_lua_file /opt/ml-waf/ml_decide.lua;
    }
    location @proxy_backend {
        include /etc/nginx/conf.d/backend_proxy_headers.inc;
        set $backend_upstream waf-backend:8000;
        proxy_pass http://$backend_upstream;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location /socket.io/ {
        limit_except GET POST HEAD { deny all; }
        limit_conn ws_conn_limit 20;
        limit_req zone=api_limit burst=20 nodelay;
        set $waf_upstream_location "@proxy_socketio";
        content_by_lua_file /opt/ml-waf/ml_decide.lua;
    }
    location @proxy_socketio {
        include /etc/nginx/conf.d/backend_proxy_headers.inc;
        set $socket_upstream waf-backend:8000;
        proxy_pass http://$socket_upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    # Live log/alert WebSocket stream (routes/ws.py, mounted with no prefix
    # — its own @router.websocket("/logs/stream") decorator is the whole
    # path on the backend). The frontend (api.js's getLiveStreamWsUrl(),
    # used by NotificationBell/Overview/ThreatGlobe) has always connected
    # to /ws/logs/stream, but no location for /ws/ existed here — every
    # such request silently fell through to the catch-all `location /`
    # instead, which sends it to @proxy_frontend (the static frontend
    # server, waf-frontend:80), which has no such route — a permanent 502
    # on every connect/reconnect attempt. Found 2026-09-04 while
    # investigating unrelated WAF false-positive noise on this same path.
    # `set` before `rewrite ... break` — see location /api/'s comment
    # above for why the order matters.
    location /ws/ {
        limit_except GET POST HEAD { deny all; }
        limit_conn ws_conn_limit 20;
        limit_req zone=api_limit burst=20 nodelay;
        set $waf_upstream_location "@proxy_ws";
        rewrite ^/ws/(.*) /$1 break;
        content_by_lua_file /opt/ml-waf/ml_decide.lua;
    }
    location @proxy_ws {
        include /etc/nginx/conf.d/backend_proxy_headers.inc;
        set $ws_upstream waf-backend:8000;
        proxy_pass http://$ws_upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
