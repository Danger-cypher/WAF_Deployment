# =============================================================================
# OpenResty Dockerfile — CyberSentinel WAF (Self-Contained & Binary Compatible)
# Builds a production-ready WAF image:
#   - OpenResty (Official base)
#   - ModSecurity v3 (Compiled from source to v3.0.14+ for CRS v4 compatibility)
#   - GeoIP2 dynamic module (compiled against OpenResty source)
#   - OWASP Core Rule Set (latest release)
# =============================================================================

# ── Stage 1: Build ModSecurity and dynamic modules ───────────────────────────
FROM ubuntu:22.04 AS builder

# Install build dependencies + libraries required to compile ModSecurity and OpenResty modules
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    ca-certificates \
    wget \
    curl \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libcurl4-openssl-dev \
    libxml2-dev \
    libyajl-dev \
    libgeoip-dev \
    libpcre3-dev \
    libpcre2-dev \
    libssl-dev \
    zlib1g-dev \
    libmaxminddb-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Local patches applied to the freshly-cloned upstream sources below — see
# each patch file's own header comment for what it does and why.
COPY patches/ /build/patches/

# ── Compile ModSecurity v3 from source (fixes CRS v4 variable incompatibility) ─
# 01-libmodsecurity-tx-variable-accessor.patch adds Transaction::getTxVariable()
# / msc_get_tx_variable(), a public accessor for arbitrary TX-collection
# variables (e.g. TX:ANOMALY_SCORE) that upstream libmodsecurity's C API has
# no equivalent for. Required so the connector below can expose the real CRS
# score to ml_check.lua instead of the always-zero value it had no way to
# read before (item 8 of the WAF improvement plan).
RUN git clone --depth=1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /build/ModSecurity \
    && cd /build/ModSecurity \
    && git apply /build/patches/01-libmodsecurity-tx-variable-accessor.patch \
    && git submodule update --init --recursive \
    && ./build.sh \
    && ./configure --with-lmdb=no \
    && make -j$(nproc) \
    && make install

# Pinned OpenResty release matching the runtime version
ARG OPENRESTY_VER=1.25.3.2

# Download and extract OpenResty source
RUN wget -q "https://openresty.org/download/openresty-${OPENRESTY_VER}.tar.gz" \
    && tar -xzf "openresty-${OPENRESTY_VER}.tar.gz"

# Clone ModSecurity-nginx connector.
# 02-connector-anomaly-score-variable.patch registers a real
# $modsecurity_anomaly_score nginx variable, backed by msc_get_tx_variable()
# above, so ml_check.lua can read ModSecurity's real anomaly score. Safe to
# read from access_by_lua_file: verified live (MSC_PHASE_ORDER_DIAG logging)
# that this module's NGX_HTTP_ACCESS_PHASE handler — which calls
# msc_process_request_body() and populates TX:BLOCKING_INBOUND_ANOMALY_SCORE
# (CRS v4's real per-request score; plain TX:ANOMALY_SCORE is a CRS v3 name
# that v4 only ever sets from the response phase) — always runs before
# access_by_lua_file within the same access phase.
RUN git clone --depth=1 https://github.com/SpiderLabs/ModSecurity-nginx.git /build/ModSecurity-nginx \
    && cd /build/ModSecurity-nginx \
    && git apply /build/patches/02-connector-anomaly-score-variable.patch

# Clone ngx_http_geoip2_module
RUN git clone --depth=1 https://github.com/leev/ngx_http_geoip2_module.git /build/ngx_http_geoip2_module

# Configure and compile dynamic modules inside the OpenResty bundled Nginx source
# Note: we explicitly point to the custom built ModSecurity paths
RUN cd /build/openresty-${OPENRESTY_VER}/bundle/nginx-1.25.3 \
    && sh configure \
        --with-compat \
        --add-dynamic-module=/build/ModSecurity-nginx \
        --add-dynamic-module=/build/ngx_http_geoip2_module \
        --with-cc-opt="-I/usr/local/modsecurity/include" \
        --with-ld-opt="-L/usr/local/modsecurity/lib -lmodsecurity" \
    && make modules \
    && mkdir -p /build/modules \
    && cp objs/ngx_http_modsecurity_module.so /build/modules/ \
    && cp objs/ngx_http_geoip2_module.so /build/modules/

# ── Stage 2: Final Runtime Image ──────────────────────────────────────────────
FROM openresty/openresty:1.25.3.2-1-jammy-amd64

LABEL maintainer="CyberSentinel WAF" \
      description="Self-contained WAF container: OpenResty + ModSecurity v3 + OWASP CRS + GeoIP2"

# Install ModSecurity runtime library dependencies + GeoIP2 runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmaxminddb0 \
    libcurl4 \
    libxml2 \
    libfuzzy2 \
    libyajl2 \
    libgeoip1 \
    libpcre3 \
    liblua5.3-0 \
    ca-certificates \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Copy compiled ModSecurity dynamic libraries from builder stage ──────────
COPY --from=builder /usr/local/modsecurity /usr/local/modsecurity
RUN ln -s /usr/local/modsecurity/lib/libmodsecurity.so.3 /usr/local/lib/libmodsecurity.so.3 \
    && ldconfig

# ── Copy compiled dynamic modules from builder stage ─────────────────────────
RUN mkdir -p /usr/local/openresty/nginx/modules
COPY --from=builder /build/modules/ngx_http_modsecurity_module.so /usr/local/openresty/nginx/modules/
COPY --from=builder /build/modules/ngx_http_geoip2_module.so      /usr/local/openresty/nginx/modules/

# ── Install OWASP Core Rule Set (latest release) ─────────────────────────────
RUN CRS_LATEST=$(curl -sf https://api.github.com/repos/coreruleset/coreruleset/releases/latest \
        | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/') \
    && echo "Installing OWASP CRS ${CRS_LATEST}" \
    && wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_LATEST}.tar.gz" \
         -O /tmp/crs.tar.gz \
    && mkdir -p /etc/nginx/modsec \
    && tar -xzf /tmp/crs.tar.gz -C /tmp \
    && CRS_DIR=$(ls /tmp | grep coreruleset- | head -1) \
    && mv /tmp/${CRS_DIR} /etc/nginx/modsec/coreruleset \
    && cp /etc/nginx/modsec/coreruleset/crs-setup.conf.example \
          /etc/nginx/modsec/coreruleset/crs-setup.conf \
    && rm /tmp/crs.tar.gz

# ── Copy ModSecurity recommended config from official repo ───────────────────
RUN wget -q https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended \
         -O /etc/nginx/modsec/modsecurity.conf.default

# ── Create required runtime directories ──────────────────────────────────────
RUN mkdir -p \
    /etc/nginx/modsec \
    /etc/nginx/sites-available \
    /etc/nginx/sites-enabled \
    /etc/nginx/conf.d \
    /etc/nginx/ssl \
    /var/log/nginx \
    /var/log/modsecurity/audit

ENV PATH="/usr/local/openresty/bin:/usr/local/openresty/nginx/sbin:${PATH}"

EXPOSE 80 443 3020

CMD ["openresty", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]
