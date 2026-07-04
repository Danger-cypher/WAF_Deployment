FROM ubuntu:22.04

# Install runtime libraries required by Nginx/OpenResty and ModSecurity dynamic modules
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libxml2 \
    libmaxminddb0 \
    libfuzzy2 \
    libyajl2 \
    libgeoip1 \
    libpcre3 \
    liblua5.3-0 \
    && rm -rf /var/lib/apt/lists/*

# Inject OpenResty and custom Nginx paths into system PATH
ENV PATH="/usr/local/openresty/bin:/usr/local/openresty/nginx/sbin:${PATH}"

EXPOSE 3001

CMD ["openresty", "-g", "daemon off;"]
