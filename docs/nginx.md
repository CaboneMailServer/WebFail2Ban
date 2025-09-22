# Nginx Integration (auth_request)

Nginx integration uses the auth_request module to validate requests against the Fail2Ban service before proxying to backend services.

## Overview

The Fail2Ban service exposes an HTTP auth_request interface (by default on port 8888) for Nginx. This allows Nginx to authorize requests based on IP reputation using the auth_request module.

**Protocol Specification**: [Nginx auth_request Module Documentation](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)

- **Protocol**: HTTP/HTTPS
- **Endpoint**: `/auth`
- **Method**: Any (GET, POST, etc.)
- **Input**: Client source IP extracted from headers and connection info
- **Output**: HTTP 200 (Allow) or HTTP 403 (Deny) with custom headers
- **Default Port**: 8888
- **Use Case**: Nginx web server authorization

## Configuration

### Fail2Ban Service Configuration

Configure the Nginx auth_request service in your `config.yaml`:

```yaml
nginx:
  address: "0.0.0.0"      # Listen address
  port: 8888              # HTTP port
  enabled: true           # Enable/disable Nginx support
  read_timeout: "10s"     # Request read timeout
  write_timeout: "10s"    # Response write timeout
  return_json: false      # Return JSON error responses
```

**Environment Variables:**
- `FAIL2BAN_NGINX_ADDRESS`
- `FAIL2BAN_NGINX_PORT`
- `FAIL2BAN_NGINX_ENABLED`
- `FAIL2BAN_NGINX_READ_TIMEOUT`
- `FAIL2BAN_NGINX_WRITE_TIMEOUT`
- `FAIL2BAN_NGINX_RETURN_JSON`

### Basic Nginx Configuration

```nginx
# /etc/nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Log format with auth status
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'auth_status=$upstream_http_x_fail2ban_status';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Upstream for the auth service
    upstream fail2ban_auth {
        server fail2ban-service:8888;
        keepalive 10;
    }

    # Upstream for backend services
    upstream backend_service {
        server backend:80;
        keepalive 10;
    }

    # Rate limiting zones
    limit_req_zone $remote_addr zone=auth:10m rate=10r/s;
    limit_req_zone $remote_addr zone=global:10m rate=100r/s;

    server {
        listen 80;
        server_name _;

        # Internal auth location
        location = /auth {
            internal;
            proxy_pass http://fail2ban_auth/auth;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Original-IP $remote_addr;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Host $http_host;

            # Cache auth responses for performance
            proxy_cache_valid 200 10s;
            proxy_cache_valid 403 60s;
        }

        # Protected location
        location / {
            # Rate limiting
            limit_req zone=global burst=10 nodelay;

            # Perform auth_request
            auth_request /auth;

            # Pass auth headers to backend
            auth_request_set $fail2ban_status $upstream_http_x_fail2ban_status;
            auth_request_set $fail2ban_ip $upstream_http_x_fail2ban_ip;
            auth_request_set $fail2ban_reason $upstream_http_x_fail2ban_reason;

            # Add headers for backend
            proxy_set_header X-Fail2ban-Status $fail2ban_status;
            proxy_set_header X-Fail2ban-IP $fail2ban_ip;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Proxy to backend
            proxy_pass http://backend_service;
            proxy_set_header Host $host;
            proxy_set_header Connection "";
            proxy_http_version 1.1;
        }

        # Custom error page for banned IPs
        error_page 403 = @banned;
        location @banned {
            return 403 '{"error":"access_denied","reason":"IP banned due to suspicious activity","timestamp":"$time_iso8601"}';
            add_header Content-Type application/json;
            add_header X-Fail2ban-Status "banned";
        }

        # Health check endpoint
        location /nginx-health {
            return 200 "OK";
            add_header Content-Type text/plain;
        }
    }
}
```

### Advanced Nginx Configuration

#### Multiple Virtual Hosts

```nginx
http {
    # Shared upstream definitions
    upstream fail2ban_auth {
        server fail2ban-service:8888;
        keepalive 20;
    }

    upstream sogo_backend {
        server sogo:80;
        keepalive 10;
    }

    upstream api_backend {
        server api-service:3000;
        keepalive 10;
    }

    # Rate limiting zones
    limit_req_zone $remote_addr zone=auth:10m rate=10r/s;
    limit_req_zone $remote_addr zone=webmail:10m rate=50r/s;
    limit_req_zone $remote_addr zone=api:10m rate=20r/s;

    # Webmail server
    server {
        listen 80;
        server_name webmail.example.com;

        # Internal auth location
        location = /auth {
            internal;
            proxy_pass http://fail2ban_auth/auth;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # SOGo webmail interface
        location / {
            limit_req zone=webmail burst=20 nodelay;
            auth_request /auth;

            # SOGo specific headers
            auth_request_set $fail2ban_status $upstream_http_x_fail2ban_status;
            proxy_set_header X-Fail2ban-Status $fail2ban_status;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header Host $host;

            proxy_pass http://sogo_backend;
        }

        # SOGo specific paths that need special handling
        location ~ ^/SOGo/(dav|\.well-known)/ {
            auth_request /auth;
            proxy_pass http://sogo_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }

    # API server
    server {
        listen 80;
        server_name api.example.com;

        location = /auth {
            internal;
            proxy_pass http://fail2ban_auth/auth;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Real-IP $remote_addr;
        }

        location /api/ {
            limit_req zone=api burst=10 nodelay;
            auth_request /auth;

            proxy_pass http://api_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
```

#### SSL/TLS Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name webmail.example.com;

    ssl_certificate /etc/ssl/certs/webmail.example.com.pem;
    ssl_certificate_key /etc/ssl/private/webmail.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Internal auth location with SSL
    location = /auth {
        internal;
        proxy_pass http://fail2ban_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Host $http_host;
    }

    location / {
        auth_request /auth;
        proxy_pass http://sogo_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name webmail.example.com;
    return 301 https://$server_name$request_uri;
}
```

## TCP Stream Configuration and Mail Proxy

Nginx supports TCP proxying via the `stream` module, which can handle IMAP, SMTP, and other TCP protocols.

### Basic TCP Proxying without Authorization

For simple TCP proxying without auth_request (auth is handled by the backend service itself):

```nginx
# /etc/nginx/nginx.conf
load_module modules/ngx_stream_module.so;

events {
    worker_connections 1024;
}

# HTTP context for web services
http {
    # Your HTTP configuration here
}

# Stream context for TCP/UDP proxying
stream {
    # Upstream definitions
    upstream imap_backend {
        server dovecot:143;
        server dovecot2:143 backup;
    }

    upstream imaps_backend {
        server dovecot:993;
        server dovecot2:993 backup;
    }

    upstream smtp_backend {
        server postfix:25;
        server postfix2:25 backup;
    }

    upstream smtps_backend {
        server postfix:465;
        server postfix2:465 backup;
    }

    # IMAP proxy (port 143)
    server {
        listen 143;
        proxy_pass imap_backend;
        proxy_timeout 300s;
        proxy_responses 1;
        proxy_bind $remote_addr transparent;  # Preserve client IP
        access_log /var/log/nginx/imap_access.log;
    }

    # IMAPS proxy (port 993)
    server {
        listen 993 ssl;
        ssl_certificate /etc/ssl/certs/mail.example.com.pem;
        ssl_certificate_key /etc/ssl/private/mail.example.com.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        proxy_pass imaps_backend;
        proxy_timeout 300s;
        proxy_responses 1;
        access_log /var/log/nginx/imaps_access.log;
    }

    # SMTP proxy (port 25)
    server {
        listen 25;
        proxy_pass smtp_backend;
        proxy_timeout 300s;
        proxy_responses 1;
        access_log /var/log/nginx/smtp_access.log;
    }

    # SMTPS proxy (port 465)
    server {
        listen 465 ssl;
        ssl_certificate /etc/ssl/certs/mail.example.com.pem;
        ssl_certificate_key /etc/ssl/private/mail.example.com.key;

        proxy_pass smtps_backend;
        proxy_timeout 300s;
        proxy_responses 1;
        access_log /var/log/nginx/smtps_access.log;
    }
}
```

### Native Mail Proxy Support

Nginx supports native proxying for mail protocols via two modules:
- **`stream` module**: Generic TCP/UDP proxying (shown above)
- **`ngx_mail` module**: Specialized mail proxy with protocol awareness

#### Mail Module (ngx_mail) Configuration

The `ngx_mail` module provides native support for IMAP, POP3, and SMTP protocols with built-in authentication and authorization capabilities:

```nginx
# /etc/nginx/nginx.conf with mail module
load_module modules/ngx_mail_module.so;

events {
    worker_connections 1024;
}

# HTTP context for auth backend
http {
    upstream fail2ban_auth {
        server fail2ban-service:8888;
    }

    # Auth backend for mail module
    server {
        listen 8889;

        location /auth-mail {
            proxy_pass http://fail2ban_auth/auth;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Protocol $http_auth_protocol;
            proxy_set_header X-Auth-User $http_auth_user;

            # Mail module expects specific headers
            proxy_set_header Auth-Status $upstream_http_auth_status;
            proxy_set_header Auth-Server $upstream_http_auth_server;
            proxy_set_header Auth-Port $upstream_http_auth_port;
        }
    }
}

# Mail context for IMAP/POP3/SMTP
mail {
    # Auth configuration
    auth_http http://127.0.0.1:8889/auth-mail;
    auth_http_timeout 5s;

    # Protocol settings
    imap_capabilities "IMAP4rev1" "UIDPLUS" "IDLE" "LITERAL+" "QUOTA";
    pop3_capabilities "LAST" "TOP" "USER" "PIPELINING" "UIDL";
    smtp_capabilities "SIZE 10485760" "VRFY" "ETRN" "ENHANCEDSTATUSCODES" "8BITMIME" "DSN";

    # SSL configuration
    ssl_certificate /etc/ssl/certs/mail.pem;
    ssl_certificate_key /etc/ssl/private/mail.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # IMAP server
    server {
        listen 143;
        listen 993 ssl;
        protocol imap;
        proxy on;
        proxy_pass_error_message on;
        proxy_timeout 24h;
        proxy_send_timeout 5s;
        proxy_read_timeout 5s;

        # Error log for debugging
        error_log /var/log/nginx/mail_imap.log info;
    }

    # POP3 server
    server {
        listen 110;
        listen 995 ssl;
        protocol pop3;
        proxy on;
        proxy_pass_error_message on;
        proxy_timeout 24h;

        error_log /var/log/nginx/mail_pop3.log info;
    }

    # SMTP server
    server {
        listen 25;
        listen 587 ssl;
        listen 465 ssl;
        protocol smtp;
        proxy on;
        proxy_pass_error_message on;
        proxy_timeout 5m;
        smtp_auth login plain cram-md5;
        xclient off;

        error_log /var/log/nginx/mail_smtp.log info;
    }
}
```

#### Stream Module IMAP/POP3/SMTP (Alternative approach)

```nginx
# Alternative: Stream module configuration with backend authentication
stream {
    upstream imap_pool {
        server dovecot1:143 weight=3;
        server dovecot2:143 weight=2;
        server dovecot3:143 backup;
    }

    upstream pop3_pool {
        server dovecot1:110;
        server dovecot2:110;
    }

    # IMAP proxy
    server {
        listen 143;
        proxy_pass imap_pool;
        proxy_timeout 600s;         # Allow longer IMAP sessions
        proxy_responses 1;          # Expected responses from IMAP
        proxy_connect_timeout 3s;

        # Preserve client information
        proxy_bind $remote_addr transparent;

        # Logging
        access_log /var/log/nginx/imap.log;
        error_log /var/log/nginx/imap_error.log;
    }

    # POP3 proxy
    server {
        listen 110;
        proxy_pass pop3_pool;
        proxy_timeout 300s;
        proxy_responses 1;
        access_log /var/log/nginx/pop3.log;
    }

    # IMAPS (SSL/TLS)
    server {
        listen 993 ssl;
        ssl_certificate /etc/ssl/certs/mail.pem;
        ssl_certificate_key /etc/ssl/private/mail.key;

        proxy_pass imap_pool;
        proxy_timeout 600s;
        proxy_responses 1;

        # SSL passthrough to backend
        proxy_ssl on;
        proxy_ssl_verify off;
    }
}
```

#### SMTP Proxy with Submission Support

```nginx
stream {
    upstream smtp_pool {
        server postfix1:25;
        server postfix2:25;
    }

    upstream submission_pool {
        server postfix1:587;
        server postfix2:587;
    }

    # SMTP proxy (port 25)
    server {
        listen 25;
        proxy_pass smtp_pool;
        proxy_timeout 300s;
        proxy_responses 1;
        access_log /var/log/nginx/smtp.log;
    }

    # SMTP Submission (port 587) with STARTTLS
    server {
        listen 587;
        proxy_pass submission_pool;
        proxy_timeout 300s;
        proxy_responses 1;
        access_log /var/log/nginx/submission.log;
    }

    # SMTPS (port 465) with implicit SSL
    server {
        listen 465 ssl;
        ssl_certificate /etc/ssl/certs/mail.pem;
        ssl_certificate_key /etc/ssl/private/mail.key;

        proxy_pass submission_pool;
        proxy_timeout 300s;
        proxy_responses 1;
        access_log /var/log/nginx/smtps.log;
    }
}
```

### TCP Proxying with Authorization (Lua Required)

For TCP stream authorization equivalent to auth_request, you need the Lua module. **Note**: This requires `lua-resty-http` and is more complex than HTTP auth_request. This approach works for all TCP protocols including mail protocols (IMAP, SMTP, POP3):

```nginx
# /etc/nginx/nginx.conf (with stream module)
load_module modules/ngx_stream_module.so;
load_module modules/ndk_http_module.so;
load_module modules/ngx_http_lua_module.so;
load_module modules/ngx_stream_lua_module.so;

events {
    worker_connections 1024;
}

# HTTP context for auth_request
http {
    upstream fail2ban_auth {
        server fail2ban-service:8888;
    }

    server {
        listen 8889;  # Internal auth server

        location /auth {
            proxy_pass http://fail2ban_auth/auth;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}

# Stream context for TCP proxying
stream {
    upstream imap_backend {
        server dovecot:143;
    }

    upstream smtp_backend {
        server postfix:25;
    }

    # Lua script for auth check
    lua_package_path "/etc/nginx/lua/?.lua;;";

    server {
        listen 143;

        # Lua access check
        access_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()

            local res, err = httpc:request_uri("http://127.0.0.1:8889/auth", {
                method = "GET",
                headers = {
                    ["X-Real-IP"] = ngx.var.remote_addr,
                    ["X-Forwarded-For"] = ngx.var.remote_addr,
                }
            })

            if not res or res.status == 403 then
                ngx.log(ngx.ERR, "IP banned: " .. ngx.var.remote_addr)
                ngx.exit(ngx.ERROR)
            end
        }

        proxy_pass imap_backend;
        proxy_timeout 300s;
        proxy_responses 1;
    }

    server {
        listen 25;

        access_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()

            local res, err = httpc:request_uri("http://127.0.0.1:8889/auth", {
                method = "GET",
                headers = {
                    ["X-Real-IP"] = ngx.var.remote_addr,
                }
            })

            if not res or res.status == 403 then
                ngx.log(ngx.ERR, "IP banned: " .. ngx.var.remote_addr)
                ngx.exit(ngx.ERROR)
            end
        }

        proxy_pass smtp_backend;
        proxy_timeout 300s;
        proxy_responses 1;
    }
}

# Note: This Lua-based approach works for all mail protocols:
# - IMAP (port 143, 993)
# - SMTP (port 25, 465, 587)
# - POP3 (port 110, 995)
# Simply adapt the listen port and backend accordingly.
```

## Docker Compose Example

```yaml
version: '3.8'

services:
  fail2ban-service:
    image: ghcr.io/cabonemailserver/webfail2ban:latest
    container_name: fail2ban-service
    ports:
      - "8888:8888"    # Nginx auth port
      - "514:514/udp"  # Syslog port
    volumes:
      - ./config.yaml:/app/config.yaml
    restart: unless-stopped

  nginx:
    image: nginx:1.25-alpine
    container_name: nginx
    ports:
      - "80:80"        # HTTP
      - "443:443"      # HTTPS
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl
    depends_on:
      - fail2ban-service
    restart: unless-stopped

  # Example backend services
  sogo:
    image: sogo/sogo:latest
    container_name: sogo
    ports:
      - "20000:80"
    restart: unless-stopped

  api-service:
    image: node:18-alpine
    container_name: api-service
    ports:
      - "3000:3000"
    restart: unless-stopped
```

## Performance Optimization

## Authorization Response Caching

Nginx provides built-in caching capabilities for auth_request responses:

### Basic Auth Response Caching

```nginx
# Create cache directory and zone
proxy_cache_path /var/cache/nginx/auth levels=1:2 keys_zone=auth_cache:10m max_size=100m inactive=60m use_temp_path=off;

server {
    location = /auth {
        internal;
        proxy_pass http://fail2ban_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        # Basic cache configuration
        proxy_cache auth_cache;
        proxy_cache_key "$remote_addr";
        proxy_cache_valid 200 10s;   # Cache allowed IPs for 10 seconds
        proxy_cache_valid 403 60s;   # Cache banned IPs for 60 seconds
        proxy_cache_use_stale error timeout invalid_header updating;

        # Headers
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Advanced Caching with Custom Keys

```nginx
# Multi-tier caching zones
proxy_cache_path /var/cache/nginx/auth_short levels=1:2 keys_zone=auth_short:10m max_size=50m inactive=5m;
proxy_cache_path /var/cache/nginx/auth_long levels=1:2 keys_zone=auth_long:50m max_size=500m inactive=60m;

map $upstream_http_x_fail2ban_status $cache_zone {
    default auth_short;
    "banned" auth_long;  # Cache banned IPs longer
}

map $upstream_http_x_fail2ban_status $cache_time {
    default "5s";
    "banned" "300s";     # Cache banned IPs for 5 minutes
}

server {
    location = /auth {
        internal;
        proxy_pass http://fail2ban_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        # Dynamic caching based on response
        proxy_cache $cache_zone;
        proxy_cache_key "$remote_addr:$http_user_agent";  # Include User-Agent for better differentiation

        # Cache valid responses with dynamic TTL
        proxy_cache_valid 200 $cache_time;
        proxy_cache_valid 403 300s;  # Always cache bans for 5 minutes
        proxy_cache_valid any 1s;    # Cache errors briefly

        # Advanced cache behavior
        proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
        proxy_cache_lock on;         # Prevent thundering herd
        proxy_cache_lock_timeout 5s;
        proxy_cache_revalidate on;   # Use conditional requests

        # Headers
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Original-URI $request_uri;

        # Add cache status header for debugging
        add_header X-Cache-Status $upstream_cache_status always;
    }
}
```

### Geographic-based Caching

```nginx
# Different cache strategies based on IP ranges
geo $auth_cache_strategy {
    default standard;
    10.0.0.0/8 internal;      # Internal IPs - shorter cache
    172.16.0.0/12 internal;
    192.168.0.0/16 internal;
}

map $auth_cache_strategy $cache_key_suffix {
    standard "";
    internal ":internal";
}

map $auth_cache_strategy $cache_ttl {
    standard "60s";
    internal "10s";           # Cache internal IPs for shorter time
}

server {
    location = /auth {
        internal;
        proxy_pass http://fail2ban_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        # Geographic-aware caching
        proxy_cache auth_cache;
        proxy_cache_key "$remote_addr$cache_key_suffix";
        proxy_cache_valid 200 $cache_ttl;
        proxy_cache_valid 403 300s;

        # Headers
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Auth-Strategy $auth_cache_strategy;
    }
}
```

### Redis-based Distributed Caching

For multi-server deployments, use Redis with lua-resty-redis:

```nginx
# Install lua-resty-redis module first
# lua_package_path "/usr/local/lib/lua/?.lua;;";

init_by_lua_block {
    local redis = require "resty.redis"
    -- Initialize Redis connection pool
}

server {
    location = /auth {
        internal;

        # Check Redis cache first
        access_by_lua_block {
            local redis = require "resty.redis"
            local red = redis:new()
            red:set_timeouts(100, 100, 100)  -- 100ms timeouts

            local ok, err = red:connect("redis", 6379)
            if not ok then
                ngx.log(ngx.ERR, "Failed to connect to Redis: ", err)
                return  -- Fall through to auth service
            end

            local cache_key = "auth:" .. ngx.var.remote_addr
            local cached_result, err = red:get(cache_key)

            if cached_result and cached_result ~= ngx.null then
                if cached_result == "banned" then
                    ngx.status = 403
                    ngx.say("Banned")
                    ngx.exit(403)
                elseif cached_result == "allowed" then
                    ngx.status = 200
                    ngx.say("OK")
                    ngx.exit(200)
                end
            end

            red:set_keepalive(10000, 100)  # Connection pooling
        }

        # If not cached, proxy to auth service
        proxy_pass http://fail2ban_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;

        # Cache the result in Redis
        header_filter_by_lua_block {
            local redis = require "resty.redis"
            local red = redis:new()
            red:set_timeouts(100, 100, 100)

            local ok, err = red:connect("redis", 6379)
            if ok then
                local cache_key = "auth:" .. ngx.var.remote_addr
                local cache_value = "allowed"
                local ttl = 60  -- 1 minute default

                if ngx.status == 403 then
                    cache_value = "banned"
                    ttl = 300  -- 5 minutes for banned IPs
                end

                red:setex(cache_key, ttl, cache_value)
                red:set_keepalive(10000, 100)
            end
        }
    }
}
```

### Connection Pooling

```nginx
upstream fail2ban_auth {
    server fail2ban-service:8888;
    keepalive 32;
    keepalive_requests 1000;
    keepalive_timeout 60s;
}
```

### Rate Limiting

```nginx
# Define rate limiting zones
limit_req_zone $remote_addr zone=auth:10m rate=10r/s;
limit_req_zone $remote_addr zone=global:10m rate=100r/s;
limit_req_zone $binary_remote_addr zone=binary:10m rate=50r/s;

server {
    location / {
        # Apply rate limiting
        limit_req zone=global burst=20 nodelay;
        limit_req zone=binary burst=10 nodelay;

        auth_request /auth;
        proxy_pass http://backend_service;
    }
}
```

## Testing and Debugging

### Test Auth Endpoint

```bash
# Test auth endpoint directly
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth
# Expected: 200 (allowed) or 403 (banned)

# Test with different headers
curl -H "X-Forwarded-For: 10.0.0.1" http://localhost:8888/auth

# Test health endpoint
curl http://localhost:8888/health
# Expected: {"status":"healthy","service":"fail2ban-nginx-auth"}
```

### Test Through Nginx

```bash
# Test HTTP request through Nginx
curl http://localhost:80/

# Test with banned IP
curl -H "X-Forwarded-For: 192.168.1.100" http://localhost:80/

# Check response headers
curl -I http://localhost:80/
```

### Monitor Nginx Logs

```bash
# Real-time access logs
tail -f /var/log/nginx/access.log

# Filter auth failures
tail -f /var/log/nginx/access.log | grep "auth_status=banned"

# Error logs
tail -f /var/log/nginx/error.log
```

### Test Cache Performance

```bash
# Check cache status
curl -H "X-Real-IP: 192.168.1.200" -I http://localhost:80/
# Look for X-Cache-Status header

# Cache statistics
curl http://localhost/nginx_status
```

## Troubleshooting

### Common Issues

1. **auth_request module not available**
   ```bash
   # Check if auth_request module is compiled
   nginx -V 2>&1 | grep -o with-http_auth_request_module

   # Install nginx with auth_request module
   # On Ubuntu/Debian: nginx-full package
   # On CentOS/RHEL: nginx package usually includes it
   ```

2. **Internal redirect loops**
   - Ensure auth location is marked as `internal`
   - Check that auth endpoint doesn't trigger additional auth_request
   - Verify proxy_pass URL is correct

3. **Performance issues**
   - Enable connection keepalive
   - Implement auth response caching
   - Optimize rate limiting zones

### Debug Configuration

```nginx
# Enable debug logging
error_log /var/log/nginx/debug.log debug;

# Test configuration syntax
nginx -t

# Reload configuration
nginx -s reload
```

### Health Monitoring

```nginx
# Status page for monitoring
location /nginx_status {
    stub_status on;
    access_log off;
    allow 127.0.0.1;
    deny all;
}

# Auth cache status
location /auth_cache_status {
    access_log off;
    allow 127.0.0.1;
    deny all;
    return 200 "Cache info: $upstream_cache_status\n";
    add_header Content-Type text/plain;
}
```

## Security Considerations

- Always mark auth endpoints as `internal` to prevent external access
- Use HTTPS for production environments
- Implement proper rate limiting to prevent abuse
- Cache auth responses carefully (balance performance vs. security)
- Monitor for auth endpoint availability
- Use dedicated networks for auth service communication
- Implement proper error handling for auth service failures
- Consider implementing IP whitelisting for critical services