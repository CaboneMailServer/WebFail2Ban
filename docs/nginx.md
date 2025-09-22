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

### TCP Stream Configuration

For TCP services like IMAP and SMTP, you can use the stream module with Lua for auth_request equivalent:

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

### Caching Auth Responses

```nginx
# Create cache directory
proxy_cache_path /var/cache/nginx/auth levels=1:2 keys_zone=auth_cache:10m max_size=100m inactive=60m use_temp_path=off;

server {
    location = /auth {
        internal;
        proxy_pass http://fail2ban_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        # Cache configuration
        proxy_cache auth_cache;
        proxy_cache_key "$remote_addr";
        proxy_cache_valid 200 10s;
        proxy_cache_valid 403 60s;
        proxy_cache_use_stale error timeout invalid_header updating;

        # Headers
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
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