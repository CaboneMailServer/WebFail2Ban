# Proxy Integration

This document explains how to integrate Fail2Ban Multi-Proxy with HAProxy, Envoy, and Nginx.

## HAProxy Integration (SPOA)

HAProxy integration uses the SPOA (Stream Processing Offload Agent) protocol.

### HAProxy Configuration

```haproxy
# haproxy.cfg
global
    daemon
    stats socket /var/run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

# SPOE configuration
backend spoe-ip-reputation
    mode tcp
    server ip-reputation 127.0.0.1:12345

# Frontend with SPOE filter
frontend mail-frontend
    bind *:143
    mode tcp

    # SPOE filter for IP reputation check
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf

    # Check if IP is banned
    tcp-request content reject if { var(sess.banned) -m int eq 1 }

    default_backend mail-backend

backend mail-backend
    mode tcp
    server dovecot 127.0.0.1:993
```

### SPOE Configuration

Create `/etc/haproxy/spoe-ip-reputation.conf`:

```
[ip-reputation]

spoe-agent ip-reputation-agent
    messages check-ip
    option var-prefix ip
    option set-on-error banned 0
    timeout hello      5s
    timeout idle       30s
    timeout processing 5s
    use-backend spoe-ip-reputation

spoe-message check-ip
    args src_ip=src
    event on-client-session if TRUE
```

### Testing HAProxy Integration

```bash
# Test IMAP connection through HAProxy
telnet localhost 143

# Check HAProxy stats
echo "show stat" | socat stdio /var/run/haproxy/admin.sock

# Check SPOE agent status
echo "show backends" | socat stdio /var/run/haproxy/admin.sock | grep spoe
```

## Envoy Integration (ext_authz)

Envoy integration uses the gRPC ext_authz (External Authorization) service.

### Envoy Configuration

```yaml
# envoy.yaml
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8080
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: service_cluster
          http_filters:
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              transport_api_version: V3
              grpc_service:
                envoy_grpc:
                  cluster_name: fail2ban_authz
                timeout: 0.25s
              include_peer_certificate: true
              failure_mode_allow: false
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: service_cluster
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: service_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: backend_service
                port_value: 80

  - name: fail2ban_authz
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    http2_protocol_options: {}
    load_assignment:
      cluster_name: fail2ban_authz
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: fail2ban-service
                port_value: 9001

admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 9901
```

### Testing Envoy Integration

```bash
# Test HTTP request through Envoy
curl -H "Host: example.com" http://localhost:8080/

# Check Envoy admin interface
curl http://localhost:9901/stats | grep ext_authz

# Check cluster health
curl http://localhost:9901/clusters | grep fail2ban_authz
```

## Nginx Integration (auth_request)

Nginx integration uses the auth_request module.

### Nginx Configuration

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    # Upstream for the auth service
    upstream fail2ban_auth {
        server fail2ban-service:8888;
        keepalive 10;
    }

    # Upstream for backend services
    upstream backend_service {
        server dovecot:143;  # or postfix:25, sogo:80, etc.
    }

    # Rate limiting (optional)
    limit_req_zone $remote_addr zone=auth:10m rate=10r/s;

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
            limit_req zone=auth burst=5 nodelay;

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
        location /health {
            return 200 "OK";
            add_header Content-Type text/plain;
        }
    }
}

# Stream module for TCP proxying (IMAP, SMTP, etc.)
stream {
    # Upstream for backend TCP services
    upstream imap_backend {
        server dovecot:143;
    }

    upstream smtp_backend {
        server postfix:25;
    }

    # IMAP proxy with basic IP-based access control
    server {
        listen 143;
        proxy_pass imap_backend;
        proxy_timeout 300s;
        proxy_responses 1;

        # For TCP streams, auth_request is not available
        # You would need nginx-lua-module for advanced auth
        access_log /var/log/nginx/imap_access.log;
    }

    # SMTP proxy
    server {
        listen 25;
        proxy_pass smtp_backend;
        proxy_timeout 300s;
        proxy_responses 1;
        access_log /var/log/nginx/smtp_access.log;
    }
}
```

### Nginx with Lua (Advanced)

For TCP stream auth_request equivalent, use nginx-lua-module:

```nginx
stream {
    lua_package_path "/etc/nginx/lua/?.lua;;";

    upstream fail2ban_auth {
        server fail2ban-service:8888;
    }

    upstream imap_backend {
        server dovecot:143;
    }

    server {
        listen 143;

        # Lua access check
        access_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()

            local res, err = httpc:request_uri("http://fail2ban-service:8888/auth", {
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
    }
}
```

### Testing Nginx Integration

```bash
# Test HTTP request through Nginx
curl http://localhost:80/

# Test with banned IP header
curl -H "X-Real-IP: 192.168.1.100" http://localhost:80/

# Test auth endpoint directly
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth

# Check Nginx access logs
tail -f /var/log/nginx/access.log

# Test health endpoint
curl http://localhost:80/health
```

## Performance Considerations

### HAProxy SPOA
- Connection pooling: Reuse SPOA connections
- Timeout configuration: Balance between performance and reliability
- Monitoring: Use HAProxy stats for SPOE agent health

### Envoy ext_authz
- gRPC connection reuse: Enable HTTP/2 connection pooling
- Circuit breaking: Configure failure thresholds
- Load balancing: Use multiple auth service instances

### Nginx auth_request
- Caching: Cache auth responses to reduce load
- Connection pooling: Use keepalive connections
- Rate limiting: Protect auth endpoint from abuse

## Monitoring Integration

All proxy integrations support monitoring through:

- Access logs with IP ban status
- Custom headers indicating ban status
- Health check endpoints
- Metrics export (Prometheus compatible)

## Troubleshooting

### Common Issues

1. **SPOA connection failures**: Check network connectivity and firewall rules
2. **gRPC timeouts**: Adjust timeout settings in Envoy configuration
3. **auth_request loops**: Ensure auth endpoint is marked as `internal`
4. **Performance issues**: Enable caching and connection pooling

### Debug Commands

```bash
# Check service connectivity
telnet fail2ban-service 12345  # SPOA
telnet fail2ban-service 9001   # Envoy gRPC
curl fail2ban-service:8888/health  # Nginx

# Test auth decisions
curl -H "X-Real-IP: 1.2.3.4" http://fail2ban-service:8888/auth

# Monitor logs
docker logs fail2ban-service -f
```