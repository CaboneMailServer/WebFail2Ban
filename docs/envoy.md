# Envoy Integration (ext_authz)

Envoy integration uses the gRPC ext_authz (External Authorization) service to check IP reputation for incoming requests.

## Overview

The Fail2Ban service exposes a gRPC ext_authz interface (by default on port 9001) for Envoy proxy. This allows Envoy to authorize requests based on IP reputation before routing to backend services.

**Protocol Specification**: [Envoy External Authorization Documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)

- **Protocol**: gRPC over HTTP/2
- **Service**: Authorization service
- **Input**: Client source IP extracted from request headers and connection info
- **Output**: Allow/Deny response with custom headers
- **Default Port**: 9001
- **Use Case**: Envoy proxy service mesh authorization

## Configuration

### Fail2Ban Service Configuration

Configure the Envoy ext_authz service in your `config.yaml`:

```yaml
envoy:
  address: "0.0.0.0"    # Listen address
  port: 9001            # gRPC port
  enabled: true         # Enable/disable Envoy support
```

**Environment Variables:**
- `FAIL2BAN_ENVOY_ADDRESS`
- `FAIL2BAN_ENVOY_PORT`
- `FAIL2BAN_ENVOY_ENABLED`

### Envoy Configuration

Create your Envoy configuration file:

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
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                text_format: |
                  [%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%"
                  %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT%
                  %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% "%REQ(X-FORWARDED-FOR)%"
                  "%REQ(USER-AGENT)%" "%REQ(X-REQUEST-ID)%" "%REQ(:AUTHORITY)%"
                  "%UPSTREAM_HOST%" %DOWNSTREAM_REMOTE_ADDRESS%
                  ext_authz_status=%DYNAMIC_METADATA(envoy.filters.http.ext_authz:ext_authz_status)%
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
                  timeout: 30s
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
              with_request_body:
                max_request_bytes: 1024
                allow_partial_message: true
              clear_route_cache: true
              status_on_error:
                code: 403
              metadata_context_namespaces:
              - envoy.filters.http.ext_authz
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
    health_checks:
    - timeout: 1s
      interval: 10s
      healthy_threshold: 2
      unhealthy_threshold: 3
      http_health_check:
        path: "/health"

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
    health_checks:
    - timeout: 1s
      interval: 5s
      healthy_threshold: 2
      unhealthy_threshold: 2
      grpc_health_check:
        service_name: "envoy.service.auth.v3.Authorization"

admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 9901
```

### Advanced Envoy Configuration

#### Multiple Backend Services

```yaml
# envoy-advanced.yaml
static_resources:
  listeners:
  # HTTP listener with ext_authz
  - name: http_listener
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
            - name: webmail_service
              domains: ["webmail.example.com"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: sogo_cluster
            - name: mail_api
              domains: ["api.example.com"]
              routes:
              - match:
                  prefix: "/api/"
                route:
                  cluster: api_cluster
          http_filters:
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              grpc_service:
                envoy_grpc:
                  cluster_name: fail2ban_authz
                timeout: 0.5s
              failure_mode_allow: false
          - name: envoy.filters.http.router

  # TCP proxy for IMAP with ext_authz
  - name: imap_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 143
    filter_chains:
    - filters:
      - name: envoy.filters.network.ext_authz
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.ext_authz.v3.ExtAuthz
          grpc_service:
            envoy_grpc:
              cluster_name: fail2ban_authz
            timeout: 0.25s
          failure_mode_allow: false
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: imap_tcp
          cluster: dovecot_cluster

  clusters:
  - name: sogo_cluster
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: sogo_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: sogo
                port_value: 80

  - name: api_cluster
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: api_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: api-service
                port_value: 3000

  - name: dovecot_cluster
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: dovecot_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: dovecot
                port_value: 143

  - name: fail2ban_authz
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    http2_protocol_options: {}
    circuit_breakers:
      thresholds:
      - priority: DEFAULT
        max_connections: 100
        max_pending_requests: 10
        max_requests: 1000
        max_retries: 3
    load_assignment:
      cluster_name: fail2ban_authz
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: fail2ban-service
                port_value: 9001
```

## Docker Compose Example

```yaml
version: '3.8'

services:
  fail2ban-service:
    image: ghcr.io/cabonemailserver/webfail2ban:latest
    container_name: fail2ban-service
    ports:
      - "9001:9001"    # Envoy gRPC port
      - "514:514/udp"  # Syslog port
    volumes:
      - ./config.yaml:/app/config.yaml
    restart: unless-stopped

  envoy:
    image: envoyproxy/envoy:v1.28-latest
    container_name: envoy
    ports:
      - "8080:8080"    # HTTP proxy
      - "143:143"      # IMAP proxy
      - "9901:9901"    # Admin interface
    volumes:
      - ./envoy.yaml:/etc/envoy/envoy.yaml
    command: ["envoy", "-c", "/etc/envoy/envoy.yaml", "--service-cluster", "fail2ban-proxy"]
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

  dovecot:
    image: dovecot/dovecot:latest
    container_name: dovecot
    ports:
      - "993:993"
    restart: unless-stopped

  api-service:
    image: node:18-alpine
    container_name: api-service
    ports:
      - "3000:3000"
    restart: unless-stopped
```

## Rate Limiting Integration

Combine IP reputation with rate limiting:

```yaml
http_filters:
- name: envoy.filters.http.local_ratelimit
  typed_config:
    "@type": type.googleapis.com/udpa.type.v1.TypedStruct
    type_url: type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
    value:
      stat_prefix: local_rate_limiter
      token_bucket:
        max_tokens: 10
        tokens_per_fill: 10
        fill_interval: 60s
      filter_enabled:
        runtime_key: local_rate_limit_enabled
        default_value:
          numerator: 100
          denominator: HUNDRED
      filter_enforced:
        runtime_key: local_rate_limit_enforced
        default_value:
          numerator: 100
          denominator: HUNDRED

- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service:
      envoy_grpc:
        cluster_name: fail2ban_authz
      timeout: 0.25s
    failure_mode_allow: false
```

## Testing and Debugging

### Test ext_authz Service

```bash
# Test HTTP request through Envoy
curl -H "Host: example.com" http://localhost:8080/

# Test with specific source IP
curl -H "X-Forwarded-For: 192.168.1.100" http://localhost:8080/

# Test IMAP connection through Envoy
telnet localhost 143
```

### Envoy Admin Interface

```bash
# Check Envoy configuration
curl http://localhost:9901/config_dump

# Check cluster health
curl http://localhost:9901/clusters | grep fail2ban_authz

# Check statistics
curl http://localhost:9901/stats | grep ext_authz

# Check listeners
curl http://localhost:9901/listeners
```

### gRPC Health Checks

```bash
# Install grpcurl for testing
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Test gRPC health check
grpcurl -plaintext localhost:9001 grpc.health.v1.Health/Check

# Test authorization service directly
grpcurl -plaintext -d '{"attributes": {"source": {"address": {"socket_address": {"address": "192.168.1.1", "port_value": 12345}}}}}' \
  localhost:9001 envoy.service.auth.v3.Authorization/Check
```

### Monitor ext_authz Requests

```bash
# Real-time Envoy access logs
docker logs envoy -f | grep ext_authz

# Filter for denied requests
docker logs envoy -f | grep "ext_authz_status=DENIED"

# Check authorization statistics
curl -s http://localhost:9901/stats | grep -E "ext_authz\.(ok|denied|error|timeout)"
```

## Performance Optimization

### Connection Pooling

```yaml
clusters:
- name: fail2ban_authz
  http2_protocol_options:
    max_concurrent_streams: 100
  upstream_connection_options:
    tcp_keepalive:
      keepalive_probes: 3
      keepalive_time: 30
      keepalive_interval: 5
```

### Circuit Breaker

```yaml
circuit_breakers:
  thresholds:
  - priority: DEFAULT
    max_connections: 50
    max_pending_requests: 20
    max_requests: 500
    max_retries: 2
    retry_budget:
      budget_percent:
        value: 25.0
      min_retry_concurrency: 5
```

## Authorization Response Caching

Envoy provides multiple built-in caching mechanisms for ext_authz responses:

### Built-in Authorization Result Caching

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service:
      envoy_grpc:
        cluster_name: fail2ban_authz
      timeout: 0.25s

    # Enable result caching
    allowed_headers:
      patterns:
      - exact: "cache-control"
      - exact: "expires"

    # Cache configuration
    filter_enabled_metadata:
      filter: envoy.filters.http.ext_authz
      path:
      - key: cache_result
      value:
        bool_value: true
```

### HTTP Cache Filter Integration

```yaml
http_filters:
# Add HTTP cache filter before ext_authz
- name: envoy.filters.http.cache
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.cache.v3.CacheConfig
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.cache.simple_http_cache.v3.SimpleHttpCacheConfig
      cache_size_bytes: 10485760  # 10MB cache for auth responses
    cache_config:
      max_body_bytes: 1024
      allowed_vary_headers:
      - exact: "x-forwarded-for"
      - exact: "x-real-ip"

- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service:
      envoy_grpc:
        cluster_name: fail2ban_authz
      timeout: 0.25s

    # Configure caching headers
    status_on_error:
      code: 403
    clear_route_cache: false  # Keep route cache for performance
```

### Advanced Caching with TTL

Configure the Fail2Ban service to return appropriate cache headers:

```yaml
# In your Fail2Ban service, modify the gRPC response to include cache headers
# This would be implemented in the Envoy ext_authz server code

# Example response headers for caching:
# - Allowed IPs: Cache-Control: max-age=60 (cache for 1 minute)
# - Banned IPs: Cache-Control: max-age=300 (cache for 5 minutes)
```

### Cluster-level Caching

```yaml
clusters:
- name: fail2ban_authz
  connect_timeout: 0.25s
  type: LOGICAL_DNS
  lb_policy: ROUND_ROBIN
  http2_protocol_options: {}

  # Enable upstream caching
  upstream_connection_options:
    tcp_keepalive:
      keepalive_probes: 3
      keepalive_time: 30
      keepalive_interval: 5

  # Circuit breaker with caching considerations
  circuit_breakers:
    thresholds:
    - priority: DEFAULT
      max_connections: 100
      max_pending_requests: 20
      max_requests: 1000
      max_retries: 2
      track_remaining: true

  load_assignment:
    cluster_name: fail2ban_authz
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: fail2ban-service
              port_value: 9001
```

### Redis-based Distributed Caching

For multi-instance Envoy deployments:

```yaml
# Add Redis cluster for shared caching
- name: redis_cache
  connect_timeout: 0.25s
  type: LOGICAL_DNS
  lb_policy: ROUND_ROBIN
  load_assignment:
    cluster_name: redis_cache
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: redis
              port_value: 6379

# Configure cache filter with Redis backend
http_filters:
- name: envoy.filters.http.cache
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.cache.v3.CacheConfig
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.cache.redis.v3.RedisConfig
      cluster_name: redis_cache
      key_prefix: "auth_cache:"
      default_ttl: 300s  # 5 minutes default TTL
```

## Troubleshooting

### Common Issues

1. **gRPC connection errors**
   - Verify Fail2Ban service is listening on port 9001
   - Check if HTTP/2 is properly configured
   - Ensure network connectivity between Envoy and Fail2Ban service

2. **Authorization timeouts**
   - Adjust timeout settings in ext_authz configuration
   - Check Fail2Ban service performance
   - Monitor gRPC response times

3. **Invalid gRPC responses**
   - Verify gRPC service implementation
   - Check protocol buffer definitions
   - Ensure proper error handling

### Debug Commands

```bash
# Test Envoy configuration syntax
envoy --mode validate --config-path /etc/envoy/envoy.yaml

# Enable debug logging
curl -X POST "http://localhost:9901/logging?level=debug"

# Check active connections
curl http://localhost:9901/stats | grep cx_

# View runtime configuration
curl http://localhost:9901/runtime
```

### Health Check Configuration

```yaml
health_checks:
- timeout: 1s
  interval: 5s
  no_traffic_interval: 5s
  healthy_threshold: 2
  unhealthy_threshold: 3
  grpc_health_check:
    service_name: "envoy.service.auth.v3.Authorization"
    authority: "fail2ban-service"
```

## Security Considerations

- Configure proper TLS for production environments
- Use dedicated networks for authorization service communication
- Implement proper error handling and fallback strategies
- Monitor authorization service availability and performance
- Consider implementing authorization result caching for high-traffic scenarios
- Use circuit breakers to prevent cascade failures