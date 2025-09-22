# HAProxy Integration (SPOA)

HAProxy integration uses the SPOA (Stream Processing Offload Agent) protocol to check IP reputation in real-time.

## Overview

The Fail2Ban service exposes a SPOA interface (by default on port 12345) for HAProxy. This allows HAProxy to query the ban status of client IPs before forwarding requests.

**Protocol Specification**: [HAProxy SPOE Documentation](https://www.haproxy.org/download/1.8/doc/SPOE.txt)

- **Input**: Client source IP
- **Output**: `banned=1` if IP is banned, `banned=0` otherwise
- **Protocol Type**: Binary TCP protocol
- **Default Port**: 12345
- **Use Case**: HAProxy load balancer authorization

## Configuration

### Fail2Ban Service Configuration

Configure the SPOA service in your `config.yaml`:

```yaml
spoa:
  address: "0.0.0.0"      # Listen address
  port: 12345             # SPOA port
  max_clients: 100        # Maximum concurrent clients
  read_timeout: "30s"     # Client read timeout
  enabled: true           # Enable/disable SPOA support
```

**Environment Variables:**
- `FAIL2BAN_SPOA_ADDRESS`
- `FAIL2BAN_SPOA_PORT`
- `FAIL2BAN_SPOA_MAX_CLIENTS`
- `FAIL2BAN_SPOA_READ_TIMEOUT`
- `FAIL2BAN_SPOA_ENABLED`

### HAProxy Configuration

Create your HAProxy configuration file:

```haproxy
# /etc/haproxy/haproxy.cfg
global
    daemon
    stats socket /var/run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    log global

# SPOE backend for IP reputation check
backend spoe-ip-reputation
    mode tcp
    server ip-reputation 127.0.0.1:12345 check inter 5s

# Frontend with SPOE filter for HTTP services
frontend http-frontend
    bind *:80
    mode http

    # SPOE filter for IP reputation check
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf

    # Check if IP is banned and reject if so
    http-request deny if { var(txn.banned) -m int eq 1 }

    # Add custom header with ban status for debugging
    http-request set-header X-IP-Status allowed if { var(txn.banned) -m int eq 0 }
    http-request set-header X-IP-Status banned if { var(txn.banned) -m int eq 1 }

    default_backend http-backend

# Frontend with SPOE filter for TCP services (IMAP, SMTP)
frontend imap-frontend
    bind *:143
    mode tcp

    # SPOE filter for IP reputation check
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf

    # Check if IP is banned and reject TCP connection
    tcp-request content reject if { var(sess.banned) -m int eq 1 }

    default_backend imap-backend

frontend smtp-frontend
    bind *:25
    mode tcp

    # SPOE filter for IP reputation check
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf

    # Check if IP is banned
    tcp-request content reject if { var(sess.banned) -m int eq 1 }

    default_backend smtp-backend

# Backend services
backend http-backend
    mode http
    balance roundrobin
    server web1 127.0.0.1:8080 check
    server web2 127.0.0.1:8081 check

backend imap-backend
    mode tcp
    balance roundrobin
    server dovecot1 127.0.0.1:993 check
    server dovecot2 127.0.0.1:994 check

backend smtp-backend
    mode tcp
    balance roundrobin
    server postfix1 127.0.0.1:26 check
    server postfix2 127.0.0.1:27 check

# HAProxy statistics
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
```

### SPOE Configuration

Create the SPOE configuration file `/etc/haproxy/spoe-ip-reputation.conf`:

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
    log global

spoe-message check-ip
    args src_ip=src
    event on-client-session if TRUE
```

## Docker Compose Example

Here's a complete Docker Compose setup:

```yaml
version: '3.8'

services:
  fail2ban-service:
    image: ghcr.io/cabonemailserver/webfail2ban:latest
    container_name: fail2ban-service
    ports:
      - "12345:12345"  # SPOA port
      - "514:514/udp"  # Syslog port
    volumes:
      - ./config.yaml:/app/config.yaml
    restart: unless-stopped

  haproxy:
    image: haproxy:2.8
    container_name: haproxy
    ports:
      - "80:80"        # HTTP
      - "143:143"      # IMAP
      - "25:25"        # SMTP
      - "8404:8404"    # Stats
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg
      - ./spoe-ip-reputation.conf:/etc/haproxy/spoe-ip-reputation.conf
    depends_on:
      - fail2ban-service
    restart: unless-stopped

  # Example backend services
  dovecot:
    image: dovecot/dovecot:latest
    container_name: dovecot
    ports:
      - "993:993"
    restart: unless-stopped

  postfix:
    image: postfix:latest
    container_name: postfix
    ports:
      - "26:25"
    restart: unless-stopped
```

## Advanced Configuration

### SSL/TLS Termination

```haproxy
frontend https-frontend
    bind *:443 ssl crt /etc/ssl/certs/example.com.pem
    mode http

    # SPOE filter for IP reputation check
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf

    # Redirect to HTTPS
    redirect scheme https code 301 if !{ ssl_fc }

    # Check if IP is banned
    http-request deny if { var(txn.banned) -m int eq 1 }

    default_backend https-backend
```

### Rate Limiting with IP Reputation

```haproxy
# Stick table for rate limiting
backend stick-table
    stick-table type ip size 100k expire 30s store http_req_rate(10s)

frontend rate-limited-frontend
    bind *:80
    mode http

    # SPOE filter for IP reputation check
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf

    # Track requests in stick table
    http-request track-sc0 src table stick-table

    # Deny banned IPs immediately
    http-request deny if { var(txn.banned) -m int eq 1 }

    # Apply rate limiting to non-banned IPs
    http-request deny if { sc_http_req_rate(0) gt 20 }

    default_backend web-backend
```

### Multiple SPOE Agents

```haproxy
# Multiple SPOE agents for redundancy
backend spoe-ip-reputation-primary
    mode tcp
    server primary-agent 127.0.0.1:12345 check

backend spoe-ip-reputation-backup
    mode tcp
    server backup-agent 127.0.0.1:12346 check backup
```

## Testing and Debugging

### Test SPOA Connection

```bash
# Test if SPOA port is listening
telnet localhost 12345

# Check HAProxy stats
curl http://localhost:8404/stats

# Check SPOE agent status in stats
curl http://localhost:8404/stats | grep spoe
```

### HAProxy Logs

Enable detailed logging to debug SPOE interactions:

```haproxy
global
    log stdout local0 debug

defaults
    option httplog
    option log-health-checks
    log global
```

### Check SPOE Messages

```bash
# Enable debug mode in HAProxy configuration
echo "set logging debug" | socat stdio /var/run/haproxy/admin.sock

# View real-time logs
tail -f /var/log/haproxy.log | grep -i spoe
```

### Test Ban Functionality

```bash
# Generate auth failures to ban an IP
for i in {1..6}; do
    echo "<134>$(date '+%b %d %H:%M:%S') hostname dovecot: auth failed, method=PLAIN, rip=192.168.1.100" | nc -u localhost 514
    sleep 1
done

# Test if IP is blocked through HAProxy
curl -H "X-Forwarded-For: 192.168.1.100" http://localhost:80/
# Should receive 403 or connection refused
```

## Authorization Response Caching

HAProxy doesn't have built-in caching for SPOA responses, but you can implement caching strategies:

### Manual Response Caching

```haproxy
# Use stick tables to cache ban decisions
backend stick-table-cache
    stick-table type ip size 10k expire 60s store gpc0

frontend http-frontend
    bind *:80

    # Check cache first
    http-request track-sc0 src table stick-table-cache
    http-request set-var(txn.cached_banned) sc_get_gpc0(0) if { sc_tracked(0) }

    # Skip SPOE if we have cached result
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf if !{ var(txn.cached_banned) -m found }

    # Use cached result or SPOE result
    http-request deny if { var(txn.cached_banned) eq 1 }
    http-request deny if { var(txn.banned) -m int eq 1 }

    # Cache the SPOE result
    http-request sc-set-gpc0(0) 1 if { var(txn.banned) -m int eq 1 }

    default_backend web-backend
```

### Stick Table Caching Strategy

```haproxy
# Create dedicated cache table
backend ip-reputation-cache
    stick-table type ip size 100k expire 300s store gpc0,gpc1
    # gpc0 = ban status (0=allowed, 1=banned)
    # gpc1 = timestamp of last check

# Enhanced frontend with caching
frontend cached-frontend
    bind *:80

    # Track IP in cache table
    http-request track-sc0 src table ip-reputation-cache

    # Get cached values
    http-request set-var(txn.cached_status) sc_get_gpc0(0)
    http-request set-var(txn.cache_time) sc_get_gpc1(0)
    http-request set-var(txn.current_time) date()

    # Use cache if fresh (less than 60 seconds old)
    http-request set-var(txn.cache_age) sub(%[var(txn.current_time)],%[var(txn.cache_time)])
    http-request set-var(txn.use_cache) bool(1) if { var(txn.cache_age) lt 60000 }

    # Apply cached decision
    http-request deny if { var(txn.use_cache) -m bool } { var(txn.cached_status) eq 1 }
    http-request accept if { var(txn.use_cache) -m bool } { var(txn.cached_status) eq 0 }

    # If no cache or expired, use SPOE
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf if !{ var(txn.use_cache) -m bool }

    # Cache new SPOE result
    http-request sc-set-gpc0(0) 1 if !{ var(txn.use_cache) -m bool } { var(txn.banned) -m int eq 1 }
    http-request sc-set-gpc0(0) 0 if !{ var(txn.use_cache) -m bool } { var(txn.banned) -m int eq 0 }
    http-request sc-set-gpc1(0) int(%[date()]) if !{ var(txn.use_cache) -m bool }

    # Apply SPOE decision
    http-request deny if { var(txn.banned) -m int eq 1 }

    default_backend web-backend
```

### Redis-based Caching (Advanced)

For distributed setups, you can use Redis with Lua scripts:

```haproxy
# Use Lua script for Redis caching
lua-load /etc/haproxy/redis-cache.lua

frontend redis-cached-frontend
    bind *:80

    # Check Redis cache first
    http-request lua.check_redis_cache

    # Use cached result if available
    http-request deny if { var(txn.redis_banned) eq 1 }
    http-request accept if { var(txn.redis_cached) -m bool }

    # If not cached, use SPOE
    filter spoe engine ip-reputation config /etc/haproxy/spoe-ip-reputation.conf if !{ var(txn.redis_cached) -m bool }

    # Cache SPOE result in Redis
    http-request lua.cache_redis_result if !{ var(txn.redis_cached) -m bool }

    # Apply SPOE decision
    http-request deny if { var(txn.banned) -m int eq 1 }

    default_backend web-backend
```

## Performance Considerations

### Connection Pooling
- HAProxy reuses SPOA connections automatically
- Configure `max_clients` based on expected concurrent connections
- Monitor connection usage via HAProxy stats

### Timeout Configuration
```haproxy
spoe-agent ip-reputation-agent
    timeout hello      2s    # Fast handshake
    timeout idle       30s   # Keep connections alive
    timeout processing 1s    # Quick IP lookups
```

### Monitoring
- Use HAProxy stats interface to monitor SPOE agent health
- Track response times and error rates
- Set up alerts for SPOE agent failures

## Troubleshooting

### Common Issues

1. **SPOA connection refused**
   - Check if Fail2Ban service is running on correct port
   - Verify firewall rules allow connections on port 12345
   - Check network connectivity between HAProxy and Fail2Ban service

2. **Variables not set**
   - Ensure SPOE configuration has correct variable names
   - Check `option var-prefix` in SPOE agent configuration
   - Verify message arguments match expected format

3. **Performance issues**
   - Increase `max_clients` if connection limit reached
   - Adjust timeouts for faster responses
   - Consider multiple SPOE agents for load distribution

### Debug Commands

```bash
# Check HAProxy configuration syntax
haproxy -c -f /etc/haproxy/haproxy.cfg

# View HAProxy process information
echo "show info" | socat stdio /var/run/haproxy/admin.sock

# Show SPOE agents status
echo "show backends" | socat stdio /var/run/haproxy/admin.sock | grep spoe

# Show current connections
echo "show sess" | socat stdio /var/run/haproxy/admin.sock
```

## Security Considerations

- Use dedicated network for SPOA communication
- Implement proper firewall rules
- Monitor for SPOA agent availability
- Configure appropriate error handling when SPOA is unavailable
- Consider SSL/TLS for SPOA communication in production environments