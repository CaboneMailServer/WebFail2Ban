# Troubleshooting

This guide helps you diagnose and resolve common issues with Fail2Ban Multi-Proxy.

## General Troubleshooting

### Service Health Check

```bash
# Check if all services are listening
netstat -tlnp | grep -E ':(12345|9001|8888|514)'

# Test service health
curl http://localhost:8888/health
# Expected: {"status":"healthy","service":"fail2ban-nginx-auth"}

# Check Docker containers
docker-compose ps
```

### Log Analysis

```bash
# Real-time service logs
docker logs fail2ban-service -f

# Filter for specific events
docker logs fail2ban-service 2>&1 | grep -E "(ban|violation|error)"

# Check startup logs
docker logs fail2ban-service --since 5m
```

### Configuration Validation

```bash
# Test configuration file syntax
docker run --rm -v ./config.yaml:/app/config.yaml \
  ghcr.io/cabonemailserver/webfail2ban:latest --validate-config

# Check environment variables
docker exec fail2ban-service env | grep FAIL2BAN_
```

## Pattern Detection Issues

### Patterns Not Matching

**Symptoms:**
- Syslog messages received but no violations detected
- Auth failures not triggering bans

**Diagnosis:**
```bash
# Check syslog reception
echo "<134>$(date '+%b %d %H:%M:%S') hostname test: message from 192.168.1.100" | nc -u localhost 514

# Monitor pattern matching
docker logs fail2ban-service -f | grep -E "(pattern|regex|violation)"

# Test regex patterns manually
echo "dovecot: auth failed, method=PLAIN, rip=192.168.1.100" | grep -P "dovecot.*auth failed.*rip=([0-9.]+)"
```

**Solutions:**
1. **Verify regex syntax**: Use online regex testers
2. **Check IP group**: Ensure `ip_group` matches capturing group number
3. **Validate log format**: Compare actual syslog messages with patterns
4. **Check severity levels**: Ensure patterns have appropriate severity

### False Positives

**Symptoms:**
- Legitimate IPs getting banned
- Too many violations detected

**Solutions:**
```yaml
# Increase violation threshold
ban:
  max_attempts: 10        # Increase from default 5
  time_window: "30m"      # Increase window

# Adjust pattern severity
patterns:
  - name: "dovecot_auth_failure"
    severity: 2           # Reduce from 4 to 2
```

## Proxy Integration Issues

### HAProxy SPOA Issues

**Common Problems:**
1. **SPOA connection refused**
2. **Variables not set in HAProxy**
3. **Performance issues**

**Diagnosis:**
```bash
# Test SPOA port
telnet localhost 12345

# Check HAProxy SPOE logs
docker logs haproxy 2>&1 | grep -i spoe

# HAProxy stats
curl http://localhost:8404/stats | grep spoe
```

**Solutions:**
```haproxy
# Increase SPOE timeouts
spoe-agent ip-reputation-agent
    timeout hello      10s    # Increase from 5s
    timeout processing 10s    # Increase from 5s
    timeout idle       60s    # Increase from 30s
```

### Envoy ext_authz Issues

**Common Problems:**
1. **gRPC connection errors**
2. **Authorization timeouts**
3. **Invalid responses**

**Diagnosis:**
```bash
# Check Envoy admin interface
curl http://localhost:9901/stats | grep ext_authz

# Test gRPC health
grpcurl -plaintext localhost:9001 grpc.health.v1.Health/Check

# Check cluster health
curl http://localhost:9901/clusters | grep fail2ban_authz
```

**Solutions:**
```yaml
# Increase timeouts in Envoy config
grpc_service:
  envoy_grpc:
    cluster_name: fail2ban_authz
  timeout: 1s             # Increase from 0.25s

# Add circuit breaker
circuit_breakers:
  thresholds:
  - max_connections: 100
    max_requests: 1000
```

### Nginx auth_request Issues

**Common Problems:**
1. **auth_request module not available**
2. **Internal redirect loops**
3. **Performance issues**

**Diagnosis:**
```bash
# Check if auth_request module is compiled
nginx -V 2>&1 | grep -o with-http_auth_request_module

# Test auth endpoint directly
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth

# Check Nginx error logs
tail -f /var/log/nginx/error.log
```

**Solutions:**
```nginx
# Enable auth response caching
location = /auth {
    internal;
    proxy_pass http://fail2ban_auth/auth;

    # Add caching
    proxy_cache auth_cache;
    proxy_cache_valid 200 10s;
    proxy_cache_valid 403 60s;
}
```

## Network and Connectivity Issues

### Port Conflicts

**Symptoms:**
- Service fails to start
- "Address already in use" errors

**Diagnosis:**
```bash
# Check what's using the ports
ss -tlnp | grep -E ':(12345|9001|8888|514)'
lsof -i :12345

# Check Docker port mapping
docker port fail2ban-service
```

**Solutions:**
1. **Change ports in configuration**
2. **Stop conflicting services**
3. **Use different host ports in Docker**

### Firewall Issues

**Symptoms:**
- Services can't communicate
- External connections rejected

**Diagnosis:**
```bash
# Check iptables rules
iptables -L -n | grep -E '(12345|9001|8888|514)'

# Test connectivity between containers
docker exec haproxy nc -zv fail2ban-service 12345
```

**Solutions:**
```bash
# Allow ports in firewall
ufw allow 12345/tcp
ufw allow 9001/tcp
ufw allow 8888/tcp
ufw allow 514/udp
```

## Performance Issues

### High Memory Usage

**Symptoms:**
- Container using excessive memory
- Out of memory errors

**Diagnosis:**
```bash
# Monitor memory usage
docker stats fail2ban-service

# Check IP cache size
docker logs fail2ban-service | grep -E "(cleanup|memory|cache)"
```

**Solutions:**
```yaml
# Reduce memory usage
ban:
  cleanup_interval: "30s"    # More frequent cleanup
  max_memory_ttl: "24h"      # Reduce from 72h
```

### High CPU Usage

**Symptoms:**
- High CPU utilization
- Slow response times

**Diagnosis:**
```bash
# Profile CPU usage
docker exec fail2ban-service top

# Check for regex performance issues
docker logs fail2ban-service | grep -E "(pattern|regex)" | tail -100
```

**Solutions:**
1. **Optimize regex patterns**: Avoid complex lookaheads
2. **Reduce pattern count**: Combine similar patterns
3. **Increase cleanup intervals**

## Ban Management Issues

### IPs Not Getting Banned

**Symptoms:**
- Violations detected but no bans applied
- Auth endpoint always returns 200

**Diagnosis:**
```bash
# Check violation counts
docker logs fail2ban-service | grep "violation.*192.168.1.100"

# Test manual ban
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth
```

**Solutions:**
```yaml
# Lower ban threshold
ban:
  max_attempts: 3         # Reduce from 5
  time_window: "5m"       # Reduce window
```

### Bans Not Expiring

**Symptoms:**
- IPs remain banned after timeout
- Ban durations incorrect

**Diagnosis:**
```bash
# Check ban expiration logs
docker logs fail2ban-service | grep -E "(expired|cleanup|removed)"

# Verify system time
docker exec fail2ban-service date
```

**Solutions:**
1. **Check system time synchronization**
2. **Verify ban duration configuration**
3. **Restart service to clear cache**

## Debugging Commands

### Enable Debug Logging

```bash
# Set debug level via environment
docker run -e FAIL2BAN_LOG_LEVEL=debug \
  ghcr.io/cabonemailserver/webfail2ban:latest

# Or modify Docker Compose
environment:
  - FAIL2BAN_LOG_LEVEL=debug
```

### Generate Test Traffic

```bash
# Generate auth failures
generate_failures() {
    local ip=${1:-192.168.1.100}
    local count=${2:-6}
    for i in $(seq 1 $count); do
        echo "<134>$(date '+%b %d %H:%M:%S') hostname dovecot: auth failed, method=PLAIN, rip=$ip" | nc -u localhost 514
        sleep 1
    done
}

# Test ban flow
generate_failures "192.168.1.100" 6
sleep 2
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth
```

### Configuration Dump

```bash
# Export current configuration
docker exec fail2ban-service cat /app/config.yaml

# Check environment override
docker exec fail2ban-service env | grep FAIL2BAN_ | sort
```

## Common Error Messages

### "failed to read config file"
- **Cause**: Configuration file not found or invalid YAML
- **Solution**: Check file path and YAML syntax

### "regex compilation failed"
- **Cause**: Invalid regex pattern
- **Solution**: Test regex with online tools, escape special characters

### "connection refused"
- **Cause**: Service not running or port blocked
- **Solution**: Check service status and firewall rules

### "timeout waiting for response"
- **Cause**: Service overloaded or network issues
- **Solution**: Increase timeouts, check resource usage

### "invalid IP address"
- **Cause**: Malformed IP in logs or headers
- **Solution**: Validate IP extraction regex, check log format

## Getting Help

### Collect Debug Information

```bash
# Create debug bundle
mkdir fail2ban-debug
cd fail2ban-debug

# Service logs
docker logs fail2ban-service > service.log 2>&1

# Configuration
docker exec fail2ban-service cat /app/config.yaml > config.yaml

# Environment
docker exec fail2ban-service env | grep FAIL2BAN_ > environment.txt

# System info
docker exec fail2ban-service uname -a > system.txt
docker version > docker.txt
docker-compose version > compose.txt

# Network info
docker network ls > networks.txt
docker port fail2ban-service > ports.txt

# Compress bundle
tar -czf fail2ban-debug.tar.gz *
```

### Log Levels

```bash
# Available log levels
ERROR   # Only errors
WARN    # Warnings and errors
INFO    # General information (default)
DEBUG   # Detailed debugging information
```

### Performance Monitoring

```bash
# Monitor service metrics
watch 'docker stats fail2ban-service --no-stream'

# Check proxy response times
time curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth

# Monitor ban cache
docker logs fail2ban-service | grep -E "(banned|allowed)" | tail -10
```