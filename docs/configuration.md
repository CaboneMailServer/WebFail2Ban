# Configuration

## Configuration Files

The service uses YAML configuration files. The configuration is loaded from:

1. `./config.yaml` (current directory)
2. `/etc/fail2ban-haproxy/config.yaml`

## Environment Variables

All configuration options can be overridden using environment variables with the `FAIL2BAN_` prefix.

For nested configuration, use underscores to separate levels:
- `FAIL2BAN_SYSLOG_ADDRESS` → `syslog.address`
- `FAIL2BAN_SPOA_PORT` → `spoa.port`
- `FAIL2BAN_BAN_MAX_ATTEMPTS` → `ban.max_attempts`

## Complete Configuration Example

```yaml
# Syslog configuration
syslog:
  address: "127.0.0.1:514"     # Syslog server address
  protocol: "udp"              # Protocol: udp or tcp
  patterns:                    # Detection patterns
    - name: "dovecot_auth_failure"
      regex: "dovecot.*auth failed.*rip=([0-9.]+)"
      ip_group: 1
      severity: 4
      description: "Dovecot authentication failure"

    - name: "postfix_sasl_failure"
      regex: "postfix.*SASL.*authentication failed.*\\[([0-9.]+)\\]"
      ip_group: 1
      severity: 4
      description: "Postfix SASL authentication failure"

    - name: "sogo_login_failure"
      regex: "sogod.*Login failed for user.*from ([0-9.]+)"
      ip_group: 1
      severity: 3
      description: "SOGo login failure"

# HAProxy SPOA configuration
spoa:
  address: "0.0.0.0"           # Listen address
  port: 12345                  # SPOA port
  max_clients: 100             # Maximum concurrent clients
  read_timeout: "30s"          # Client read timeout
  enabled: true                # Enable/disable SPOA support

# Envoy ext_authz configuration
envoy:
  address: "0.0.0.0"           # Listen address
  port: 9001                   # gRPC port
  enabled: true                # Enable/disable Envoy support

# Nginx auth_request configuration
nginx:
  address: "0.0.0.0"           # Listen address
  port: 8888                   # HTTP port
  enabled: true                # Enable/disable Nginx support
  read_timeout: "10s"          # Request read timeout
  write_timeout: "10s"         # Response write timeout
  return_json: false           # Return JSON error responses

# Ban configuration
ban:
  initial_ban_time: "5m"       # Initial ban duration
  max_ban_time: "24h"          # Maximum ban duration
  escalation_factor: 2.0       # Ban time escalation factor
  max_attempts: 5              # Attempts before ban
  time_window: "10m"           # Time window for attempts
  cleanup_interval: "1m"       # Cleanup interval for expired IPs
  max_memory_ttl: "72h"        # Maximum IP storage time in memory
```

## Configuration Sections

### Syslog Configuration

```yaml
syslog:
  address: "127.0.0.1:514"
  protocol: "udp"              # udp or tcp
  patterns: [...]              # See Pattern Configuration below
```

**Environment Variables:**
- `FAIL2BAN_SYSLOG_ADDRESS`
- `FAIL2BAN_SYSLOG_PROTOCOL`

### Pattern Configuration

Patterns define how to detect suspicious activity from log messages:

```yaml
patterns:
  - name: "service_auth_failure"
    regex: "service.*failed login.*from ([0-9.]+)"
    ip_group: 1                # Regex group containing the IP
    severity: 4                # Severity level (1-6)
    description: "Service authentication failure"
```

**Pattern Fields:**
- `name`: Unique pattern identifier
- `regex`: Regular expression to match log lines
- `ip_group`: Capture group number containing the IP address
- `severity`: Severity level (1=low, 6=critical)
- `description`: Human-readable description

**Severity Levels:**
- **1-2**: Light attempts (non-existent user, expired session)
- **3-4**: Failed authentication attempts
- **5-6**: Brute force and repeated abuse

### SPOA Configuration (HAProxy)

```yaml
spoa:
  address: "0.0.0.0"
  port: 12345
  max_clients: 100
  read_timeout: "30s"
  enabled: true
```

**Environment Variables:**
- `FAIL2BAN_SPOA_ADDRESS`
- `FAIL2BAN_SPOA_PORT`
- `FAIL2BAN_SPOA_MAX_CLIENTS`
- `FAIL2BAN_SPOA_READ_TIMEOUT`
- `FAIL2BAN_SPOA_ENABLED`

### Envoy Configuration

```yaml
envoy:
  address: "0.0.0.0"
  port: 9001
  enabled: true
```

**Environment Variables:**
- `FAIL2BAN_ENVOY_ADDRESS`
- `FAIL2BAN_ENVOY_PORT`
- `FAIL2BAN_ENVOY_ENABLED`

### Nginx Configuration

```yaml
nginx:
  address: "0.0.0.0"
  port: 8888
  enabled: true
  read_timeout: "10s"
  write_timeout: "10s"
  return_json: false
```

**Environment Variables:**
- `FAIL2BAN_NGINX_ADDRESS`
- `FAIL2BAN_NGINX_PORT`
- `FAIL2BAN_NGINX_ENABLED`
- `FAIL2BAN_NGINX_READ_TIMEOUT`
- `FAIL2BAN_NGINX_WRITE_TIMEOUT`
- `FAIL2BAN_NGINX_RETURN_JSON`

### Ban Configuration

```yaml
ban:
  initial_ban_time: "5m"
  max_ban_time: "24h"
  escalation_factor: 2.0
  max_attempts: 5
  time_window: "10m"
  cleanup_interval: "1m"
  max_memory_ttl: "72h"
```

**Environment Variables:**
- `FAIL2BAN_BAN_INITIAL_BAN_TIME`
- `FAIL2BAN_BAN_MAX_BAN_TIME`
- `FAIL2BAN_BAN_ESCALATION_FACTOR`
- `FAIL2BAN_BAN_MAX_ATTEMPTS`
- `FAIL2BAN_BAN_TIME_WINDOW`
- `FAIL2BAN_BAN_CLEANUP_INTERVAL`
- `FAIL2BAN_BAN_MAX_MEMORY_TTL`

**Ban Logic:**
1. Count violations within `time_window`
2. Ban IP after `max_attempts` violations
3. Start with `initial_ban_time`, escalate by `escalation_factor`
4. Maximum ban time is `max_ban_time`
5. Clean up expired bans every `cleanup_interval`

## Service-Specific Patterns

### Dovecot (IMAP/POP3)

```yaml
patterns:
  - name: "dovecot_auth_failure"
    regex: "dovecot.*auth failed.*rip=([0-9.]+)"
    ip_group: 1
    severity: 4
    description: "Dovecot authentication failure"

  - name: "dovecot_unknown_user"
    regex: "dovecot.*unknown user.*rip=([0-9.]+)"
    ip_group: 1
    severity: 2
    description: "Dovecot unknown user attempt"
```

### Postfix (SMTP)

```yaml
patterns:
  - name: "postfix_sasl_failure"
    regex: "postfix.*SASL.*authentication failed.*\\[([0-9.]+)\\]"
    ip_group: 1
    severity: 4
    description: "Postfix SASL authentication failure"

  - name: "postfix_relay_denied"
    regex: "postfix.*Relay access denied.*\\[([0-9.]+)\\]"
    ip_group: 1
    severity: 3
    description: "Postfix relay access denied"
```

### SOGo (Webmail)

```yaml
patterns:
  - name: "sogo_login_failure"
    regex: "sogod.*Login failed for user.*from ([0-9.]+)"
    ip_group: 1
    severity: 3
    description: "SOGo login failure"

  - name: "sogo_expired_session"
    regex: "sogod.*expired session.*from ([0-9.]+)"
    ip_group: 1
    severity: 1
    description: "SOGo expired session"
```

## Docker Environment Variables

When using Docker, you can override configuration via environment variables:

```bash
docker run -d \
  -e FAIL2BAN_SPOA_PORT=12345 \
  -e FAIL2BAN_ENVOY_PORT=9001 \
  -e FAIL2BAN_NGINX_PORT=8888 \
  -e FAIL2BAN_BAN_MAX_ATTEMPTS=3 \
  -e FAIL2BAN_BAN_INITIAL_BAN_TIME=10m \
  mailfail2ban
```

## Configuration Validation

The service validates configuration on startup:

- Pattern regex compilation
- Port availability
- Time duration parsing
- Required fields presence

Invalid configuration will prevent service startup with detailed error messages.

## Configuration Reloading

Currently, configuration changes require service restart. Hot reloading is planned for future versions.

## Advanced Detection Patterns

### Severity Levels
- **1-2**: Light attempts (non-existent user, expired session)
- **3-4**: Failed authentication attempts
- **5-6**: Brute force and repeated abuse

### Automatic Escalation
1. **First ban**: 5 minutes
2. **Second ban**: 10 minutes
3. **Third ban**: 20 minutes
4. **Fourth ban**: 40 minutes
5. **Maximum**: 24 hours

### Memory Management
- **Automatic cleanup**: every minute
- **Maximum TTL**: 72 hours in memory
- **Ban expiration**: automatic according to duration

## Monitoring and Observability

### Structured Logs
Logs include:
- Pattern violation detections
- IP bans with durations
- Ban expirations
- Cleanup statistics
- Performance metrics

### Available Metrics (prometheus exporter)
- Number of active banned IPs
- Violations per service
- False positive rate
- Radix tree performance

## Security Considerations

- Use restrictive file permissions for config files (600 or 640)
- Avoid storing sensitive information in environment variables in production
- Consider using Docker secrets or Kubernetes secrets for sensitive data
- Validate regex patterns to prevent ReDoS attacks
- **Strict IP validation** (IPv4/IPv6)
- **Memory limits** with automatic TTL
- **Graceful shutdown** of services
- **Network error handling** and timeouts
- **Complete containerized isolation**
- **Complete audit logs**