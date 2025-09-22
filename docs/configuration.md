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

Currently, configuration changes require service restart, except when using database configuration which supports hot reloading.

## Database Configuration

### Overview

The service supports externalizing patterns and ban configuration to SQL databases (SQLite, MySQL, PostgreSQL) with automatic fallback to file configuration. This enables:

- **Hot configuration reloading** without service restart
- **Centralized configuration management** across multiple instances
- **Configuration persistence** with automatic failure recovery
- **Fallback to file configuration** when database is unavailable

### Database Configuration

```yaml
database:
  enabled: true                    # Enable database configuration
  driver: "sqlite3"                # Database driver: sqlite3, mysql, postgres
  dsn: "./fail2ban.db"            # Data Source Name
  refresh_interval: "5m"           # How often to reload config from DB
  max_retries: 3                   # Maximum retry attempts on failure
  retry_delay: "5s"               # Delay between retry attempts
```

**Environment Variables:**
- `FAIL2BAN_DATABASE_ENABLED`
- `FAIL2BAN_DATABASE_DRIVER`
- `FAIL2BAN_DATABASE_DSN`
- `FAIL2BAN_DATABASE_REFRESH_INTERVAL`
- `FAIL2BAN_DATABASE_MAX_RETRIES`
- `FAIL2BAN_DATABASE_RETRY_DELAY`

### Database Connection Examples

#### SQLite (Default)
```yaml
database:
  enabled: true
  driver: "sqlite3"
  dsn: "./fail2ban.db"
```

#### MySQL
```yaml
database:
  enabled: true
  driver: "mysql"
  dsn: "user:password@tcp(localhost:3306)/fail2ban"
```

#### PostgreSQL
```yaml
database:
  enabled: true
  driver: "postgres"
  dsn: "postgres://user:password@localhost/fail2ban?sslmode=disable"
```

### Database Schema

The service automatically creates the required tables:

#### Patterns Table
```sql
CREATE TABLE patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE,
    regex TEXT NOT NULL,
    ip_group INTEGER NOT NULL DEFAULT 1,
    severity INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Ban Configuration Table
```sql
CREATE TABLE ban_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE,
    initial_ban_time_seconds INTEGER NOT NULL,
    max_ban_time_seconds INTEGER NOT NULL,
    escalation_factor REAL NOT NULL,
    max_attempts INTEGER NOT NULL,
    time_window_seconds INTEGER NOT NULL,
    cleanup_interval_seconds INTEGER NOT NULL,
    max_memory_ttl_seconds INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Failure Handling and Fallback

The configuration manager implements robust failure handling:

#### 🔄 **Configuration Caching**
- **Last known good configuration** is cached in memory
- **Automatic fallback** to cached config during database outages
- **File configuration** used as ultimate fallback

#### 📊 **Failure Tracking**
- **Failure counter** tracks consecutive database errors
- **Connection status** monitoring with real-time health checks
- **Automatic recovery** detection and logging

#### ⚡ **Hot Reloading**
- **No service interruption** during configuration updates
- **Atomic configuration updates** - either all changes apply or none
- **Change notifications** via update channels

### Configuration Priority

The service uses the following priority order:

1. **Database configuration** (if enabled and connected)
2. **Cached database configuration** (if database temporarily unavailable)
3. **File configuration** (ultimate fallback)

### Monitoring Database Configuration

#### Configuration Source Tracking
```bash
# Check configuration source via metrics endpoint
curl http://localhost:8888/config/source

# Response example:
{
  "patterns_source": "database_cached",
  "ban_config_source": "database_cached",
  "database_enabled": true,
  "database_connected": false
}
```

#### Database Status Monitoring
```bash
# Check database status
curl http://localhost:8888/database/status

# Response example:
{
  "enabled": true,
  "connected": false,
  "driver": "sqlite3",
  "failure_count": 3,
  "last_successful_load": "2024-01-15T10:30:00Z",
  "has_cached_config": true,
  "last_error": "database connection timeout"
}
```

### Prometheus Metrics

Database-related metrics are available:

```prometheus
# Database operations
fail2ban_database_operations_total{operation="reload",status="success"} 45
fail2ban_database_operations_total{operation="reload",status="failure"} 3

# Configuration reloads
fail2ban_config_reloads_total{source="database",status="success"} 42
fail2ban_config_reloads_total{source="file",status="success"} 1

# Patterns loaded
fail2ban_config_patterns_loaded 15
```

### Best Practices

#### High Availability
- Use **database clustering** for production deployments
- Configure **appropriate timeouts** for your environment
- Monitor **failure counts** and set up alerts
- Test **failover scenarios** regularly

#### Performance
- Set **refresh_interval** based on your change frequency (default: 5m)
- Use **connection pooling** for high-traffic deployments
- Consider **read replicas** for distributed configurations

#### Security
- Use **encrypted connections** to database in production
- Implement **proper access controls** on database
- **Audit configuration changes** through database logs
- Use **secrets management** for database credentials

## Prometheus Configuration

```yaml
prometheus:
  enabled: true                    # Enable Prometheus metrics
  address: "0.0.0.0"              # Listen address
  port: 2112                       # Metrics port
  path: "/metrics"                 # Metrics endpoint path
```

**Environment Variables:**
- `FAIL2BAN_PROMETHEUS_ENABLED`
- `FAIL2BAN_PROMETHEUS_ADDRESS`
- `FAIL2BAN_PROMETHEUS_PORT`
- `FAIL2BAN_PROMETHEUS_PATH`

### Available Metrics

- **Request counters**: Total requests by service and result
- **Ban metrics**: Total bans, current bans, ban durations
- **Pattern metrics**: Pattern matches by pattern and severity
- **Database metrics**: Operations, connection status, reload stats
- **Service metrics**: Request duration, uptime, build info

## API Security Configuration

The Ban Management API includes comprehensive security features including IP filtering, basic authentication, and rate limiting.

```yaml
api:
  enabled: true
  allowed_ips:                    # IP addresses and CIDR ranges allowed to access API
    - "127.0.0.1/32"              # localhost IPv4
    - "::1/128"                   # localhost IPv6
    - "10.0.0.0/8"                # Private network
    - "192.168.1.100"             # Specific admin IP
  basic_auth:
    enabled: true
    username: "admin"             # Single user auth
    password: "secure_password"
    users:                        # Multiple users auth (alternative to single user)
      admin: "admin_password"
      operator: "operator_password"
      readonly: "readonly_password"
  rate_limiting:
    enabled: true
    requests_per_minute: 60       # Max requests per IP per minute
```

**Environment Variables:**
- `FAIL2BAN_API_ENABLED`
- `FAIL2BAN_API_ALLOWED_IPS`
- `FAIL2BAN_API_BASIC_AUTH_ENABLED`
- `FAIL2BAN_API_BASIC_AUTH_USERNAME`
- `FAIL2BAN_API_BASIC_AUTH_PASSWORD`
- `FAIL2BAN_API_RATE_LIMITING_ENABLED`
- `FAIL2BAN_API_RATE_LIMITING_REQUESTS_PER_MINUTE`

### Security Features

#### IP Address Filtering
- **CIDR Support**: Configure IP ranges using CIDR notation
- **IPv4 and IPv6**: Full support for both IP versions
- **Multiple Ranges**: Allow multiple IP addresses and ranges
- **Default**: Localhost only (127.0.0.1/32, ::1/128)

#### Basic Authentication
- **Single User**: Simple username/password configuration
- **Multiple Users**: Support for multiple username/password pairs
- **Constant-time Comparison**: Prevents timing attacks
- **Optional**: Can be disabled for internal networks

#### Rate Limiting
- **Per-IP Limiting**: Track requests per client IP address
- **Configurable Window**: Default 60 requests per minute
- **Memory Efficient**: Automatic cleanup of old request data
- **Graceful Degradation**: API remains available if rate limiter fails

### Example Configurations

#### Development (Permissive)
```yaml
api:
  enabled: true
  allowed_ips:
    - "0.0.0.0/0"                 # Allow all IPs (development only!)
  basic_auth:
    enabled: false                # No authentication
  rate_limiting:
    enabled: false                # No rate limiting
```

#### Production (Secure)
```yaml
api:
  enabled: true
  allowed_ips:
    - "10.0.0.0/8"                # Internal network only
    - "172.16.0.0/12"             # Docker networks
  basic_auth:
    enabled: true
    users:
      admin: "very_secure_password_123"
      monitor: "monitoring_password_456"
  rate_limiting:
    enabled: true
    requests_per_minute: 30       # Conservative limit
```

#### Monitoring/Automation
```yaml
api:
  enabled: true
  allowed_ips:
    - "10.0.1.100/32"             # Monitoring server
    - "10.0.1.101/32"             # Automation server
  basic_auth:
    enabled: true
    username: "automation"
    password: "automation_token_xyz"
  rate_limiting:
    enabled: true
    requests_per_minute: 120      # Higher limit for automation
```

## Manual Ban Management API

The service provides REST API endpoints for manual IP ban/unban operations and permanent blacklist/whitelist management.

### API Endpoints

#### Manual Ban Operations

**POST `/api/ban`** - Manually ban an IP address
```bash
curl -X POST http://localhost:8888/api/ban \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "permanent": true,
    "reason": "Malicious activity detected",
    "created_by": "admin"
  }'
```

**POST `/api/unban`** - Manually unban an IP address
```bash
curl -X POST http://localhost:8888/api/unban \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "reason": "False positive"
  }'
```

#### Permanent Whitelist Management

**POST `/api/whitelist`** - Add IP to permanent whitelist
```bash
curl -X POST http://localhost:8888/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.0.1",
    "reason": "Trusted admin IP",
    "created_by": "admin"
  }'
```

**DELETE `/api/whitelist`** - Remove IP from whitelist
```bash
curl -X DELETE http://localhost:8888/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.0.1"
  }'
```

**GET `/api/whitelist`** - List all whitelisted IPs
```bash
curl http://localhost:8888/api/whitelist
```

#### Blacklist Information

**GET `/api/blacklist`** - List all blacklisted IPs
```bash
curl http://localhost:8888/api/blacklist
```

### API Response Format

All API endpoints return JSON responses with the following format:

```json
{
  "success": true,
  "message": "IP 192.168.1.100 permanently banned (blacklisted)",
  "ip_address": "192.168.1.100"
}
```

List endpoints return:
```json
{
  "success": true,
  "count": 2,
  "blacklist": [
    {
      "ip_address": "192.168.1.100",
      "reason": "Malicious activity",
      "created_at": "2024-01-15T10:30:00Z",
      "created_by": "admin"
    }
  ]
}
```

### Database Tables

The API operations use the following database tables:

#### Blacklist Table
```sql
-- Permanently banned IPs
INSERT INTO blacklist (ip_address, reason, created_by)
VALUES ('192.168.1.100', 'Brute force attack', 'admin');

-- Remove from blacklist
UPDATE blacklist SET enabled = FALSE
WHERE ip_address = '192.168.1.100';
```

#### Whitelist Table
```sql
-- Permanently allowed IPs
INSERT INTO whitelist (ip_address, reason, created_by)
VALUES ('10.0.0.1', 'Admin workstation', 'system');

-- Remove from whitelist
UPDATE whitelist SET enabled = FALSE
WHERE ip_address = '10.0.0.1';
```

### Security Considerations

- **IP Validation**: All IP addresses are validated before processing
- **Access Control**: Consider implementing authentication for API endpoints in production
- **Rate Limiting**: Implement rate limiting to prevent API abuse
- **Audit Logging**: All API operations are logged with timestamps and user information
- **Database Integrity**: Use unique constraints to prevent duplicate entries

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