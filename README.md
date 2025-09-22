# Reverse Proxy Fail2Ban dynamic filtering

Real-time IP banning system for HAProxy, Envoy, and Nginx with **🔥 hot configuration reloading**. 

Originally designed to protect Dovecot, Postfix, and SOGo by analyzing syslog logs, but can protect any service behind supported reverse proxies.

## 🔥 **Hot Configuration Reloading**

**Modify patterns and ban escalation settings without service restart!**

- **✅ Live pattern updates** - Add/modify detection patterns in real-time
- **✅ Live ban configuration** - Adjust escalation timeouts without downtime
- **✅ Database-driven** - Store configuration in SQL database for persistence
- **✅ Automatic fallback** - Keeps working even if database becomes unavailable
- **✅ Zero-downtime updates** - No service interruption during config changes

## Features

- **🔥 Hot configuration reloading** - Modify patterns and ban settings without restart
- **🚀 REST API for ban management** - Manual IP ban/unban with temporary & permanent lists
- **Real-time syslog analysis** with pattern matching
- **Multiple proxy integration**: HAProxy (SPOA), Envoy (gRPC ext_authz), Nginx (auth_request)
- **Ban escalation** with configurable timeouts (5m → 24h)
- **Database integration** with SQL-based configuration storage
- **Permanent blacklist/whitelist** - Database-stored IP lists for long-term management
- **Robust failure handling** with automatic fallback to cached configuration
- **Prometheus metrics** for comprehensive monitoring
- **Radix tree** optimized IP storage with purge functionality
- **Docker-ready** with comprehensive test environment

## Quick Start

```bash
# Clone and start
git clone <repository-url>
cd mailfail2ban
docker-compose up -d

# Check logs
docker-compose logs -f fail2ban-haproxy
```

### 🔥 **Hot Configuration Example**

```bash
# Enable database configuration for hot reloading
export FAIL2BAN_DATABASE_ENABLED=true
export FAIL2BAN_DATABASE_DRIVER=sqlite3
export FAIL2BAN_DATABASE_DSN=./fail2ban.db

# Start service with database support
./fail2ban-haproxy

# Add new pattern without restart (via SQL)
sqlite3 fail2ban.db "INSERT INTO patterns (name, regex, ip_group, severity, description)
VALUES ('nginx_404', 'nginx.*404.*client: ([0-9.]+)', 1, 2, 'Nginx 404 abuse');"

# Modify ban escalation without restart
sqlite3 fail2ban.db "UPDATE ban_config SET max_attempts=3, initial_ban_time_seconds=600
WHERE name='default';"

# Configuration reloads automatically every 5 minutes (configurable)
```

### 🚀 **API Management Example**

```bash
# Manual IP ban via REST API
curl -X POST http://localhost:8888/api/ban \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100", "duration": "1h"}'

# List current temporary bans
curl http://localhost:8888/api/temp-bans

# Add to permanent whitelist
curl -X POST http://localhost:8888/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "10.0.0.1", "reason": "Admin IP"}'
```

## Supported Reverse Proxies

- **HAProxy**: SPOA (Stream Processing Offload Agent) protocol
- **Envoy**: gRPC ext_authz (External Authorization) service
- **Nginx**: auth_request HTTP module

## Protected Services

Originally designed for:
- **Dovecot** (IMAP/POP3): Authentication failures, brute force
- **Postfix** (SMTP): SASL failures, relay attempts
- **SOGo** (Webmail): Login failures, CalDAV/CardDAV abuse

Can protect **any service** that can be reverse proxied behind the supported proxies.

## Configuration

Basic configuration in `config.yaml`:

```yaml
# Ban escalation settings
ban:
  initial_ban_time: "5m"
  max_ban_time: "24h"
  max_attempts: 5
  time_window: "10m"

# Enable proxy integrations
spoa:
  port: 12345
  enabled: true     # HAProxy

envoy:
  port: 9001
  enabled: true     # Envoy

nginx:
  port: 8888
  enabled: true     # Nginx

# 🔥 Hot configuration reloading (optional)
database:
  enabled: true
  driver: "sqlite3"
  dsn: "./fail2ban.db"
  refresh_interval: "5m"

# Prometheus metrics (optional)
prometheus:
  enabled: true
  port: 2112
  path: "/metrics"
```

## Documentation

For detailed documentation, see [GitHub Pages](https://cabonemailserver.github.io/WebFail2Ban/docs/):

- **[Installation](https://cabonemailserver.github.io/WebFail2Ban/docs/installation.html)** - Installation methods and setup
- **[Configuration](https://cabonemailserver.github.io/WebFail2Ban/docs/configuration.html)** - Complete configuration reference
- **[Ban Management API](https://cabonemailserver.github.io/WebFail2Ban/docs/api.html)** - REST API for manual IP ban/unban operations
- **[API Reference (OpenAPI)](https://raw.githubusercontent.com/CaboneMailServer/WebFail2Ban/refs/heads/master/docs/api.jsonhttps://raw.githubusercontent.com/CaboneMailServer/WebFail2Ban/refs/heads/master/docs/api.json)** - Interactive API documentation with Swagger UI
- **[Proxy Integration](https://cabonemailserver.github.io/WebFail2Ban/docs/proxy-integration.html)** - HAProxy, Envoy, and Nginx integration guides
- **[Testing](https://cabonemailserver.github.io/WebFail2Ban/docs/testing.html)** - Unit tests, integration tests, and performance testing

## Testing

```bash
# Run unit tests
go test ./...

# Run with coverage
go test -cover ./...

# Integration tests
docker-compose up -d
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth
```

## License

This project is licensed under the MIT License - see the [LICENCE.md](https://cabonemailserver.github.io/WebFail2Ban/LICENCE.html) file for details.

