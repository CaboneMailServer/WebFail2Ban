# Fail2Ban Multi-Proxy

Real-time IP banning system for HAProxy, Envoy, and Nginx. Originally designed to protect Dovecot, Postfix, and SOGo by analyzing syslog logs, but can protect any service behind supported reverse proxies.

## Features

- **Real-time syslog analysis** with pattern matching
- **Multiple proxy integration**: HAProxy (SPOA), Envoy (gRPC ext_authz), Nginx (auth_request)
- **Ban escalation** with configurable timeouts (5m → 24h)
- **Radix tree** optimized IP storage
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
```

## Documentation

For detailed documentation, see [GitHub Pages](https://cabonemailserver.github.io/WebFail2Ban/docs/):

- **[Installation](https://cabonemailserver.github.io/WebFail2Ban/docs/installation.html)** - Installation methods and setup
- **[Configuration](https://cabonemailserver.github.io/WebFail2Ban/docs/configuration.html)** - Complete configuration reference
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

