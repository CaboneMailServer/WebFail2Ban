# Fail2Ban Multi-Proxy - Documentation

Real-time IP banning system for HAProxy, Envoy, and Nginx. Originally designed to protect Dovecot, Postfix, and SOGo by analyzing syslog logs, but can protect any service behind supported reverse proxies.

## Documentation Index

- **[Installation](installation.md)** - Installation methods and setup
- **[Configuration](configuration.md)** - Complete configuration reference
- **[Proxy Integration](proxy-integration.md)** - Overview of proxy integration methods
  - **[HAProxy Integration](haproxy.md)** - Detailed HAProxy SPOA configuration
  - **[Envoy Integration](envoy.md)** - Detailed Envoy ext_authz configuration
  - **[Nginx Integration](nginx.md)** - Detailed Nginx auth_request configuration
- **[Testing](testing.md)** - Unit tests, integration tests, and performance testing
- **[Troubleshooting](troubleshooting.md)** - Common issues and debugging guide

## Architecture

```mermaid
flowchart TB
    Client[Client Request] --> ReverseProxy[Reverse Proxy<br/>HAProxy/Envoy/Nginx]

    ReverseProxy -->|SPOA/gRPC/HTTP<br/>Check IP| Fail2Ban[Fail2Ban Service<br/>IP Ban Manager]
    Fail2Ban -->|Allow/Deny| ReverseProxy

    ReverseProxy -->|Forward if allowed| Backend[Backend Services<br/>Dovecot/Postfix/SOGo]

    Backend -->|Syslog Events| Fail2Ban

    Fail2Ban --> Storage[Storage & Management<br/>Radix Tree • TTL Manager]
    Fail2Ban --> Rules[Detection Rules<br/>Auth Failures • Brute Force<br/>Ban Escalation: 5m→24h]

    classDef service fill:#e1f5fe
    classDef security fill:#ffebee
    classDef storage fill:#f3e5f5
    classDef proxy fill:#fff3e0

    class Backend service
    class ReverseProxy proxy
    class Fail2Ban,Rules security
    class Storage storage
```

## Key Features

- **Real-time syslog analysis** with regex pattern matching
- **Multiple proxy support**: HAProxy (SPOA), Envoy (gRPC ext_authz), Nginx (auth_request)
- **Ban escalation**: Configurable timeouts from 5 minutes to 24 hours
- **Radix tree storage**: Optimized IP address management
- **Environment variables**: Full configuration override support

## Quick Start

```bash
# Basic deployment
docker-compose up -d

# Check service health
curl http://localhost:8888/health

# Test auth endpoint
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth
```

## Supported Services

Originally designed for:
- **Dovecot** (IMAP/POP3): Authentication failures, brute force
- **Postfix** (SMTP): SASL failures, relay attempts
- **SOGo** (Webmail): Login failures, CalDAV/CardDAV abuse

Can protect **any service** that can be reverse proxied behind HAProxy, Envoy, or Nginx.

## Configuration Overview

```yaml
# Enable all proxy integrations
spoa:
  port: 12345
  enabled: true     # HAProxy

envoy:
  port: 9001
  enabled: true     # Envoy

nginx:
  port: 8888
  enabled: true     # Nginx

# Ban configuration
ban:
  initial_ban_time: "5m"
  max_ban_time: "24h"
  max_attempts: 5
  time_window: "10m"
```

## Project Structure

```
├── docs/                   # Documentation
├── internal/               # Go source code
│   ├── config/            # Configuration management
│   ├── envoy/             # Envoy ext_authz server
│   ├── ipban/             # IP banning logic
│   ├── nginx/             # Nginx auth_request server
│   └── syslog/            # Syslog reader
├── tests-ressources/      # Docker Compose test environment
├── .github/workflows/     # CI/CD pipelines
├── docker-compose.yml     # Complete test orchestration
├── Dockerfile             # Service container build
└── main.go               # Application entry point
```