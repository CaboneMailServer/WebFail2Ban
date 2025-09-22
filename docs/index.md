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

## Ban Escalation Mechanics

```mermaid
sequenceDiagram
    participant C as Client
    participant P as Reverse Proxy
    participant F as Fail2Ban Service
    participant S as Syslog Source
    participant DB as Database/Config

    Note over F: System starts, loads patterns & config
    F->>DB: Load patterns & ban config
    DB-->>F: Patterns: dovecot, postfix, sogo

    Note over C,S: Normal operation flow
    C->>P: Request (IP: 192.168.1.100)
    P->>F: Check IP ban status
    F-->>P: IP allowed (not banned)
    P->>C: Forward request/response

    Note over S,F: Authentication failure detected
    S->>F: Syslog: auth failed, rip=192.168.1.100
    F->>F: Pattern match: dovecot-auth-failure
    F->>F: Record attempt #1 (severity: 1)

    Note over C,F: Subsequent failures trigger escalation
    loop 4 more failures within time window (10m)
        S->>F: Syslog: auth failed, rip=192.168.1.100
        F->>F: Record attempt #2-5
    end

    Note over F: Ban threshold reached (5 attempts)
    F->>F: Create ban: 192.168.1.100<br/>Duration: 5m (initial_ban_time)
    F->>F: Store in radix tree with TTL

    Note over C,P: Subsequent requests blocked
    C->>P: Request (IP: 192.168.1.100)
    P->>F: Check IP ban status
    F-->>P: IP banned (deny)
    P-->>C: HTTP 403 / TCP connection refused

    Note over F: Ban expires, IP tries again
    F->>F: TTL expires, remove from radix tree

    Note over S,F: Second ban cycle (escalation)
    loop 5 failures within time window
        S->>F: Syslog: auth failed, rip=192.168.1.100
        F->>F: Record attempt (history exists)
    end

    F->>F: Create escalated ban: 192.168.1.100<br/>Duration: 10m (5m × 2.0 escalation_factor)

    Note over F: Continue escalation until max_ban_time
    F->>F: Next ban: 20m → 40m → 80m → 160m → 320m<br/>Cap at max_ban_time: 24h

    Note over F: Cleanup and maintenance
    F->>F: Cleanup expired bans (every 1m)
    F->>F: Clean old attempts (max_memory_ttl: 72h)

    opt Database enabled
        F->>DB: Reload config (every 5m)
        alt Database available
            DB-->>F: Updated patterns & config
            F->>F: Cache new config in memory
        else Database failure
            Note over F,DB: Keep using cached config
            F->>F: Use last known good config
            F->>F: Increment failure counter
            F->>F: Log: "Using cached config from [timestamp]"
        end
    end

    Note over F: Robust failure handling
    F->>F: Config priority:<br/>1. Live database<br/>2. Cached database<br/>3. File fallback
```

## Key Features

- **Real-time syslog analysis** with regex pattern matching
- **Multiple proxy support**: HAProxy (SPOA), Envoy (gRPC ext_authz), Nginx (auth_request)
- **Ban escalation**: Configurable timeouts from 5 minutes to 24 hours
- **Radix tree storage**: Optimized IP address management
- **Database integration**: SQL-based configuration with hot reloading
- **Robust failure handling**: Configuration caching and automatic fallback
- **Prometheus metrics**: Comprehensive monitoring and observability
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

# Database configuration (optional)
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

## Project Structure

```
├── docs/                   # Documentation
├── internal/               # Go source code
│   ├── config/            # Configuration management & hot reloading
│   ├── database/          # SQL database integration
│   ├── metrics/           # Prometheus metrics collection
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