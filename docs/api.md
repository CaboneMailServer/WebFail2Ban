# Ban Management API

The Fail2Ban Multi-Proxy service provides a comprehensive REST API for manual IP ban/unban operations, permanent blacklist/whitelist management, and radix tree operations.

## API Overview

The API is accessible via HTTP endpoints on the same port as the Nginx auth_request service (default: 8888). All endpoints return JSON responses with consistent error handling.

### Base URL
```
http://localhost:8888/api/
```

## Authentication & Security

The API includes comprehensive security features:

### IP Address Filtering
Access is restricted to configured IP addresses and CIDR ranges:

```yaml
# Configuration example
api:
  enabled: true
  allowed_ips:
    - "127.0.0.1/32"        # localhost IPv4
    - "::1/128"             # localhost IPv6
    - "10.0.0.0/8"          # private network
    - "192.168.1.100"       # specific admin IP
```

### Basic Authentication
HTTP Basic Authentication with support for single or multiple users:

```yaml
# Single user configuration
api:
  basic_auth:
    enabled: true
    username: "admin"
    password: "secure_password"

# Multiple users configuration
api:
  basic_auth:
    enabled: true
    users:
      admin: "admin_password"
      operator: "operator_password"
```

### Rate Limiting
Per-IP rate limiting prevents API abuse:

```yaml
api:
  rate_limiting:
    enabled: true
    requests_per_minute: 60
```

### Security Status Endpoint

**GET `/api/security-status`** - Get security configuration status

```bash
curl http://localhost:8888/api/security-status
```

**Response:**
```json
{
  "success": true,
  "security": {
    "enabled": true,
    "allowed_ips_count": 4,
    "basic_auth_enabled": true,
    "rate_limiting_enabled": true,
    "active_clients": 2,
    "rate_limit": 60
  }
}
```

## Manual Ban Operations

### POST `/api/ban` - Ban IP Address

Manually ban an IP address either temporarily (in-memory radix tree) or permanently (database blacklist).

**Request Body:**
```json
{
  "ip_address": "192.168.1.100",
  "permanent": false,
  "duration": "1h",
  "reason": "Malicious activity detected",
  "created_by": "admin"
}
```

**Parameters:**
- `ip_address` (string, required): Valid IPv4 or IPv6 address
- `permanent` (boolean, optional): If true, adds to permanent blacklist
- `duration` (string, optional): Ban duration (e.g., "5m", "1h", "24h"). Only for temporary bans
- `reason` (string, optional): Reason for the ban
- `created_by` (string, optional): Who created the ban (defaults to "api")

**Examples:**

```bash
# Temporary ban for 30 minutes (with authentication)
curl -X POST http://localhost:8888/api/ban \
  -u admin:secure_password \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "duration": "30m",
    "reason": "Brute force attempt"
  }'

# Permanent ban (blacklist)
curl -X POST http://localhost:8888/api/ban \
  -u admin:secure_password \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.0.50",
    "permanent": true,
    "reason": "Known malicious IP",
    "created_by": "security-team"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "IP 192.168.1.100 temporarily banned for 30m0s",
  "ip_address": "192.168.1.100"
}
```

### POST `/api/unban` - Unban IP Address

Remove an IP address from both temporary bans (radix tree) and permanent blacklist.

**Request Body:**
```json
{
  "ip_address": "192.168.1.100",
  "reason": "False positive"
}
```

**Example:**
```bash
curl -X POST http://localhost:8888/api/unban \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "reason": "Investigation completed - legitimate user"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "IP 192.168.1.100 removed from temporary bans",
  "ip_address": "192.168.1.100"
}
```

## Temporary Ban Management

### GET `/api/temp-bans` - List Temporary Bans

Retrieve all currently active temporary bans from the radix tree.

**Example:**
```bash
curl http://localhost:8888/api/temp-bans
```

**Response:**
```json
{
  "success": true,
  "count": 2,
  "temp_bans": [
    {
      "ip_address": "192.168.1.100",
      "expires_at": "2024-01-15T11:30:00Z",
      "duration_remaining": "25m30s"
    },
    {
      "ip_address": "10.0.0.50",
      "expires_at": "2024-01-15T12:00:00Z",
      "duration_remaining": "55m15s"
    }
  ]
}
```

### POST `/api/purge-bans` - Purge All Temporary Bans

Remove all temporary bans from the radix tree immediately.

**Example:**
```bash
curl -X POST http://localhost:8888/api/purge-bans
```

**Response:**
```json
{
  "success": true,
  "message": "Purged 5 temporary bans",
  "purged_count": 5
}
```

### GET `/api/radix-stats` - Radix Tree Statistics

Get detailed statistics about the radix tree performance and usage.

**Example:**
```bash
curl http://localhost:8888/api/radix-stats
```

**Response:**
```json
{
  "success": true,
  "stats": {
    "total_ips_tracked": 150,
    "currently_banned": 8,
    "tree_nodes": 1247
  }
}
```

## Permanent Whitelist Management

### POST `/api/whitelist` - Add to Whitelist

Add an IP address to the permanent whitelist (never banned).

**Request Body:**
```json
{
  "ip_address": "10.0.0.1",
  "reason": "Admin workstation",
  "created_by": "admin"
}
```

**Example:**
```bash
curl -X POST http://localhost:8888/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "172.16.0.10",
    "reason": "CI/CD server",
    "created_by": "devops"
  }'
```

### DELETE `/api/whitelist` - Remove from Whitelist

Remove an IP address from the permanent whitelist.

**Request Body:**
```json
{
  "ip_address": "10.0.0.1"
}
```

**Example:**
```bash
curl -X DELETE http://localhost:8888/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "172.16.0.10"
  }'
```

### GET `/api/whitelist` - List Whitelist

Retrieve all permanently whitelisted IP addresses.

**Example:**
```bash
curl http://localhost:8888/api/whitelist
```

**Response:**
```json
{
  "success": true,
  "count": 3,
  "whitelist": [
    {
      "ip_address": "10.0.0.1",
      "reason": "Admin workstation",
      "created_at": "2024-01-15T09:00:00Z",
      "created_by": "admin"
    },
    {
      "ip_address": "172.16.0.10",
      "reason": "CI/CD server",
      "created_at": "2024-01-15T10:00:00Z",
      "created_by": "devops"
    }
  ]
}
```

## Permanent Blacklist Information

### GET `/api/blacklist` - List Blacklist

Retrieve all permanently blacklisted IP addresses.

**Example:**
```bash
curl http://localhost:8888/api/blacklist
```

**Response:**
```json
{
  "success": true,
  "count": 5,
  "blacklist": [
    {
      "ip_address": "203.0.113.100",
      "reason": "Repeated brute force attacks",
      "created_at": "2024-01-15T08:30:00Z",
      "created_by": "security-system"
    },
    {
      "ip_address": "198.51.100.50",
      "reason": "Known botnet IP",
      "created_at": "2024-01-15T09:15:00Z",
      "created_by": "threat-intel"
    }
  ]
}
```

## Error Handling

All API endpoints return consistent error responses:

### HTTP Status Codes
- `200 OK`: Successful operation
- `400 Bad Request`: Invalid request data (e.g., invalid IP address)
- `405 Method Not Allowed`: Incorrect HTTP method
- `500 Internal Server Error`: Server-side error

### Error Response Format
```json
{
  "success": false,
  "message": "Invalid IP address: not.an.ip",
  "ip_address": "not.an.ip"
}
```

## Database Integration

The API operations interact with the following database tables:

### Blacklist Table
```sql
-- View all blacklisted IPs
SELECT ip_address, reason, created_at, created_by
FROM blacklist
WHERE enabled = TRUE;

-- Manually add to blacklist
INSERT INTO blacklist (ip_address, reason, created_by)
VALUES ('192.168.1.100', 'Manual block', 'admin');

-- Remove from blacklist
UPDATE blacklist SET enabled = FALSE
WHERE ip_address = '192.168.1.100';
```

### Whitelist Table
```sql
-- View all whitelisted IPs
SELECT ip_address, reason, created_at, created_by
FROM whitelist
WHERE enabled = TRUE;

-- Manually add to whitelist
INSERT INTO whitelist (ip_address, reason, created_by)
VALUES ('10.0.0.1', 'Trusted IP', 'admin');

-- Remove from whitelist
UPDATE whitelist SET enabled = FALSE
WHERE ip_address = '10.0.0.1';
```

## Integration Examples

### Automation Scripts

**Bash Script - Emergency IP Block:**
```bash
#!/bin/bash
# emergency-block.sh
IP="$1"
REASON="$2"

if [ -z "$IP" ] || [ -z "$REASON" ]; then
    echo "Usage: $0 <ip_address> <reason>"
    exit 1
fi

curl -X POST http://localhost:8888/api/ban \
  -H "Content-Type: application/json" \
  -d "{
    \"ip_address\": \"$IP\",
    \"permanent\": true,
    \"reason\": \"$REASON\",
    \"created_by\": \"emergency-script\"
  }"
```

**Python Script - Ban Status Check:**
```python
#!/usr/bin/env python3
import requests
import json

def check_ban_status(ip):
    # Check temporary bans
    temp_response = requests.get('http://localhost:8888/api/temp-bans')
    temp_data = temp_response.json()

    for ban in temp_data.get('temp_bans', []):
        if ban['ip_address'] == ip:
            return f"IP {ip} is temporarily banned until {ban['expires_at']}"

    # Check blacklist
    black_response = requests.get('http://localhost:8888/api/blacklist')
    black_data = black_response.json()

    for entry in black_data.get('blacklist', []):
        if entry['ip_address'] == ip:
            return f"IP {ip} is permanently blacklisted: {entry['reason']}"

    return f"IP {ip} is not banned"

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 check_ban.py <ip_address>")
        sys.exit(1)

    print(check_ban_status(sys.argv[1]))
```

### Monitoring Integration

**Prometheus Metrics Collection:**
```bash
# Collect radix tree stats for Prometheus
curl -s http://localhost:8888/api/radix-stats | \
  jq -r '.stats | to_entries[] | "fail2ban_\(.key) \(.value)"'
```

**Grafana Dashboard Query:**
```bash
# Get current ban counts for dashboard
curl -s http://localhost:8888/api/temp-bans | jq '.count'
curl -s http://localhost:8888/api/blacklist | jq '.count'
curl -s http://localhost:8888/api/whitelist | jq '.count'
```

## Rate Limiting Recommendations

For production environments, implement rate limiting on API endpoints:

```nginx
# Nginx rate limiting example
location /api/ {
    limit_req zone=api burst=10 nodelay;
    proxy_pass http://fail2ban-service:8888;
}

# Define rate limit zone
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
}
```

## Security Best Practices

1. **Access Control**: Restrict API access to authorized networks only
2. **Authentication**: Implement API key or token-based authentication
3. **HTTPS**: Use HTTPS in production environments
4. **Input Validation**: Always validate IP addresses and input data
5. **Audit Logging**: Log all API operations for security auditing
6. **Rate Limiting**: Prevent API abuse with appropriate rate limits
7. **Network Isolation**: Run API on internal networks when possible

## Troubleshooting

### Common Issues

**API Not Responding:**
```bash
# Check if service is running
curl http://localhost:8888/health

# Check logs
docker logs fail2ban-service
```

**Database Connection Issues:**
```bash
# Check database status
curl http://localhost:8888/database/status

# Check configuration source
curl http://localhost:8888/config/source
```

**Invalid Responses:**
```bash
# Validate JSON syntax
echo '{"ip_address": "192.168.1.100"}' | jq .

# Check IP address format
python3 -c "import ipaddress; print(ipaddress.ip_address('192.168.1.100'))"
```

### Debug Commands

```bash
# Test all endpoints
curl http://localhost:8888/api/temp-bans
curl http://localhost:8888/api/blacklist
curl http://localhost:8888/api/whitelist
curl http://localhost:8888/api/radix-stats

# Test ban/unban cycle
curl -X POST http://localhost:8888/api/ban \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100", "duration": "5m"}'

curl -X POST http://localhost:8888/api/unban \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100"}'
```