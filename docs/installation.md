# Installation

## Docker Compose (Recommended)

The easiest way to run Fail2Ban Multi-Proxy is using Docker Compose:

```bash
# Clone the repository
git clone <repository-url>
cd mailfail2ban

# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f fail2ban-haproxy

# Stop services
docker-compose down
```

## Docker

### Pull from Registry

```bash
# Pull the latest image
docker pull ghcr.io/your-org/mailfail2ban:latest

# Run with default configuration
docker run -d \
  --name fail2ban-multiproxy \
  -p 12345:12345 \
  -p 9001:9001 \
  -p 8888:8888 \
  -v ./config.yaml:/app/config.yaml \
  ghcr.io/your-org/mailfail2ban:latest
```

### Build from Source

```bash
# Build the image
docker build -t mailfail2ban .

# Run the container
docker run -d \
  --name fail2ban-multiproxy \
  -p 12345:12345 \
  -p 9001:9001 \
  -p 8888:8888 \
  -v ./config.yaml:/app/config.yaml \
  mailfail2ban
```

## Binary Installation

### Download Pre-built Binaries

Download the latest release from the [releases page](https://github.com/your-org/mailfail2ban/releases):

```bash
# Download for Linux amd64
wget https://github.com/your-org/mailfail2ban/releases/latest/download/mailfail2ban-linux-amd64

# Make executable
chmod +x mailfail2ban-linux-amd64

# Run
./mailfail2ban-linux-amd64
```

### Build from Source

Requirements:
- Go 1.21 or later

```bash
# Clone the repository
git clone <repository-url>
cd mailfail2ban

# Build the binary
go build -o mailfail2ban .

# Run
./mailfail2ban
```

## System Service Installation

### systemd (Linux)

Create a systemd service file:

```bash
sudo tee /etc/systemd/system/mailfail2ban.service > /dev/null <<EOF
[Unit]
Description=Fail2Ban Multi-Proxy Service
After=network.target

[Service]
Type=simple
User=fail2ban
Group=fail2ban
WorkingDirectory=/opt/mailfail2ban
ExecStart=/opt/mailfail2ban/mailfail2ban
Restart=always
RestartSec=5

# Environment variables (optional)
Environment=FAIL2BAN_SPOA_PORT=12345
Environment=FAIL2BAN_ENVOY_PORT=9001
Environment=FAIL2BAN_NGINX_PORT=8888

[Install]
WantedBy=multi-user.target
EOF

# Create user and directories
sudo useradd -r -s /bin/false fail2ban
sudo mkdir -p /opt/mailfail2ban
sudo cp mailfail2ban /opt/mailfail2ban/
sudo cp config.yaml /opt/mailfail2ban/
sudo chown -R fail2ban:fail2ban /opt/mailfail2ban

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable mailfail2ban
sudo systemctl start mailfail2ban

# Check status
sudo systemctl status mailfail2ban
```

## Environment Variables

All configuration options can be overridden using environment variables with the `FAIL2BAN_` prefix:

```bash
# Syslog configuration
export FAIL2BAN_SYSLOG_ADDRESS="0.0.0.0:514"
export FAIL2BAN_SYSLOG_PROTOCOL="udp"

# SPOA configuration
export FAIL2BAN_SPOA_ADDRESS="0.0.0.0"
export FAIL2BAN_SPOA_PORT="12345"
export FAIL2BAN_SPOA_ENABLED="true"

# Envoy configuration
export FAIL2BAN_ENVOY_ADDRESS="0.0.0.0"
export FAIL2BAN_ENVOY_PORT="9001"
export FAIL2BAN_ENVOY_ENABLED="true"

# Nginx configuration
export FAIL2BAN_NGINX_ADDRESS="0.0.0.0"
export FAIL2BAN_NGINX_PORT="8888"
export FAIL2BAN_NGINX_ENABLED="true"

# Ban configuration
export FAIL2BAN_BAN_INITIAL_BAN_TIME="5m"
export FAIL2BAN_BAN_MAX_BAN_TIME="24h"
export FAIL2BAN_BAN_MAX_ATTEMPTS="5"
```

## Verification

After installation, verify the service is running:

```bash
# Check if ports are listening
netstat -tlnp | grep -E ':(12345|9001|8888)'

# Test SPOA (HAProxy)
# This requires HAProxy configured with SPOA

# Test Envoy ext_authz
# This requires Envoy configured with ext_authz

# Test Nginx auth_request
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth
# Should return 200 (allowed)

# Test health endpoint
curl http://localhost:8888/health
# Should return: {"status":"healthy","service":"fail2ban-nginx-auth"}
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure the binary has execute permissions
2. **Port already in use**: Check if other services are using the same ports
3. **Config file not found**: Ensure `config.yaml` is in the working directory or `/etc/fail2ban-haproxy/`

### Logs

Check logs for debugging:

```bash
# Docker
docker logs mailfail2ban

# systemd
sudo journalctl -u mailfail2ban -f

# Binary (with log file)
./mailfail2ban 2>&1 | tee mailfail2ban.log
```