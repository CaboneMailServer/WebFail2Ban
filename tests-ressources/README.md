# Tests Resources

This directory contains all the configuration files and resources needed for the Docker Compose test environment.

## Files Structure

### Configuration Files
- `config.yaml` - Main fail2ban service configuration with all three protocols enabled
- `haproxy.cfg` - HAProxy configuration with SPOA integration
- `spoe-ip-reputation.conf` - HAProxy SPOE configuration for fail2ban communication
- `envoy-example.yaml` - Envoy proxy configuration with ext_authz integration
- `nginx-example.conf` - Nginx configuration with auth_request integration
- `dovecot.conf` - Dovecot IMAP/POP3 server configuration

### Application-specific Configurations
- `postfix/main.cf` - Postfix main configuration
- `postfix/master.cf` - Postfix master configuration
- `sogo/sogo.conf` - SOGo webmail configuration
- `sogo/sogo-schema.sql` - PostgreSQL schema for SOGo

### Runtime Directories
- `logs/` - Log files from fail2ban service
- `ssl/` - SSL certificates for mail services

## Docker Compose Services

The docker-compose.yml file includes the following services:

### Core Services
- `fail2ban-service` - Main fail2ban service with all three protocols (SPOA, Envoy, Nginx)
- `postgres` - PostgreSQL database for SOGo
- `redis` - Redis cache

### Mail Services
- `dovecot` - IMAP/POP3 server
- `postfix` - SMTP server
- `sogo` - Webmail and groupware

### Proxy Services (for testing)
- `haproxy` - HAProxy with SPOA integration (port 143, 993, 587, 465, 80, 443)
- `envoy` - Envoy proxy with ext_authz integration (port 8080)
- `nginx` - Nginx proxy with auth_request integration (port 8081)

## Ports Mapping

### fail2ban-service
- `12345` - SPOA protocol (HAProxy)
- `9001` - gRPC ext_authz (Envoy)
- `8888` - HTTP auth_request (Nginx)
- `514/udp` - Syslog receiver

### Proxy Services
- `8080` - Envoy proxy HTTP listener
- `8081` - Nginx proxy HTTP listener
- `80, 443, 143, 993, 587, 465` - HAProxy ports

### Backend Services
- `10143, 10993` - Dovecot internal ports
- `10587, 10465` - Postfix internal ports
- `10080, 10443` - SOGo internal ports

## Testing the Integration

1. **Start the environment:**
   ```bash
   docker-compose up -d
   ```

2. **Test HAProxy + SPOA:**
   ```bash
   # Connect through HAProxy
   curl -H "Host: webmail.example.com" http://localhost:80/
   ```

3. **Test Envoy + ext_authz:**
   ```bash
   # Connect through Envoy
   curl http://localhost:8080/
   ```

4. **Test Nginx + auth_request:**
   ```bash
   # Connect through Nginx
   curl http://localhost:8081/
   ```

5. **Generate failed authentication (to test banning):**
   ```bash
   # Try invalid IMAP login through HAProxy
   telnet localhost 143
   # Enter invalid credentials
   ```

6. **Check logs:**
   ```bash
   # fail2ban logs
   docker-compose logs fail2ban-service

   # Proxy logs
   docker-compose logs haproxy
   docker-compose logs envoy
   docker-compose logs nginx
   ```

7. **Check ban status:**
   ```bash
   # View active bans
   docker-compose exec fail2ban-service tail -f /var/log/fail2ban-haproxy/app.log
   ```

## Configuration Notes

- All mail services are configured to send logs to the fail2ban-service via syslog
- The fail2ban service has all three protocols enabled by default
- Each proxy integration protects different backend services for testing
- SSL certificates should be added to `ssl/` directory for production use