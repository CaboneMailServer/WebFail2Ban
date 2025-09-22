# Testing

## Unit Tests

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run tests for specific package
go test ./internal/config
go test ./internal/ipban
go test ./internal/syslog
go test ./internal/spoa
go test ./internal/envoy
go test ./internal/nginx

# Run tests with race detection
go test -race ./...

# Run tests multiple times
go test -count=10 ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Test Coverage

The test suite covers:

#### Configuration Package (`internal/config`)
- Configuration loading and validation
- Default value handling
- YAML parsing and unmarshaling
- Error handling for invalid configurations
- Environment variable override

#### IP Ban Manager (`internal/ipban`)
- IP violation recording and tracking
- Ban escalation logic with configurable factors
- Radix tree operations (insert, search, delete)
- Time window violation cleanup
- Concurrent access safety
- Memory TTL management
- IPv4 and IPv6 support

#### Syslog Reader (`internal/syslog`)
- Syslog message processing and pattern matching
- Regex pattern compilation and execution
- IP extraction from various log formats
- Integration with ban manager
- UDP socket handling and timeouts
- Real-time log processing

#### SPOA Server (`internal/spoa`)
- HAProxy SPOA protocol implementation
- TCP connection handling and client management
- Message parsing and response generation
- Ban status checking and responses
- Concurrent client handling
- Connection timeouts and error handling

#### Envoy Server (`internal/envoy`)
- gRPC ext_authz service implementation
- Authorization request processing
- IP extraction from request headers and metadata
- Allow/deny response generation
- gRPC status code handling
- Concurrent request processing

#### Nginx Server (`internal/nginx`)
- HTTP auth_request endpoint implementation
- IP extraction from various headers
- HTTP response handling with custom headers
- Health check endpoint
- JSON error response support
- Concurrent HTTP request handling

## Integration Tests

### Docker Compose Test Environment

The project includes a complete test environment in `tests-ressources/`:

```bash
# Start test environment
docker-compose up -d

# Wait for services to be ready
sleep 30

# Check service health
docker-compose ps
```

### Service Tests

#### Test Nginx Auth

```bash
# Test allowed IP
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth
# Expected: 200 OK

# Test health endpoint
curl http://localhost:8888/health
# Expected: {"status":"healthy","service":"fail2ban-nginx-auth"}

# Test with custom headers
curl -H "X-Real-IP: 10.0.0.1" \
     -H "X-Forwarded-For: 10.0.0.1" \
     http://localhost:8888/auth
```

#### Test Envoy ext_authz

```bash
# Test HTTP request through Envoy
curl http://localhost:8080/

# Check Envoy admin stats
curl http://localhost:9901/stats | grep ext_authz

# Check authorization cluster health
curl http://localhost:9901/clusters | grep fail2ban_authz
```

#### Test HAProxy SPOA

```bash
# Test IMAP connection through HAProxy
telnet localhost 143

# Alternative: use netcat
echo "QUIT" | nc localhost 143

# Check HAProxy stats
curl http://localhost:8404/stats
```

### Syslog Injection Tests

Test pattern detection by sending syslog messages:

```bash
# Test Dovecot auth failure
echo "<134>$(date '+%b %d %H:%M:%S') hostname dovecot: auth failed, method=PLAIN, rip=192.168.1.100" | nc -u localhost 514

# Test Postfix SASL failure
echo "<134>$(date '+%b %d %H:%M:%S') hostname postfix/smtpd: warning: SASL authentication failed: authentication failure [192.168.1.100]" | nc -u localhost 514

# Test SOGo login failure
echo "<134>$(date '+%b %d %H:%M:%S') hostname sogod: Login failed for user 'test' from 192.168.1.100" | nc -u localhost 514

# Wait for processing
sleep 5

# Check if IP is now banned
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth
# Expected: 403 Forbidden after max_attempts violations
```

### Automated Integration Tests

Create an integration test script:

```bash
#!/bin/bash
# tests/integration_test.sh

set -e

echo "Starting integration tests..."

# Start services
docker-compose up -d
sleep 30

# Test 1: Health checks
echo "Testing health endpoints..."
curl -f http://localhost:8888/health || exit 1

# Test 2: Initial auth (should allow)
echo "Testing initial auth (should allow)..."
response=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Real-IP: 10.0.0.1" http://localhost:8888/auth)
if [ "$response" != "200" ]; then
    echo "Expected 200, got $response"
    exit 1
fi

# Test 3: Generate violations
echo "Generating auth failures..."
for i in {1..6}; do
    echo "<134>$(date '+%b %d %H:%M:%S') hostname dovecot: auth failed, method=PLAIN, rip=10.0.0.1" | nc -u localhost 514
    sleep 1
done

# Wait for processing
sleep 5

# Test 4: Check if IP is banned
echo "Testing if IP is banned..."
response=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Real-IP: 10.0.0.1" http://localhost:8888/auth)
if [ "$response" != "403" ]; then
    echo "Expected 403 (banned), got $response"
    exit 1
fi

# Test 5: Test different IP (should allow)
echo "Testing different IP (should allow)..."
response=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Real-IP: 10.0.0.2" http://localhost:8888/auth)
if [ "$response" != "200" ]; then
    echo "Expected 200, got $response"
    exit 1
fi

echo "All integration tests passed!"

# Cleanup
docker-compose down
```

Run the integration tests:

```bash
chmod +x tests/integration_test.sh
./tests/integration_test.sh
```

## Performance Tests

### Benchmark Tests

```bash
# Benchmark IP ban manager
go test -bench=. ./internal/ipban

# Benchmark syslog processing
go test -bench=. ./internal/syslog

# Benchmark with memory profiling
go test -bench=. -memprofile=mem.prof ./internal/ipban
go tool pprof mem.prof

# Benchmark with CPU profiling
go test -bench=. -cpuprofile=cpu.prof ./internal/ipban
go tool pprof cpu.prof
```

### Load Testing

#### Nginx Auth Endpoint

```bash
# Install hey (HTTP load testing tool)
go install github.com/rakyll/hey@latest

# Load test auth endpoint
hey -n 10000 -c 100 -H "X-Real-IP: 192.168.1.200" http://localhost:8888/auth

# Load test with different IPs
for i in {1..100}; do
    hey -n 100 -c 10 -H "X-Real-IP: 192.168.1.$i" http://localhost:8888/auth &
done
wait
```

#### Syslog Message Processing

```bash
# Generate high-volume syslog traffic
for i in {1..10000}; do
    echo "<134>$(date '+%b %d %H:%M:%S') hostname dovecot: auth failed, method=PLAIN, rip=192.168.$((i%255)).$((i%255))" | nc -u localhost 514
done
```

### Memory and Resource Testing

```bash
# Monitor memory usage during tests
docker stats fail2ban-service

# Test with large IP ranges
go test -run TestLargeIPRange ./internal/ipban

# Test memory leaks
go test -run TestMemoryLeak -timeout 30m ./internal/ipban
```

## Manual Testing

### Test Scenarios

#### Scenario 1: Basic Ban Flow
1. Send auth failures for IP 192.168.1.100
2. Verify IP gets banned after max_attempts
3. Verify different IP still works
4. Wait for ban expiry and verify IP is unbanned

#### Scenario 2: Ban Escalation
1. Ban IP 192.168.1.101 (first offense)
2. Wait for ban to expire
3. Generate new violations for same IP
4. Verify ban time has escalated

#### Scenario 3: Multiple Services
1. Send Dovecot auth failures
2. Send Postfix SASL failures
3. Send SOGo login failures
4. Verify all contribute to same IP ban

#### Scenario 4: Proxy Integration
1. Test through HAProxy (if configured)
2. Test through Envoy (if configured)
3. Test through Nginx (if configured)
4. Verify ban decisions are consistent

### Manual Test Commands

```bash
# Generate test violations
generate_violations() {
    local ip=$1
    local count=${2:-6}
    for i in $(seq 1 $count); do
        echo "<134>$(date '+%b %d %H:%M:%S') hostname dovecot: auth failed, method=PLAIN, rip=$ip" | nc -u localhost 514
        sleep 0.1
    done
}

# Test ban flow
generate_violations "192.168.1.100" 6
sleep 2
curl -H "X-Real-IP: 192.168.1.100" http://localhost:8888/auth

# Test different service patterns
echo "<134>$(date '+%b %d %H:%M:%S') hostname postfix/smtpd: warning: SASL authentication failed: authentication failure [192.168.1.101]" | nc -u localhost 514
echo "<134>$(date '+%b %d %H:%M:%S') hostname sogod: Login failed for user 'test' from 192.168.1.101" | nc -u localhost 514
```

## Continuous Integration

### GitHub Actions

See `.github/workflows/test.yml` for automated testing pipeline that runs:

- Unit tests with coverage
- Integration tests with Docker Compose
- Performance benchmarks
- Security scans
- Multi-platform builds

### Test Automation

```bash
# Run full test suite
make test

# Run tests with coverage report
make test-coverage

# Run integration tests
make test-integration

# Run performance tests
make test-performance
```

## Troubleshooting Tests

### Common Test Issues

1. **Port conflicts**: Ensure test ports are available
2. **Docker permissions**: Ensure Docker daemon is accessible
3. **Network connectivity**: Check firewall rules for test ports
4. **Timing issues**: Add appropriate delays for async operations

### Debug Test Failures

```bash
# Run specific test with verbose output
go test -v -run TestSpecificFunction ./internal/package

# Run tests with additional logging
go test -v -run TestFunction ./internal/package -args -test.v

# Check test containers
docker-compose logs fail2ban-service
docker-compose logs nginx
docker-compose logs haproxy
```