package syslog

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/ipban"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func getTestConfig() *config.Config {
	return &config.Config{
		Syslog: config.SyslogConfig{
			Address:  "127.0.0.1:0", // Use port 0 for dynamic allocation in tests
			Protocol: "udp",
			Patterns: []config.PatternConfig{
				{
					Name:        "dovecot-auth-failure",
					Regex:       `auth failed.*rip=([0-9.]+)`,
					IPGroup:     1,
					Severity:    3,
					Description: "Dovecot authentication failure",
				},
				{
					Name:        "postfix-auth-failure",
					Regex:       `authentication failed.*client=([0-9.]+)`,
					IPGroup:     1,
					Severity:    2,
					Description: "Postfix authentication failure",
				},
				{
					Name:        "ssh-brute-force",
					Regex:       `Failed password.*from ([0-9.]+)`,
					IPGroup:     1,
					Severity:    4,
					Description: "SSH brute force attempt",
				},
			},
		},
		Ban: config.BanConfig{
			InitialBanTime:   5 * time.Minute,
			MaxBanTime:       24 * time.Hour,
			EscalationFactor: 2.0,
			MaxAttempts:      3,
			TimeWindow:       10 * time.Minute,
			CleanupInterval:  1 * time.Minute,
			MaxMemoryTTL:     72 * time.Hour,
		},
	}
}

func getTestLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func TestNewReader(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	reader := NewReader(cfg, logger, banManager)

	if reader == nil {
		t.Fatal("Expected reader to be created, got nil")
	}
	if reader.cfg != cfg {
		t.Error("Expected config to be set correctly")
	}
	if reader.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
	if reader.banManager != banManager {
		t.Error("Expected ban manager to be set correctly")
	}
	if len(reader.patterns) != len(cfg.Syslog.Patterns) {
		t.Errorf("Expected %d compiled patterns, got %d", len(cfg.Syslog.Patterns), len(reader.patterns))
	}
}

func TestNewReaderInvalidRegex(t *testing.T) {
	cfg := getTestConfig()
	cfg.Syslog.Patterns = []config.PatternConfig{
		{
			Name:        "invalid-pattern",
			Regex:       "[unclosed",
			IPGroup:     1,
			Severity:    1,
			Description: "Invalid regex pattern",
		},
		{
			Name:        "valid-pattern",
			Regex:       `valid.*pattern=([0-9.]+)`,
			IPGroup:     1,
			Severity:    1,
			Description: "Valid regex pattern",
		},
	}

	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	reader := NewReader(cfg, logger, banManager)

	// Should only compile valid patterns
	if len(reader.patterns) != 1 {
		t.Errorf("Expected 1 compiled pattern (invalid one should be skipped), got %d", len(reader.patterns))
	}
	if reader.patterns[0].name != "valid-pattern" {
		t.Errorf("Expected compiled pattern to be 'valid-pattern', got '%s'", reader.patterns[0].name)
	}
}

func TestProcessMessage(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	reader := NewReader(cfg, logger, banManager)

	tests := []struct {
		message         string
		expectedIP      string
		expectedPattern string
		shouldMatch     bool
	}{
		{
			message:         "Oct 15 10:30:15 mail dovecot: auth failed, 1 attempts in 0 secs: user=test@example.com, method=PLAIN, rip=192.168.1.100",
			expectedIP:      "192.168.1.100",
			expectedPattern: "dovecot-auth-failure",
			shouldMatch:     true,
		},
		{
			message:         "Oct 15 10:30:16 mail postfix/smtpd: authentication failed: client=10.0.0.50",
			expectedIP:      "10.0.0.50",
			expectedPattern: "postfix-auth-failure",
			shouldMatch:     true,
		},
		{
			message:         "Oct 15 10:30:17 ssh sshd: Failed password for root from 172.16.0.100 port 22 ssh2",
			expectedIP:      "172.16.0.100",
			expectedPattern: "ssh-brute-force",
			shouldMatch:     true,
		},
		{
			message:     "Oct 15 10:30:18 mail dovecot: auth failed, rip=invalid.ip.address",
			shouldMatch: false,
		},
		{
			message:     "Oct 15 10:30:19 mail dovecot: successful login for user@example.com",
			shouldMatch: false,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			// Clear previous violations
			banManager = ipban.NewManager(cfg, logger)
			reader.banManager = banManager

			reader.processMessage(test.message)

			if test.shouldMatch {
				// Check if violation was recorded
				stats := banManager.GetIPStats(test.expectedIP)

				if stats == nil {
					t.Errorf("Expected IP %s to have stats recorded", test.expectedIP)
					return
				}
				if len(stats.Violations) != 1 {
					t.Errorf("Expected 1 violation for IP %s, got %d", test.expectedIP, len(stats.Violations))
					return
				}

				// Find the expected pattern
				var expectedSeverity int
				var expectedDescription string
				for _, pattern := range reader.patterns {
					if pattern.name == test.expectedPattern {
						expectedSeverity = pattern.severity
						expectedDescription = pattern.description
						break
					}
				}

				violation := stats.Violations[0]
				if violation.Severity != expectedSeverity {
					t.Errorf("Expected severity %d, got %d", expectedSeverity, violation.Severity)
				}
				if violation.Description != expectedDescription {
					t.Errorf("Expected description '%s', got '%s'", expectedDescription, violation.Description)
				}
			} else {
				// Check that no violations were recorded
				statsCount := banManager.GetStatsCount()

				if statsCount > 0 {
					t.Errorf("Expected no violations to be recorded for non-matching message, got %d stats entries", statsCount)
				}
			}
		})
	}
}

func TestIsValidIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	reader := NewReader(cfg, logger, banManager)

	tests := []struct {
		ip    string
		valid bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"8.8.8.8", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"invalid.ip", false},
		{"999.999.999.999", false},
		{"192.168.1", false},
		{"", false},
		{"not.an.ip.address", false},
	}

	for _, test := range tests {
		result := reader.isValidIP(test.ip)
		if result != test.valid {
			t.Errorf("isValidIP(%s): expected %t, got %t", test.ip, test.valid, result)
		}
	}
}

func TestStartAndStop(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	// Create a reader with a dynamic port
	reader := NewReader(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())

	// Start reader in goroutine
	errChan := make(chan error, 1)
	go func() {
		err := reader.Start(ctx)
		errChan <- err
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop reader
	cancel()

	// Wait for reader to stop
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Expected reader to stop cleanly, got error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Reader did not stop within timeout")
	}
}

func TestStartInvalidAddress(t *testing.T) {
	cfg := getTestConfig()
	cfg.Syslog.Address = "invalid:address:format"

	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	reader := NewReader(cfg, logger, banManager)

	ctx := context.Background()
	err := reader.Start(ctx)

	if err == nil {
		t.Error("Expected error when starting with invalid address, got nil")
	}
	if !strings.Contains(err.Error(), "failed to resolve syslog address") {
		t.Errorf("Expected 'failed to resolve syslog address' error, got: %v", err)
	}
}

func TestIntegrationWithRealSocket(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	// Create reader with dynamic port allocation
	reader := NewReader(cfg, logger, banManager)

	// Find an available port
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create test UDP socket: %v", err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()

	// Update config with the available port
	cfg.Syslog.Address = fmt.Sprintf("127.0.0.1:%d", addr.Port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start reader in goroutine
	go func() {
		reader.Start(ctx)
	}()

	// Give reader time to start
	time.Sleep(100 * time.Millisecond)

	// Send test messages
	testConn, err := net.Dial("udp", cfg.Syslog.Address)
	if err != nil {
		t.Fatalf("Failed to connect to syslog reader: %v", err)
	}
	defer testConn.Close()

	testMessages := []string{
		"Oct 15 10:30:15 mail dovecot: auth failed, 1 attempts in 0 secs: user=test@example.com, method=PLAIN, rip=192.168.1.200",
		"Oct 15 10:30:16 mail dovecot: auth failed, 2 attempts in 0 secs: user=test@example.com, method=PLAIN, rip=192.168.1.200",
		"Oct 15 10:30:17 mail dovecot: auth failed, 3 attempts in 0 secs: user=test@example.com, method=PLAIN, rip=192.168.1.200",
	}

	for _, msg := range testMessages {
		_, err = testConn.Write([]byte(msg))
		if err != nil {
			t.Errorf("Failed to send test message: %v", err)
		}
		time.Sleep(10 * time.Millisecond) // Small delay between messages
	}

	// Give reader time to process messages
	time.Sleep(200 * time.Millisecond)

	// Check if IP was banned
	if !banManager.IsBanned("192.168.1.200") {
		t.Error("Expected IP 192.168.1.200 to be banned after 3 violations")
	}

	stats := banManager.GetIPStats("192.168.1.200")

	if stats == nil {
		t.Fatal("Expected stats for IP 192.168.1.200")
	}
	if len(stats.Violations) != 3 {
		t.Errorf("Expected 3 violations, got %d", len(stats.Violations))
	}
}

func TestCompiledPatternMatching(t *testing.T) {
	cfg := &config.Config{
		Syslog: config.SyslogConfig{
			Patterns: []config.PatternConfig{
				{
					Name:        "test-pattern",
					Regex:       `test message.*ip=([0-9.]+).*severity=(\d+)`,
					IPGroup:     1,
					Severity:    3,
					Description: "Test pattern",
				},
			},
		},
	}

	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	reader := NewReader(cfg, logger, banManager)

	if len(reader.patterns) != 1 {
		t.Fatalf("Expected 1 compiled pattern, got %d", len(reader.patterns))
	}

	pattern := reader.patterns[0]
	if pattern.name != "test-pattern" {
		t.Errorf("Expected pattern name 'test-pattern', got '%s'", pattern.name)
	}
	if pattern.ipGroup != 1 {
		t.Errorf("Expected IP group 1, got %d", pattern.ipGroup)
	}
	if pattern.severity != 3 {
		t.Errorf("Expected severity 3, got %d", pattern.severity)
	}
	if pattern.description != "Test pattern" {
		t.Errorf("Expected description 'Test pattern', got '%s'", pattern.description)
	}

	// Test regex compilation
	testMessage := "test message from client ip=10.0.0.100 with severity=5"
	matches := pattern.regex.FindStringSubmatch(testMessage)

	if len(matches) < 2 {
		t.Fatalf("Expected at least 2 matches, got %d", len(matches))
	}
	if matches[1] != "10.0.0.100" {
		t.Errorf("Expected IP match '10.0.0.100', got '%s'", matches[1])
	}
}
