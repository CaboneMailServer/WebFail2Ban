package ipban

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"testing"
	"time"

	"go.uber.org/zap"
)

func getTestConfig() *config.Config {
	return &config.Config{
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

func TestNewManager(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()

	manager := NewManager(cfg, logger)

	if manager == nil {
		t.Fatal("Expected manager to be created, got nil")
	}
	if manager.cfg != cfg {
		t.Error("Expected config to be set correctly")
	}
	if manager.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
	if manager.tree == nil {
		t.Error("Expected radix tree to be initialized")
	}
	if manager.stats == nil {
		t.Error("Expected stats map to be initialized")
	}
}

func TestRecordViolation(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	manager := NewManager(cfg, logger)

	ip := "192.168.1.100"
	severity := 3
	description := "Failed login attempt"

	// Record first violation
	manager.RecordViolation(ip, severity, description)

	stats := manager.GetIPStats(ip)

	if stats == nil {
		t.Fatal("Expected IP stats to be created")
	}
	if len(stats.Violations) != 1 {
		t.Errorf("Expected 1 violation, got %d", len(stats.Violations))
	}
	if stats.TotalSeverity != severity {
		t.Errorf("Expected total severity %d, got %d", severity, stats.TotalSeverity)
	}
	if stats.Violations[0].Severity != severity {
		t.Errorf("Expected violation severity %d, got %d", severity, stats.Violations[0].Severity)
	}
	if stats.Violations[0].Description != description {
		t.Errorf("Expected violation description '%s', got '%s'", description, stats.Violations[0].Description)
	}
}

func TestBanAfterMaxAttempts(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	manager := NewManager(cfg, logger)

	ip := "192.168.1.101"

	// Record violations up to max attempts
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		manager.RecordViolation(ip, 1, "test violation")
	}

	// Check if IP is banned
	if !manager.IsBanned(ip) {
		t.Error("Expected IP to be banned after max attempts")
	}

	stats := manager.GetIPStats(ip)

	if stats.BanCount != 1 {
		t.Errorf("Expected ban count 1, got %d", stats.BanCount)
	}
	if stats.BanExpiry.Before(time.Now()) {
		t.Error("Expected ban expiry to be in the future")
	}
}

func TestBanEscalation(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	manager := NewManager(cfg, logger)

	ip := "192.168.1.102"

	// First ban cycle
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		manager.RecordViolation(ip, 1, "test violation")
	}

	stats := manager.GetIPStats(ip)
	firstBanExpiry := stats.BanExpiry

	// Simulate ban expiry by manipulating the stats directly
	// Note: This is accessing internal state for testing purposes
	stats.BanExpiry = time.Now().Add(-1 * time.Second)

	// Second ban cycle
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		manager.RecordViolation(ip, 1, "test violation")
	}

	stats = manager.GetIPStats(ip)
	secondBanExpiry := stats.BanExpiry
	banCount := stats.BanCount

	if banCount != 2 {
		t.Errorf("Expected ban count 2, got %d", banCount)
	}

	// Second ban should be longer due to escalation
	firstDuration := firstBanExpiry.Sub(time.Now().Add(-cfg.Ban.InitialBanTime))
	secondDuration := secondBanExpiry.Sub(time.Now())

	if secondDuration <= firstDuration {
		t.Error("Expected second ban to be longer due to escalation")
	}
}

func TestIsBannedExpiry(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	manager := NewManager(cfg, logger)

	ip := "192.168.1.103"

	// Record violations to trigger ban
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		manager.RecordViolation(ip, 1, "test violation")
	}

	// Should be banned
	if !manager.IsBanned(ip) {
		t.Error("Expected IP to be banned")
	}

	// Simulate ban expiry
	stats := manager.GetIPStats(ip)
	stats.BanExpiry = time.Now().Add(-1 * time.Second)

	// Should not be banned anymore
	if manager.IsBanned(ip) {
		t.Error("Expected IP to not be banned after expiry")
	}
}

func TestTimeWindowCleanup(t *testing.T) {
	cfg := getTestConfig()
	cfg.Ban.TimeWindow = 1 * time.Second // Short window for testing
	logger := getTestLogger()
	manager := NewManager(cfg, logger)

	ip := "192.168.1.104"

	// Record some violations
	manager.RecordViolation(ip, 1, "old violation")
	manager.RecordViolation(ip, 1, "old violation")

	// Wait for time window to pass
	time.Sleep(2 * time.Second)

	// Record new violation - should clean old ones
	manager.RecordViolation(ip, 1, "new violation")

	stats := manager.GetIPStats(ip)

	// Should only have the latest violation
	if len(stats.Violations) != 1 {
		t.Errorf("Expected 1 violation after cleanup, got %d", len(stats.Violations))
	}
	if stats.TotalSeverity != 1 {
		t.Errorf("Expected total severity 1 after cleanup, got %d", stats.TotalSeverity)
	}
}

func TestCleanup(t *testing.T) {
	cfg := getTestConfig()
	cfg.Ban.MaxMemoryTTL = 1 * time.Second // Short TTL for testing
	logger := getTestLogger()
	manager := NewManager(cfg, logger)

	ip := "192.168.1.105"

	// Record violation
	manager.RecordViolation(ip, 1, "test violation")

	// Verify IP exists in stats
	stats := manager.GetIPStats(ip)
	if stats == nil {
		t.Fatal("Expected IP to exist in stats")
	}

	// Wait for TTL to pass
	time.Sleep(2 * time.Second)

	// Run cleanup
	manager.cleanup()

	// Verify IP was cleaned up
	stats = manager.GetIPStats(ip)
	if stats != nil {
		t.Error("Expected IP to be cleaned up from stats")
	}
}

func TestStartCleanup(t *testing.T) {
	cfg := getTestConfig()
	cfg.Ban.CleanupInterval = 100 * time.Millisecond // Fast cleanup for testing
	logger := getTestLogger()
	manager := NewManager(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup in goroutine
	go manager.StartCleanup(ctx)

	// Let it run for a bit
	time.Sleep(500 * time.Millisecond)

	// Cancel and verify it stops
	cancel()

	// Give it time to stop
	time.Sleep(200 * time.Millisecond)

	// Test passes if no panic or deadlock occurs
}

func TestRadixTreeOperations(t *testing.T) {
	tree := NewRadixTree()

	testIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"::1",
		"2001:db8::1",
	}

	// Test insertion and search
	for _, ip := range testIPs {
		tree.Insert(ip)
		if !tree.Search(ip) {
			t.Errorf("Expected IP %s to be found after insertion", ip)
		}
	}

	// Test that non-inserted IPs are not found
	if tree.Search("8.8.8.8") {
		t.Error("Expected non-inserted IP to not be found")
	}

	// Test deletion
	for _, ip := range testIPs {
		tree.Delete(ip)
		if tree.Search(ip) {
			t.Errorf("Expected IP %s to not be found after deletion", ip)
		}
	}
}

func TestRadixTreeInvalidIP(t *testing.T) {
	tree := NewRadixTree()

	// Test with invalid IP
	tree.Insert("invalid.ip")
	if tree.Search("invalid.ip") {
		t.Error("Expected invalid IP to not be inserted")
	}

	tree.Delete("invalid.ip") // Should not panic
}

func TestIPToBytes(t *testing.T) {
	tests := []struct {
		ip       string
		expected int
	}{
		{"192.168.1.1", 4}, // IPv4
		{"::1", 16},        // IPv6
		{"invalid", 0},     // Invalid IP
	}

	for _, test := range tests {
		bytes := ipToBytes(test.ip)
		if test.expected == 0 && bytes != nil {
			t.Errorf("Expected nil for invalid IP %s, got %v", test.ip, bytes)
		} else if test.expected > 0 && len(bytes) != test.expected {
			t.Errorf("Expected %d bytes for IP %s, got %d", test.expected, test.ip, len(bytes))
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	manager := NewManager(cfg, logger)

	ip := "192.168.1.106"

	// Test concurrent violations and checks
	done := make(chan bool, 10)

	// Start multiple goroutines recording violations
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				manager.RecordViolation(ip, 1, "concurrent violation")
				manager.IsBanned(ip)
			}
			done <- true
		}()
	}

	// Start multiple goroutines checking ban status
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				manager.IsBanned(ip)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic or deadlock
	stats := manager.GetIPStats(ip)

	if stats == nil {
		t.Error("Expected IP stats to exist after concurrent access")
	}
}
