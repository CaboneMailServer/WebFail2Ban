package spoa

import (
	"bufio"
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
		SPOA: config.SPOAConfig{
			Address:     "127.0.0.1",
			Port:        0, // Use port 0 for dynamic allocation in tests
			MaxClients:  10,
			ReadTimeout: 5 * time.Second,
			Enabled:     true,
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

func TestNewServer(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	server := NewServer(cfg, logger, banManager)

	if server == nil {
		t.Fatal("Expected server to be created, got nil")
	}
	if server.cfg != cfg {
		t.Error("Expected config to be set correctly")
	}
	if server.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
	if server.banManager != banManager {
		t.Error("Expected ban manager to be set correctly")
	}
}

func TestProcessMessage(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	tests := []struct {
		message  string
		expected string
		name     string
	}{
		{
			message:  "haproxy_processing src=192.168.1.100",
			expected: "banned=0",
			name:     "non-banned IP",
		},
		{
			message:  "haproxy_processing src=10.0.0.1 dest=10.0.0.2",
			expected: "banned=0",
			name:     "non-banned IP with multiple params",
		},
		{
			message:  "notify event=connection_closed",
			expected: "",
			name:     "notify message",
		},
		{
			message:  "unknown_command param=value",
			expected: "",
			name:     "unknown command",
		},
		{
			message:  "incomplete",
			expected: "",
			name:     "incomplete message",
		},
		{
			message:  "",
			expected: "",
			name:     "empty message",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := server.processMessage(test.message)
			if result != test.expected {
				t.Errorf("processMessage(%s): expected '%s', got '%s'", test.message, test.expected, result)
			}
		})
	}
}

func TestProcessMessageWithBannedIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	// Ban an IP
	bannedIP := "192.168.1.200"
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		banManager.RecordViolation(bannedIP, 1, "test violation")
	}

	// Verify IP is banned
	if !banManager.IsBanned(bannedIP) {
		t.Fatal("Expected IP to be banned for test")
	}

	// Test banned IP response
	message := fmt.Sprintf("haproxy_processing src=%s", bannedIP)
	result := server.processMessage(message)

	if result != "banned=1" {
		t.Errorf("Expected banned=1 for banned IP, got '%s'", result)
	}
}

func TestHandleHAProxyProcessing(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	tests := []struct {
		parts    []string
		expected string
		name     string
	}{
		{
			parts:    []string{"src=192.168.1.1"},
			expected: "banned=0",
			name:     "single src parameter",
		},
		{
			parts:    []string{"src=10.0.0.1", "dest=10.0.0.2", "port=80"},
			expected: "banned=0",
			name:     "multiple parameters with src",
		},
		{
			parts:    []string{"dest=10.0.0.2", "port=80"},
			expected: "banned=0",
			name:     "no src parameter",
		},
		{
			parts:    []string{},
			expected: "banned=0",
			name:     "empty parts",
		},
		{
			parts:    []string{"invalid_param=value"},
			expected: "banned=0",
			name:     "invalid parameters",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := server.handleHAProxyProcessing(test.parts)
			if result != test.expected {
				t.Errorf("handleHAProxyProcessing(%v): expected '%s', got '%s'", test.parts, test.expected, result)
			}
		})
	}
}

func TestHandleHAProxyProcessingWithBannedIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	// Ban an IP
	bannedIP := "172.16.0.100"
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		banManager.RecordViolation(bannedIP, 1, "test violation")
	}

	parts := []string{fmt.Sprintf("src=%s", bannedIP), "dest=172.16.0.1"}
	result := server.handleHAProxyProcessing(parts)

	if result != "banned=1" {
		t.Errorf("Expected banned=1 for banned IP, got '%s'", result)
	}
}

func TestHandleNotify(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	// Test notify handler (currently returns empty string)
	parts := []string{"event=connection_closed", "ip=192.168.1.1"}
	result := server.handleNotify(parts)

	if result != "" {
		t.Errorf("Expected empty response for notify, got '%s'", result)
	}
}

func TestServerStartAndStop(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	listener.Close()

	cfg.SPOA.Port = addr.Port

	server := NewServer(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		err := server.Start(ctx)
		errChan <- err
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop server
	cancel()

	// Wait for server to stop
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Expected server to stop cleanly, got error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Server did not stop within timeout")
	}
}

func TestServerInvalidAddress(t *testing.T) {
	cfg := getTestConfig()
	cfg.SPOA.Address = "invalid.address.that.does.not.exist"
	cfg.SPOA.Port = 99999

	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	ctx := context.Background()
	err := server.Start(ctx)

	if err == nil {
		t.Error("Expected error when starting with invalid address, got nil")
	}
	if !strings.Contains(err.Error(), "failed to listen") {
		t.Errorf("Expected 'failed to listen' error, got: %v", err)
	}
}

func TestClientHandling(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	listener.Close()

	cfg.SPOA.Port = addr.Port

	server := NewServer(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine
	go func() {
		server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect to server
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.SPOA.Port))
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Test communication
	testCases := []struct {
		send     string
		expected string
	}{
		{"haproxy_processing src=192.168.1.50", "banned=0"},
		{"notify event=test", ""},
		{"invalid_command", ""},
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for _, test := range testCases {
		// Send message
		_, err = writer.WriteString(test.send + "\n")
		if err != nil {
			t.Errorf("Failed to send message: %v", err)
			continue
		}
		err = writer.Flush()
		if err != nil {
			t.Errorf("Failed to flush message: %v", err)
			continue
		}

		// Read response if expected
		if test.expected != "" {
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			response, err := reader.ReadString('\n')
			if err != nil {
				t.Errorf("Failed to read response: %v", err)
				continue
			}
			response = strings.TrimSpace(response)
			if response != test.expected {
				t.Errorf("Expected response '%s', got '%s'", test.expected, response)
			}
		}
	}
}

func TestClientHandlingWithBannedIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	// Ban an IP first
	bannedIP := "10.0.0.200"
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		banManager.RecordViolation(bannedIP, 1, "test violation")
	}

	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	listener.Close()

	cfg.SPOA.Port = addr.Port

	server := NewServer(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect and test banned IP
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.SPOA.Port))
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	// Send request for banned IP
	message := fmt.Sprintf("haproxy_processing src=%s", bannedIP)
	_, err = writer.WriteString(message + "\n")
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}
	err = writer.Flush()
	if err != nil {
		t.Fatalf("Failed to flush message: %v", err)
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	response = strings.TrimSpace(response)
	if response != "banned=1" {
		t.Errorf("Expected 'banned=1' for banned IP, got '%s'", response)
	}
}

func TestMultipleClients(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)

	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	listener.Close()

	cfg.SPOA.Port = addr.Port

	server := NewServer(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test multiple concurrent clients
	numClients := 5
	done := make(chan bool, numClients)

	for i := 0; i < numClients; i++ {
		go func(clientID int) {
			defer func() { done <- true }()

			conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.SPOA.Port))
			if err != nil {
				t.Errorf("Client %d failed to connect: %v", clientID, err)
				return
			}
			defer conn.Close()

			writer := bufio.NewWriter(conn)
			reader := bufio.NewReader(conn)

			// Send a test message
			message := fmt.Sprintf("haproxy_processing src=192.168.1.%d", clientID+10)
			_, err = writer.WriteString(message + "\n")
			if err != nil {
				t.Errorf("Client %d failed to send message: %v", clientID, err)
				return
			}
			err = writer.Flush()
			if err != nil {
				t.Errorf("Client %d failed to flush message: %v", clientID, err)
				return
			}

			// Read response
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			response, err := reader.ReadString('\n')
			if err != nil {
				t.Errorf("Client %d failed to read response: %v", clientID, err)
				return
			}

			response = strings.TrimSpace(response)
			if response != "banned=0" {
				t.Errorf("Client %d expected 'banned=0', got '%s'", clientID, response)
			}
		}(i)
	}

	// Wait for all clients to complete
	for i := 0; i < numClients; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Client did not complete within timeout")
		}
	}
}
