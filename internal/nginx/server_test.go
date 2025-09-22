package nginx

import (
	"context"
	"encoding/json"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/ipban"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func getTestConfig() *config.Config {
	return &config.Config{
		Nginx: config.NginxConfig{
			Address:      "127.0.0.1",
			Port:         0, // Use port 0 for dynamic allocation in tests
			Enabled:      true,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			ReturnJSON:   false,
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

func TestExtractClientIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	tests := []struct {
		name     string
		headers  map[string]string
		remoteIP string
		expected string
	}{
		{
			name: "X-Original-IP header (highest priority)",
			headers: map[string]string{
				"X-Original-IP":   "192.168.1.100",
				"X-Forwarded-For": "10.0.0.1",
				"X-Real-IP":       "172.16.0.1",
			},
			expected: "192.168.1.100",
		},
		{
			name: "X-Forwarded-For header",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.200, 10.0.0.1, 172.16.0.1",
				"X-Real-IP":       "10.0.0.50",
			},
			expected: "192.168.1.200",
		},
		{
			name: "X-Real-IP header",
			headers: map[string]string{
				"X-Real-IP":   "10.0.0.100",
				"X-Client-IP": "172.16.0.100",
			},
			expected: "10.0.0.100",
		},
		{
			name: "X-Client-IP header",
			headers: map[string]string{
				"X-Client-IP":      "172.16.0.150",
				"CF-Connecting-IP": "8.8.8.8",
			},
			expected: "172.16.0.150",
		},
		{
			name: "CF-Connecting-IP header",
			headers: map[string]string{
				"CF-Connecting-IP": "1.1.1.1",
			},
			expected: "1.1.1.1",
		},
		{
			name:     "RemoteAddr fallback with port",
			headers:  map[string]string{},
			remoteIP: "203.0.113.1:12345",
			expected: "203.0.113.1",
		},
		{
			name:     "RemoteAddr fallback without port",
			headers:  map[string]string{},
			remoteIP: "203.0.113.2",
			expected: "203.0.113.2",
		},
		{
			name:     "No IP available",
			headers:  map[string]string{},
			remoteIP: "",
			expected: "192.0.2.1", // httptest default IP
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/auth", nil)

			// Set headers
			for key, value := range test.headers {
				req.Header.Set(key, value)
			}

			// Set RemoteAddr if specified
			if test.remoteIP != "" {
				req.RemoteAddr = test.remoteIP
			}

			result := server.extractClientIP(req)
			if result != test.expected {
				t.Errorf("extractClientIP(): expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

func TestHandleAuthRequestAllowed(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("X-Original-IP", "192.168.1.50")
	req.Header.Set("X-Original-URI", "/protected/resource")

	recorder := httptest.NewRecorder()

	server.handleAuthRequest(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	// Check response headers
	if status := recorder.Header().Get("X-Fail2ban-Status"); status != "allowed" {
		t.Errorf("Expected X-Fail2ban-Status 'allowed', got '%s'", status)
	}
	if ip := recorder.Header().Get("X-Fail2ban-IP"); ip != "192.168.1.50" {
		t.Errorf("Expected X-Fail2ban-IP '192.168.1.50', got '%s'", ip)
	}
	if service := recorder.Header().Get("X-Fail2ban-Service"); service != "fail2ban-nginx-auth" {
		t.Errorf("Expected X-Fail2ban-Service 'fail2ban-nginx-auth', got '%s'", service)
	}
}

func TestHandleAuthRequestBanned(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	// Ban an IP
	bannedIP := "192.168.1.250"
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		banManager.RecordViolation(bannedIP, 1, "test violation")
	}

	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("X-Original-IP", bannedIP)
	req.Header.Set("X-Original-URI", "/protected/resource")

	recorder := httptest.NewRecorder()

	server.handleAuthRequest(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}

	// Check response headers
	if status := recorder.Header().Get("X-Fail2ban-Status"); status != "denied" {
		t.Errorf("Expected X-Fail2ban-Status 'denied', got '%s'", status)
	}
	if ip := recorder.Header().Get("X-Fail2ban-IP"); ip != bannedIP {
		t.Errorf("Expected X-Fail2ban-IP '%s', got '%s'", bannedIP, ip)
	}
	if reason := recorder.Header().Get("X-Fail2ban-Reason"); reason == "" {
		t.Error("Expected X-Fail2ban-Reason to be set")
	}
}

func TestHandleAuthRequestBannedWithJSON(t *testing.T) {
	cfg := getTestConfig()
	cfg.Nginx.ReturnJSON = true

	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	// Ban an IP
	bannedIP := "10.0.0.250"
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		banManager.RecordViolation(bannedIP, 1, "test violation")
	}

	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("X-Real-IP", bannedIP)

	recorder := httptest.NewRecorder()

	server.handleAuthRequest(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}

	// Check content type
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Parse JSON response
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse JSON response: %v", err)
	}

	if response["error"] != "access_denied" {
		t.Errorf("Expected error 'access_denied', got '%s'", response["error"])
	}
	if response["ip"] != bannedIP {
		t.Errorf("Expected ip '%s', got '%s'", bannedIP, response["ip"])
	}
	if response["reason"] == "" {
		t.Error("Expected reason to be set in JSON response")
	}
}

func TestHandleAuthRequestNoIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	req := httptest.NewRequest("GET", "/auth", nil)
	// Don't set any IP headers or RemoteAddr

	recorder := httptest.NewRecorder()

	server.handleAuthRequest(recorder, req)

	// Should allow when no IP can be determined
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d when no IP found, got %d", http.StatusOK, recorder.Code)
	}

	if status := recorder.Header().Get("X-Fail2ban-Status"); status != "allowed" {
		t.Errorf("Expected X-Fail2ban-Status 'allowed' when no IP found, got '%s'", status)
	}
	if ip := recorder.Header().Get("X-Fail2ban-IP"); ip != "192.0.2.1" {
		t.Errorf("Expected X-Fail2ban-IP '192.0.2.1' (httptest default) when no IP found, got '%s'", ip)
	}
}

func TestHandleHealthCheck(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	req := httptest.NewRequest("GET", "/health", nil)
	recorder := httptest.NewRecorder()

	server.handleHealthCheck(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Parse JSON response
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse JSON response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", response["status"])
	}
	if response["service"] != "fail2ban-nginx-auth" {
		t.Errorf("Expected service 'fail2ban-nginx-auth', got '%s'", response["service"])
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

	cfg.Nginx.Port = addr.Port

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
	case <-time.After(10 * time.Second):
		t.Error("Server did not stop within timeout")
	}
}

func TestServerInvalidAddress(t *testing.T) {
	cfg := getTestConfig()
	cfg.Nginx.Address = "invalid.address.that.does.not.exist"
	cfg.Nginx.Port = 99999

	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	ctx := context.Background()
	err := server.Start(ctx)

	if err == nil {
		t.Error("Expected error when starting with invalid address, got nil")
	}
}

func TestHTTPIntegration(t *testing.T) {
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

	cfg.Nginx.Port = addr.Port

	server := NewServer(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.Nginx.Port)

	// Test health check
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("Failed to make health check request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected health check status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Test auth request with allowed IP
	req, err := http.NewRequest("GET", baseURL+"/auth", nil)
	if err != nil {
		t.Fatalf("Failed to create auth request: %v", err)
	}
	req.Header.Set("X-Original-IP", "10.0.0.100")
	req.Header.Set("X-Original-URI", "/test")

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make auth request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected auth status %d for allowed IP, got %d", http.StatusOK, resp.StatusCode)
	}

	// Ban an IP and test again
	bannedIP := "10.0.0.200"
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		banManager.RecordViolation(bannedIP, 1, "test violation")
	}

	req.Header.Set("X-Original-IP", bannedIP)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make auth request for banned IP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected auth status %d for banned IP, got %d", http.StatusForbidden, resp.StatusCode)
	}

	// Check response headers
	if status := resp.Header.Get("X-Fail2ban-Status"); status != "denied" {
		t.Errorf("Expected X-Fail2ban-Status 'denied', got '%s'", status)
	}
}

func TestConcurrentRequests(t *testing.T) {
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

	cfg.Nginx.Port = addr.Port

	server := NewServer(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.Nginx.Port)

	// Test concurrent requests
	numRequests := 20
	results := make(chan error, numRequests)

	client := &http.Client{}

	for i := 0; i < numRequests; i++ {
		go func(requestID int) {
			req, err := http.NewRequest("GET", baseURL+"/auth", nil)
			if err != nil {
				results <- fmt.Errorf("request %d failed to create: %v", requestID, err)
				return
			}

			req.Header.Set("X-Original-IP", fmt.Sprintf("10.0.1.%d", requestID+1))
			req.Header.Set("X-Original-URI", fmt.Sprintf("/test/%d", requestID))

			resp, err := client.Do(req)
			if err != nil {
				results <- fmt.Errorf("request %d failed: %v", requestID, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				results <- fmt.Errorf("request %d got unexpected status: %d", requestID, resp.StatusCode)
				return
			}

			results <- nil
		}(i)
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Request did not complete within timeout")
		}
	}
}

func TestAllowAndDenyResponseMethods(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	// Test allowResponse
	recorder := httptest.NewRecorder()
	server.allowResponse(recorder, "192.168.1.1")

	if recorder.Code != http.StatusOK {
		t.Errorf("allowResponse: expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if status := recorder.Header().Get("X-Fail2ban-Status"); status != "allowed" {
		t.Errorf("allowResponse: expected X-Fail2ban-Status 'allowed', got '%s'", status)
	}

	// Test denyResponse without JSON
	recorder = httptest.NewRecorder()
	server.denyResponse(recorder, "192.168.1.2", "test reason")

	if recorder.Code != http.StatusForbidden {
		t.Errorf("denyResponse: expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
	if status := recorder.Header().Get("X-Fail2ban-Status"); status != "denied" {
		t.Errorf("denyResponse: expected X-Fail2ban-Status 'denied', got '%s'", status)
	}
	if reason := recorder.Header().Get("X-Fail2ban-Reason"); reason != "test reason" {
		t.Errorf("denyResponse: expected X-Fail2ban-Reason 'test reason', got '%s'", reason)
	}

	// Test denyResponse with JSON
	cfg.Nginx.ReturnJSON = true
	recorder = httptest.NewRecorder()
	server.denyResponse(recorder, "192.168.1.3", "json test reason")

	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("denyResponse JSON: expected Content-Type 'application/json', got '%s'", contentType)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "json test reason") {
		t.Errorf("denyResponse JSON: expected body to contain reason, got '%s'", body)
	}
	if !strings.Contains(body, "192.168.1.3") {
		t.Errorf("denyResponse JSON: expected body to contain IP, got '%s'", body)
	}
}
