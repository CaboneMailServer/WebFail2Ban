package envoy

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/ipban"
	"fmt"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

func getTestConfig() *config.Config {
	return &config.Config{
		Envoy: config.EnvoyConfig{
			Address: "127.0.0.1",
			Port:    0, // Use port 0 for dynamic allocation in tests
			Enabled: true,
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

func TestAllowResponse(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	response := server.allowResponse()

	if response == nil {
		t.Fatal("Expected response to be created, got nil")
	}
	if response.Status == nil {
		t.Fatal("Expected status to be set, got nil")
	}
	if response.Status.Code != int32(codes.OK) {
		t.Errorf("Expected status code %d, got %d", int32(codes.OK), response.Status.Code)
	}
}

func TestDenyResponse(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	reason := "Test denial reason"
	response := server.denyResponse(reason)

	if response == nil {
		t.Fatal("Expected response to be created, got nil")
	}
	if response.Status == nil {
		t.Fatal("Expected status to be set, got nil")
	}
	if response.Status.Code != int32(codes.PermissionDenied) {
		t.Errorf("Expected status code %d, got %d", int32(codes.PermissionDenied), response.Status.Code)
	}
	if response.Status.Message != reason {
		t.Errorf("Expected message '%s', got '%s'", reason, response.Status.Message)
	}
}

func TestExtractClientIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	tests := []struct {
		name     string
		req      *auth.CheckRequest
		expected string
	}{
		{
			name: "IP from X-Forwarded-For header",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"x-forwarded-for": "192.168.1.100, 10.0.0.1",
							},
						},
					},
				},
			},
			expected: "192.168.1.100",
		},
		{
			name: "IP from X-Real-IP header",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"x-real-ip": "10.0.0.50",
							},
						},
					},
				},
			},
			expected: "10.0.0.50",
		},
		{
			name: "IP from source address",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "172.16.0.100",
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: 12345,
									},
								},
							},
						},
					},
				},
			},
			expected: "172.16.0.100",
		},
		{
			name: "IP from destination address (fallback)",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Destination: &auth.AttributeContext_Peer{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Address: "8.8.8.8",
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: 80,
									},
								},
							},
						},
					},
				},
			},
			expected: "8.8.8.8",
		},
		{
			name:     "No IP available",
			req:      &auth.CheckRequest{},
			expected: "",
		},
		{
			name: "X-Forwarded-For takes precedence over X-Real-IP",
			req: &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"x-forwarded-for": "192.168.1.200",
								"x-real-ip":       "10.0.0.200",
							},
						},
					},
				},
			},
			expected: "192.168.1.200",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := server.extractClientIP(test.req)
			if result != test.expected {
				t.Errorf("extractClientIP(): expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

func TestCheckAllowedIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	ctx := context.Background()
	req := &auth.CheckRequest{
		Attributes: &auth.AttributeContext{
			Request: &auth.AttributeContext_Request{
				Http: &auth.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"x-forwarded-for": "192.168.1.150",
					},
				},
			},
		},
	}

	response, err := server.Check(ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}
	if response.Status.Code != int32(codes.OK) {
		t.Errorf("Expected status code %d for allowed IP, got %d", int32(codes.OK), response.Status.Code)
	}
}

func TestCheckBannedIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	// Ban an IP
	bannedIP := "192.168.1.250"
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		banManager.RecordViolation(bannedIP, 1, "test violation")
	}

	ctx := context.Background()
	req := &auth.CheckRequest{
		Attributes: &auth.AttributeContext{
			Request: &auth.AttributeContext_Request{
				Http: &auth.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"x-forwarded-for": bannedIP,
					},
				},
			},
		},
	}

	response, err := server.Check(ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}
	if response.Status.Code != int32(codes.PermissionDenied) {
		t.Errorf("Expected status code %d for banned IP, got %d", int32(codes.PermissionDenied), response.Status.Code)
	}
	if response.Status.Message == "" {
		t.Error("Expected error message for banned IP, got empty string")
	}
}

func TestCheckNoClientIP(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	ctx := context.Background()
	req := &auth.CheckRequest{} // Empty request with no IP information

	response, err := server.Check(ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if response == nil {
		t.Fatal("Expected response, got nil")
	}
	// Should allow when no IP can be extracted
	if response.Status.Code != int32(codes.OK) {
		t.Errorf("Expected status code %d when no IP found, got %d", int32(codes.OK), response.Status.Code)
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

	cfg.Envoy.Port = addr.Port

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
		if err != nil && err.Error() != "rpc error: code = Canceled desc = context canceled" {
			t.Errorf("Expected server to stop cleanly, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Server did not stop within timeout")
	}
}

func TestServerInvalidAddress(t *testing.T) {
	cfg := getTestConfig()
	cfg.Envoy.Address = "invalid.address.that.does.not.exist"
	cfg.Envoy.Port = 99999

	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	ctx := context.Background()
	err := server.Start(ctx)

	if err == nil {
		t.Error("Expected error when starting with invalid address, got nil")
	}
}

func TestGRPCIntegration(t *testing.T) {
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

	cfg.Envoy.Port = addr.Port

	server := NewServer(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Create gRPC client
	conn, err := grpc.Dial(
		fmt.Sprintf("127.0.0.1:%d", cfg.Envoy.Port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	// Test allowed IP
	req := &auth.CheckRequest{
		Attributes: &auth.AttributeContext{
			Request: &auth.AttributeContext_Request{
				Http: &auth.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"x-real-ip": "10.0.0.100",
					},
				},
			},
		},
	}

	response, err := client.Check(context.Background(), req)
	if err != nil {
		t.Errorf("Expected no error for allowed IP, got: %v", err)
	}
	if response.Status.Code != int32(codes.OK) {
		t.Errorf("Expected OK status for allowed IP, got: %d", response.Status.Code)
	}

	// Ban an IP and test again
	bannedIP := "10.0.0.200"
	for i := 0; i < cfg.Ban.MaxAttempts; i++ {
		banManager.RecordViolation(bannedIP, 1, "test violation")
	}

	req.Attributes.Request.Http.Headers["x-real-ip"] = bannedIP
	response, err = client.Check(context.Background(), req)
	if err != nil {
		t.Errorf("Expected no error for banned IP check, got: %v", err)
	}
	if response.Status.Code != int32(codes.PermissionDenied) {
		t.Errorf("Expected PermissionDenied status for banned IP, got: %d", response.Status.Code)
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

	cfg.Envoy.Port = addr.Port

	server := NewServer(cfg, logger, banManager)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Create gRPC client
	conn, err := grpc.Dial(
		fmt.Sprintf("127.0.0.1:%d", cfg.Envoy.Port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	// Test concurrent requests
	numRequests := 20
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(requestID int) {
			req := &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"x-real-ip": fmt.Sprintf("10.0.1.%d", requestID+1),
							},
						},
					},
				},
			}

			response, err := client.Check(context.Background(), req)
			if err != nil {
				results <- fmt.Errorf("request %d failed: %v", requestID, err)
				return
			}

			if response.Status.Code != int32(codes.OK) {
				results <- fmt.Errorf("request %d got unexpected status: %d", requestID, response.Status.Code)
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

func TestServerStatusCodes(t *testing.T) {
	cfg := getTestConfig()
	logger := getTestLogger()
	banManager := ipban.NewManager(cfg, logger)
	server := NewServer(cfg, logger, banManager)

	// Test that status codes match gRPC standards
	allowResp := server.allowResponse()
	if allowResp.Status.Code != int32(codes.OK) {
		t.Errorf("Allow response should use codes.OK (%d), got %d", codes.OK, allowResp.Status.Code)
	}

	denyResp := server.denyResponse("test")
	if denyResp.Status.Code != int32(codes.PermissionDenied) {
		t.Errorf("Deny response should use codes.PermissionDenied (%d), got %d", codes.PermissionDenied, denyResp.Status.Code)
	}

	// Verify these are valid gRPC status codes
	if status.Code(status.New(codes.Code(allowResp.Status.Code), "").Err()) != codes.OK {
		t.Error("Allow response code is not a valid gRPC OK code")
	}

	if status.Code(status.New(codes.Code(denyResp.Status.Code), "").Err()) != codes.PermissionDenied {
		t.Error("Deny response code is not a valid gRPC PermissionDenied code")
	}
}
