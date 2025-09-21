package envoy

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/ipban"
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
)

type Server struct {
	auth.UnimplementedAuthorizationServer
	cfg        *config.Config
	logger     *zap.Logger
	banManager *ipban.Manager
	grpcServer *grpc.Server
}

func NewServer(cfg *config.Config, logger *zap.Logger, banManager *ipban.Manager) *Server {
	return &Server{
		cfg:        cfg,
		logger:     logger,
		banManager: banManager,
	}
}

func (s *Server) Start(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", s.cfg.Envoy.Address, s.cfg.Envoy.Port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}

	s.grpcServer = grpc.NewServer()
	auth.RegisterAuthorizationServer(s.grpcServer, s)

	s.logger.Info("Envoy ext_authz server started", zap.String("address", address))

	go func() {
		<-ctx.Done()
		s.logger.Info("Stopping Envoy ext_authz server...")
		s.grpcServer.GracefulStop()
	}()

	if err := s.grpcServer.Serve(listener); err != nil {
		return fmt.Errorf("failed to serve gRPC server: %w", err)
	}

	return nil
}

// Check implements the Authorization service Check method
func (s *Server) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	// Extract client IP from the request
	clientIP := s.extractClientIP(req)
	if clientIP == "" {
		s.logger.Warn("Could not extract client IP from request")
		return s.allowResponse(), nil
	}

	// Check if IP is banned
	if s.banManager.IsBanned(clientIP) {
		s.logger.Debug("Blocking banned IP via Envoy ext_authz",
			zap.String("ip", clientIP))
		return s.denyResponse("IP is banned due to suspicious activity"), nil
	}

	s.logger.Debug("Allowing IP via Envoy ext_authz",
		zap.String("ip", clientIP))
	return s.allowResponse(), nil
}

func (s *Server) extractClientIP(req *auth.CheckRequest) string {
	// Try to get IP from various sources in order of preference

	// 1. Check X-Forwarded-For header
	if req.Attributes != nil && req.Attributes.Request != nil && req.Attributes.Request.Http != nil {
		headers := req.Attributes.Request.Http.Headers
		if xff, exists := headers["x-forwarded-for"]; exists {
			// Take the first IP from X-Forwarded-For
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}

		// 2. Check X-Real-IP header
		if realIP, exists := headers["x-real-ip"]; exists {
			return strings.TrimSpace(realIP)
		}
	}

	// 3. Check source address from connection
	if req.Attributes != nil && req.Attributes.Source != nil && req.Attributes.Source.Address != nil {
		if socketAddr := req.Attributes.Source.Address.GetSocketAddress(); socketAddr != nil {
			return socketAddr.GetAddress()
		}
	}

	// 4. Check destination address as fallback
	if req.Attributes != nil && req.Attributes.Destination != nil && req.Attributes.Destination.Address != nil {
		if socketAddr := req.Attributes.Destination.Address.GetSocketAddress(); socketAddr != nil {
			return socketAddr.GetAddress()
		}
	}

	return ""
}

func (s *Server) allowResponse() *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &rpc_status.Status{
			Code: int32(codes.OK),
		},
	}
}

func (s *Server) denyResponse(reason string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &rpc_status.Status{
			Code:    int32(codes.PermissionDenied),
			Message: reason,
		},
	}
}
