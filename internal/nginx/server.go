package nginx

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/ipban"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Server struct {
	cfg        *config.Config
	logger     *zap.Logger
	banManager *ipban.Manager
	server     *http.Server
}

func NewServer(cfg *config.Config, logger *zap.Logger, banManager *ipban.Manager) *Server {
	return &Server{
		cfg:        cfg,
		logger:     logger,
		banManager: banManager,
	}
}

func (s *Server) Start(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", s.cfg.Nginx.Address, s.cfg.Nginx.Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", s.handleAuthRequest)
	mux.HandleFunc("/health", s.handleHealthCheck)

	s.server = &http.Server{
		Addr:         address,
		Handler:      mux,
		ReadTimeout:  s.cfg.Nginx.ReadTimeout,
		WriteTimeout: s.cfg.Nginx.WriteTimeout,
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info("Nginx auth_request server started", zap.String("address", address))

	go func() {
		<-ctx.Done()
		s.logger.Info("Stopping nginx auth_request server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("Error during nginx server shutdown", zap.Error(err))
		}
	}()

	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start nginx auth server: %w", err)
	}

	return nil
}

func (s *Server) handleAuthRequest(w http.ResponseWriter, r *http.Request) {
	// Extract client IP from the request
	clientIP := s.extractClientIP(r)
	if clientIP == "" {
		s.logger.Warn("Could not extract client IP from nginx auth request",
			zap.String("method", r.Method),
			zap.String("uri", r.RequestURI),
			zap.String("remote_addr", r.RemoteAddr))

		// Allow request if we can't determine IP
		s.allowResponse(w, "unknown-ip")
		return
	}

	// Check if IP is banned
	if s.banManager.IsBanned(clientIP) {
		s.logger.Debug("Blocking banned IP via nginx auth_request",
			zap.String("ip", clientIP),
			zap.String("method", r.Method),
			zap.String("uri", r.RequestURI))

		s.denyResponse(w, clientIP, "IP banned due to suspicious activity")
		return
	}

	s.logger.Debug("Allowing IP via nginx auth_request",
		zap.String("ip", clientIP),
		zap.String("method", r.Method),
		zap.String("uri", r.RequestURI))

	s.allowResponse(w, clientIP)
}

func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"fail2ban-nginx-auth"}`))
}

func (s *Server) extractClientIP(r *http.Request) string {
	// Priority order for IP extraction:
	// 1. X-Original-IP (nginx specific header for auth_request)
	// 2. X-Forwarded-For (standard proxy header)
	// 3. X-Real-IP (nginx/proxy header)
	// 4. X-Client-IP (some proxies)
	// 5. CF-Connecting-IP (Cloudflare)
	// 6. RemoteAddr (direct connection)

	// Check X-Original-IP first (nginx auth_request specific)
	if ip := r.Header.Get("X-Original-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}

	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP from X-Forwarded-For
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Check X-Client-IP
	if clientIP := r.Header.Get("X-Client-IP"); clientIP != "" {
		return strings.TrimSpace(clientIP)
	}

	// Check CF-Connecting-IP (Cloudflare)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}

	// Fall back to RemoteAddr
	if r.RemoteAddr != "" {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// Might not have port
			return strings.TrimSpace(r.RemoteAddr)
		}
		return strings.TrimSpace(ip)
	}

	return ""
}

func (s *Server) allowResponse(w http.ResponseWriter, clientIP string) {
	// Set headers that nginx can use
	w.Header().Set("X-Fail2ban-Status", "allowed")
	w.Header().Set("X-Fail2ban-IP", clientIP)
	w.Header().Set("X-Fail2ban-Service", "fail2ban-nginx-auth")

	// Return 200 OK for allowed requests
	w.WriteHeader(http.StatusOK)
}

func (s *Server) denyResponse(w http.ResponseWriter, clientIP, reason string) {
	// Set headers that nginx can use
	w.Header().Set("X-Fail2ban-Status", "denied")
	w.Header().Set("X-Fail2ban-IP", clientIP)
	w.Header().Set("X-Fail2ban-Reason", reason)
	w.Header().Set("X-Fail2ban-Service", "fail2ban-nginx-auth")

	// Return 403 Forbidden for banned requests
	w.WriteHeader(http.StatusForbidden)

	// Optional: Return JSON error response
	if s.cfg.Nginx.ReturnJSON {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"access_denied","reason":"%s","ip":"%s"}`, reason, clientIP)
	}
}