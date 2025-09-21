package spoa

import (
	"bufio"
	"context"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/ipban"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type Server struct {
	cfg        *config.Config
	logger     *zap.Logger
	banManager *ipban.Manager
	listener   net.Listener
	clients    sync.WaitGroup
}

func NewServer(cfg *config.Config, logger *zap.Logger, banManager *ipban.Manager) *Server {
	return &Server{
		cfg:        cfg,
		logger:     logger,
		banManager: banManager,
	}
}

func (s *Server) Start(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", s.cfg.SPOA.Address, s.cfg.SPOA.Port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	s.listener = listener

	s.logger.Info("SPOA server started", zap.String("address", address))

	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Error("Failed to accept connection", zap.Error(err))
				continue
			}
		}

		s.clients.Add(1)
		go s.handleClient(ctx, conn)
	}
}

func (s *Server) handleClient(ctx context.Context, conn net.Conn) {
	defer s.clients.Done()
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(s.cfg.SPOA.ReadTimeout))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			response := s.processMessage(line)
			if response != "" {
				conn.Write([]byte(response + "\n"))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		s.logger.Error("Error reading from client", zap.Error(err))
	}
}

func (s *Server) processMessage(message string) string {
	parts := strings.Fields(message)
	if len(parts) < 2 {
		return ""
	}

	switch parts[0] {
	case "haproxy_processing":
		return s.handleHAProxyProcessing(parts[1:])
	case "notify":
		return s.handleNotify(parts[1:])
	default:
		return ""
	}
}

func (s *Server) handleHAProxyProcessing(parts []string) string {
	for _, part := range parts {
		if strings.HasPrefix(part, "src=") {
			ip := strings.TrimPrefix(part, "src=")
			if s.banManager.IsBanned(ip) {
				s.logger.Debug("Blocking banned IP", zap.String("ip", ip))
				return "banned=1"
			}
			return "banned=0"
		}
	}
	return "banned=0"
}

func (s *Server) handleNotify(parts []string) string {
	// Handle notify messages from HAProxy if needed
	return ""
}
