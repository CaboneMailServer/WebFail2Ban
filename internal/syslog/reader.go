package syslog

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/ipban"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Reader struct {
	cfg        *config.Config
	logger     *zap.Logger
	banManager *ipban.Manager
	patterns   []*compiledPattern
}

type compiledPattern struct {
	name        string
	regex       *regexp.Regexp
	ipGroup     int
	severity    int
	description string
}

func NewReader(cfg *config.Config, logger *zap.Logger, banManager *ipban.Manager) *Reader {
	reader := &Reader{
		cfg:        cfg,
		logger:     logger,
		banManager: banManager,
		patterns:   make([]*compiledPattern, 0, len(cfg.Syslog.Patterns)),
	}

	// Compile patterns
	for _, pattern := range cfg.Syslog.Patterns {
		regex, err := regexp.Compile(pattern.Regex)
		if err != nil {
			logger.Error("Failed to compile regex pattern",
				zap.String("name", pattern.Name),
				zap.String("regex", pattern.Regex),
				zap.Error(err))
			continue
		}

		reader.patterns = append(reader.patterns, &compiledPattern{
			name:        pattern.Name,
			regex:       regex,
			ipGroup:     pattern.IPGroup,
			severity:    pattern.Severity,
			description: pattern.Description,
		})
	}

	return reader
}

func (r *Reader) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr(r.cfg.Syslog.Protocol, r.cfg.Syslog.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve syslog address: %w", err)
	}

	conn, err := net.ListenUDP(r.cfg.Syslog.Protocol, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on syslog address: %w", err)
	}
	defer conn.Close()

	r.logger.Info("Syslog reader started", zap.String("address", r.cfg.Syslog.Address))

	buffer := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, _, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				r.logger.Error("Failed to read from syslog", zap.Error(err))
				continue
			}

			message := string(buffer[:n])
			r.processMessage(message)
		}
	}
}

func (r *Reader) processMessage(message string) {
	for _, pattern := range r.patterns {
		matches := pattern.regex.FindStringSubmatch(message)
		if len(matches) > pattern.ipGroup {
			ip := strings.TrimSpace(matches[pattern.ipGroup])
			if r.isValidIP(ip) {
				r.logger.Debug("Suspicious activity detected",
					zap.String("pattern", pattern.name),
					zap.String("ip", ip),
					zap.Int("severity", pattern.severity),
					zap.String("message", message))

				r.banManager.RecordViolation(ip, pattern.severity, pattern.description)
			}
		}
	}
}

func (r *Reader) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
