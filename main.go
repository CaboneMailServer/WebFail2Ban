package main

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/envoy"
	"fail2ban-haproxy/internal/ipban"
	"fail2ban-haproxy/internal/nginx"
	"fail2ban-haproxy/internal/spoa"
	"fail2ban-haproxy/internal/syslog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
	defer logger.Sync()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	logger.Info("Starting fail2ban-haproxy service")

	// Validate that at least one proxy protocol is enabled
	if !cfg.SPOA.Enabled && !cfg.Envoy.Enabled && !cfg.Nginx.Enabled {
		logger.Fatal("At least one proxy protocol must be enabled (SPOA, Envoy, or Nginx)")
	}

	// Log which protocols are enabled
	enabledProtocols := []string{}
	if cfg.SPOA.Enabled {
		enabledProtocols = append(enabledProtocols, "SPOA")
	}
	if cfg.Envoy.Enabled {
		enabledProtocols = append(enabledProtocols, "Envoy")
	}
	if cfg.Nginx.Enabled {
		enabledProtocols = append(enabledProtocols, "Nginx")
	}
	logger.Info("Enabled proxy protocols", zap.Strings("protocols", enabledProtocols))

	// Initialize IP ban manager
	banManager := ipban.NewManager(cfg, logger)

	// Initialize syslog reader
	syslogReader := syslog.NewReader(cfg, logger, banManager)

	// Initialize SPOA server
	var spoaServer *spoa.Server
	if cfg.SPOA.Enabled {
		spoaServer = spoa.NewServer(cfg, logger, banManager)
	}

	// Initialize Envoy ext_authz server
	var envoyServer *envoy.Server
	if cfg.Envoy.Enabled {
		envoyServer = envoy.NewServer(cfg, logger, banManager)
	}

	// Initialize Nginx auth_request server
	var nginxServer *nginx.Server
	if cfg.Nginx.Enabled {
		nginxServer = nginx.NewServer(cfg, logger, banManager)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Wait group for goroutines
	var wg sync.WaitGroup

	// Start syslog reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := syslogReader.Start(ctx); err != nil {
			logger.Error("Syslog reader failed", zap.Error(err))
		}
	}()

	// Start SPOA server if enabled
	if cfg.SPOA.Enabled && spoaServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := spoaServer.Start(ctx); err != nil {
				logger.Error("SPOA server failed", zap.Error(err))
			}
		}()
	}

	// Start Envoy ext_authz server if enabled
	if cfg.Envoy.Enabled && envoyServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := envoyServer.Start(ctx); err != nil {
				logger.Error("Envoy ext_authz server failed", zap.Error(err))
			}
		}()
	}

	// Start Nginx auth_request server if enabled
	if cfg.Nginx.Enabled && nginxServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := nginxServer.Start(ctx); err != nil {
				logger.Error("Nginx auth_request server failed", zap.Error(err))
			}
		}()
	}

	// Start cleanup routine
	wg.Add(1)
	go func() {
		defer wg.Done()
		banManager.StartCleanup(ctx)
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	logger.Info("Shutdown signal received, stopping services...")
	cancel()

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("All services stopped gracefully")
	case <-time.After(30 * time.Second):
		logger.Warn("Timeout waiting for services to stop")
	}
}
