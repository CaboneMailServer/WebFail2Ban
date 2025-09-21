package main

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/ipban"
	"fail2ban-haproxy/internal/syslog"
	"fail2ban-haproxy/tests-ressources/spoa"
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

	// Initialize IP ban manager
	banManager := ipban.NewManager(cfg, logger)

	// Initialize syslog reader
	syslogReader := syslog.NewReader(cfg, logger, banManager)

	// Initialize SPOA server
	spoaServer := spoa.NewServer(cfg, logger, banManager)

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

	// Start SPOA server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := spoaServer.Start(ctx); err != nil {
			logger.Error("SPOA server failed", zap.Error(err))
		}
	}()

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
