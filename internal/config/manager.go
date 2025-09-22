package config

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"fail2ban-haproxy/internal/database"
)

// ConfigManager handles dynamic configuration loading from database with file fallback
type ConfigManager struct {
	config       *Config
	db           *database.DB
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	patterns     []PatternConfig
	banConfig    *BanConfig
	updateChan   chan struct{}
	reloadTicker *time.Ticker
	// Keep track of database status and last successful load
	dbConnected     bool
	lastDbLoad      time.Time
	failureCount    int
	lastDbPatterns  []PatternConfig
	lastDbBanConfig *BanConfig
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(cfg *Config) (*ConfigManager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	cm := &ConfigManager{
		config:     cfg,
		ctx:        ctx,
		cancel:     cancel,
		updateChan: make(chan struct{}, 1),
	}

	// Initialize with file configuration
	cm.patterns = cfg.Syslog.Patterns
	cm.banConfig = &cfg.Ban

	// Initialize database if enabled
	if cfg.Database.Enabled {
		dbConfig := database.DatabaseConfig{
			Enabled:         cfg.Database.Enabled,
			Driver:          cfg.Database.Driver,
			DSN:             cfg.Database.DSN,
			RefreshInterval: cfg.Database.RefreshInterval,
			MaxRetries:      cfg.Database.MaxRetries,
			RetryDelay:      cfg.Database.RetryDelay,
		}

		db, err := database.NewDB(dbConfig)
		if err != nil {
			log.Printf("Warning: failed to initialize database, using file fallback: %v", err)
		} else {
			cm.db = db
			// Insert default data if tables are empty
			if err := db.InsertDefaultData(); err != nil {
				log.Printf("Warning: failed to insert default data: %v", err)
			}
			// Load initial data from database
			if err := cm.loadFromDatabase(); err != nil {
				log.Printf("Warning: failed to load from database, using file fallback: %v", err)
			}
		}
	}

	// Start reload mechanism if database is enabled
	if cm.db != nil && cfg.Database.RefreshInterval > 0 {
		cm.startReloadRoutine()
	}

	return cm, nil
}

// GetPatterns returns the current patterns configuration
func (cm *ConfigManager) GetPatterns() []PatternConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return a copy to prevent race conditions
	patterns := make([]PatternConfig, len(cm.patterns))
	copy(patterns, cm.patterns)
	return patterns
}

// GetBanConfig returns the current ban configuration
func (cm *ConfigManager) GetBanConfig() BanConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return *cm.banConfig
}

// GetConfig returns the base configuration
func (cm *ConfigManager) GetConfig() *Config {
	return cm.config
}

// UpdateChan returns a channel that signals when configuration is updated
func (cm *ConfigManager) UpdateChan() <-chan struct{} {
	return cm.updateChan
}

// loadFromDatabase loads configuration from database with fallback to previous config on failure
func (cm *ConfigManager) loadFromDatabase() error {
	if cm.db == nil {
		cm.mu.Lock()
		cm.dbConnected = false
		cm.failureCount++
		cm.mu.Unlock()
		return fmt.Errorf("database not initialized")
	}

	// Test database connection first
	if err := cm.db.Ping(); err != nil {
		cm.mu.Lock()
		cm.dbConnected = false
		cm.failureCount++
		cm.mu.Unlock()
		log.Printf("Database connection failed (failure #%d), keeping previous configuration: %v", cm.failureCount, err)

		// If we have previously loaded database configuration, keep using it
		if cm.lastDbPatterns != nil || cm.lastDbBanConfig != nil {
			log.Printf("Using last known good database configuration from %v", cm.lastDbLoad)
			return nil // Don't treat this as a fatal error
		}

		return fmt.Errorf("database connection failed and no previous config available: %w", err)
	}

	// Load patterns
	dbPatterns, err := cm.db.GetPatterns()
	if err != nil {
		cm.mu.Lock()
		cm.dbConnected = false
		cm.failureCount++
		cm.mu.Unlock()
		log.Printf("Failed to load patterns from database (failure #%d), keeping previous configuration: %v", cm.failureCount, err)

		// Keep using previous database config if available
		if cm.lastDbPatterns != nil || cm.lastDbBanConfig != nil {
			return nil
		}

		return fmt.Errorf("failed to load patterns and no previous config available: %w", err)
	}

	// Load ban config (may be nil if not found)
	dbBanConfig, err := cm.db.GetBanConfig()
	if err != nil {
		cm.mu.Lock()
		cm.dbConnected = false
		cm.failureCount++
		cm.mu.Unlock()
		log.Printf("Failed to load ban config from database (failure #%d), keeping previous configuration: %v", cm.failureCount, err)

		// Keep using previous database config if available
		if cm.lastDbPatterns != nil || cm.lastDbBanConfig != nil {
			return nil
		}

		return fmt.Errorf("failed to load ban config and no previous config available: %w", err)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Mark database as connected and reset failure count
	wasDisconnected := !cm.dbConnected
	cm.dbConnected = true
	cm.failureCount = 0
	cm.lastDbLoad = time.Now()

	if wasDisconnected {
		log.Printf("Database connection restored after %d failures", cm.failureCount)
	}

	// Convert patterns
	var patterns []PatternConfig
	if len(dbPatterns) > 0 {
		patterns = make([]PatternConfig, len(dbPatterns))
		for i, dbPattern := range dbPatterns {
			patterns[i] = PatternConfig{
				Name:        dbPattern.Name,
				Regex:       dbPattern.Regex,
				IPGroup:     dbPattern.IPGroup,
				Severity:    dbPattern.Severity,
				Description: dbPattern.Description,
			}
		}

		// Update current patterns and save as last known good
		cm.patterns = patterns
		cm.lastDbPatterns = make([]PatternConfig, len(patterns))
		copy(cm.lastDbPatterns, patterns)
		log.Printf("Loaded and cached %d patterns from database", len(patterns))
	}

	// Convert ban config
	if dbBanConfig != nil {
		banConfig := &BanConfig{
			InitialBanTime:   dbBanConfig.InitialBanTime,
			MaxBanTime:       dbBanConfig.MaxBanTime,
			EscalationFactor: dbBanConfig.EscalationFactor,
			MaxAttempts:      dbBanConfig.MaxAttempts,
			TimeWindow:       dbBanConfig.TimeWindow,
			CleanupInterval:  dbBanConfig.CleanupInterval,
			MaxMemoryTTL:     dbBanConfig.MaxMemoryTTL,
		}

		// Update current ban config and save as last known good
		cm.banConfig = banConfig
		cm.lastDbBanConfig = &BanConfig{
			InitialBanTime:   banConfig.InitialBanTime,
			MaxBanTime:       banConfig.MaxBanTime,
			EscalationFactor: banConfig.EscalationFactor,
			MaxAttempts:      banConfig.MaxAttempts,
			TimeWindow:       banConfig.TimeWindow,
			CleanupInterval:  banConfig.CleanupInterval,
			MaxMemoryTTL:     banConfig.MaxMemoryTTL,
		}
		log.Printf("Loaded and cached ban configuration from database")
	}

	// Signal configuration update only if we actually loaded new data
	if len(patterns) > 0 || dbBanConfig != nil {
		select {
		case cm.updateChan <- struct{}{}:
		default:
			// Channel is full, skip
		}
	}

	return nil
}

// startReloadRoutine starts the configuration reload routine
func (cm *ConfigManager) startReloadRoutine() {
	cm.reloadTicker = time.NewTicker(cm.config.Database.RefreshInterval)

	go func() {
		defer cm.reloadTicker.Stop()

		for {
			select {
			case <-cm.ctx.Done():
				return
			case <-cm.reloadTicker.C:
				if err := cm.reloadConfiguration(); err != nil {
					log.Printf("Warning: failed to reload configuration: %v", err)
				}
			}
		}
	}()

	log.Printf("Started configuration reload routine with interval: %v", cm.config.Database.RefreshInterval)
}

// reloadConfiguration reloads configuration from database with retry logic
func (cm *ConfigManager) reloadConfiguration() error {
	if cm.db == nil {
		return fmt.Errorf("database not initialized")
	}

	var lastErr error
	maxRetries := cm.config.Database.MaxRetries
	retryDelay := cm.config.Database.RetryDelay

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("Retrying configuration reload (attempt %d/%d)", attempt, maxRetries)
			time.Sleep(retryDelay)
		}

		if err := cm.loadFromDatabase(); err != nil {
			lastErr = err
			continue
		}

		// Success
		return nil
	}

	return fmt.Errorf("failed to reload configuration after %d attempts: %w", maxRetries+1, lastErr)
}

// ForceReload forces an immediate configuration reload
func (cm *ConfigManager) ForceReload() error {
	return cm.reloadConfiguration()
}

// Stop stops the configuration manager and cleans up resources
func (cm *ConfigManager) Stop() error {
	cm.cancel()

	if cm.reloadTicker != nil {
		cm.reloadTicker.Stop()
	}

	if cm.db != nil {
		return cm.db.Close()
	}

	return nil
}

// GetDatabaseStatus returns the database connection status
func (cm *ConfigManager) GetDatabaseStatus() DatabaseStatus {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	status := DatabaseStatus{
		Enabled:            cm.config.Database.Enabled,
		Connected:          cm.dbConnected,
		Driver:             cm.config.Database.Driver,
		FailureCount:       cm.failureCount,
		LastSuccessfulLoad: cm.lastDbLoad,
		HasCachedConfig:    cm.lastDbPatterns != nil || cm.lastDbBanConfig != nil,
	}

	if cm.db != nil {
		// Test connection in real-time
		if err := cm.db.Ping(); err != nil {
			status.Connected = false
			status.LastError = err.Error()
		}
	}

	return status
}

// DatabaseStatus represents the current database connection status
type DatabaseStatus struct {
	Enabled            bool      `json:"enabled"`
	Connected          bool      `json:"connected"`
	Driver             string    `json:"driver"`
	FailureCount       int       `json:"failure_count"`
	LastSuccessfulLoad time.Time `json:"last_successful_load"`
	HasCachedConfig    bool      `json:"has_cached_config"`
	LastError          string    `json:"last_error,omitempty"`
}

// GetConfigurationSource returns information about where the current configuration comes from
func (cm *ConfigManager) GetConfigurationSource() ConfigurationSource {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	source := ConfigurationSource{
		PatternsSource:    "file",
		BanConfigSource:   "file",
		DatabaseEnabled:   cm.config.Database.Enabled,
		DatabaseConnected: cm.dbConnected,
	}

	// Determine if we're using database config
	if cm.config.Database.Enabled && cm.dbConnected {
		if cm.lastDbPatterns != nil {
			source.PatternsSource = "database"
		}
		if cm.lastDbBanConfig != nil {
			source.BanConfigSource = "database"
		}
	} else if cm.config.Database.Enabled && !cm.dbConnected && cm.lastDbPatterns != nil {
		source.PatternsSource = "database_cached"
		if cm.lastDbBanConfig != nil {
			source.BanConfigSource = "database_cached"
		}
	}

	return source
}

// ConfigurationSource represents where configuration comes from
type ConfigurationSource struct {
	PatternsSource    string `json:"patterns_source"`   // "file", "database", or "database_cached"
	BanConfigSource   string `json:"ban_config_source"` // "file", "database", or "database_cached"
	DatabaseEnabled   bool   `json:"database_enabled"`
	DatabaseConnected bool   `json:"database_connected"`
}

// ValidateConfiguration validates the current configuration
func (cm *ConfigManager) ValidateConfiguration() error {
	patterns := cm.GetPatterns()
	if len(patterns) == 0 {
		return fmt.Errorf("no patterns configured")
	}

	// Validate each pattern
	for i, pattern := range patterns {
		if pattern.Name == "" {
			return fmt.Errorf("pattern %d has empty name", i)
		}
		if pattern.Regex == "" {
			return fmt.Errorf("pattern %s has empty regex", pattern.Name)
		}
		if pattern.IPGroup < 1 {
			return fmt.Errorf("pattern %s has invalid IP group: %d", pattern.Name, pattern.IPGroup)
		}
	}

	banConfig := cm.GetBanConfig()
	if banConfig.InitialBanTime <= 0 {
		return fmt.Errorf("initial ban time must be positive")
	}
	if banConfig.MaxBanTime <= 0 {
		return fmt.Errorf("max ban time must be positive")
	}
	if banConfig.EscalationFactor <= 1.0 {
		return fmt.Errorf("escalation factor must be greater than 1.0")
	}
	if banConfig.MaxAttempts <= 0 {
		return fmt.Errorf("max attempts must be positive")
	}
	if banConfig.TimeWindow <= 0 {
		return fmt.Errorf("time window must be positive")
	}

	return nil
}
