package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

const (
	createPatternsTable = `
		CREATE TABLE IF NOT EXISTS patterns (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name VARCHAR(255) NOT NULL UNIQUE,
			regex TEXT NOT NULL,
			ip_group INTEGER NOT NULL DEFAULT 1,
			severity INTEGER NOT NULL DEFAULT 1,
			description TEXT,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`

	createBanConfigTable = `
		CREATE TABLE IF NOT EXISTS ban_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name VARCHAR(255) NOT NULL UNIQUE,
			initial_ban_time_seconds INTEGER NOT NULL,
			max_ban_time_seconds INTEGER NOT NULL,
			escalation_factor REAL NOT NULL,
			max_attempts INTEGER NOT NULL,
			time_window_seconds INTEGER NOT NULL,
			cleanup_interval_seconds INTEGER NOT NULL,
			max_memory_ttl_seconds INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`

	createBlacklistTable = `
		CREATE TABLE IF NOT EXISTS blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address VARCHAR(45) NOT NULL UNIQUE,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by VARCHAR(255) DEFAULT 'system',
			enabled BOOLEAN NOT NULL DEFAULT TRUE
		);`

	createWhitelistTable = `
		CREATE TABLE IF NOT EXISTS whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address VARCHAR(45) NOT NULL UNIQUE,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by VARCHAR(255) DEFAULT 'system',
			enabled BOOLEAN NOT NULL DEFAULT TRUE
		);`

	createIndexes = `
		CREATE INDEX IF NOT EXISTS idx_patterns_enabled ON patterns(enabled);
		CREATE INDEX IF NOT EXISTS idx_ban_config_enabled ON ban_config(enabled);
		CREATE INDEX IF NOT EXISTS idx_patterns_name ON patterns(name);
		CREATE INDEX IF NOT EXISTS idx_ban_config_name ON ban_config(name);
		CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip_address);
		CREATE INDEX IF NOT EXISTS idx_blacklist_enabled ON blacklist(enabled);
		CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip_address);
		CREATE INDEX IF NOT EXISTS idx_whitelist_enabled ON whitelist(enabled);`
)

// MySQL specific schema adjustments
const (
	createPatternsTableMySQL = `
		CREATE TABLE IF NOT EXISTS patterns (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			regex TEXT NOT NULL,
			ip_group INT NOT NULL DEFAULT 1,
			severity INT NOT NULL DEFAULT 1,
			description TEXT,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		);`

	createBanConfigTableMySQL = `
		CREATE TABLE IF NOT EXISTS ban_config (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			initial_ban_time_seconds INT NOT NULL,
			max_ban_time_seconds INT NOT NULL,
			escalation_factor DECIMAL(10,6) NOT NULL,
			max_attempts INT NOT NULL,
			time_window_seconds INT NOT NULL,
			cleanup_interval_seconds INT NOT NULL,
			max_memory_ttl_seconds INT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		);`

	createBlacklistTableMySQL = `
		CREATE TABLE IF NOT EXISTS blacklist (
			id INT AUTO_INCREMENT PRIMARY KEY,
			ip_address VARCHAR(45) NOT NULL UNIQUE,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by VARCHAR(255) DEFAULT 'system',
			enabled BOOLEAN NOT NULL DEFAULT TRUE
		);`

	createWhitelistTableMySQL = `
		CREATE TABLE IF NOT EXISTS whitelist (
			id INT AUTO_INCREMENT PRIMARY KEY,
			ip_address VARCHAR(45) NOT NULL UNIQUE,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by VARCHAR(255) DEFAULT 'system',
			enabled BOOLEAN NOT NULL DEFAULT TRUE
		);`
)

// PostgreSQL specific schema adjustments
const (
	createPatternsTablePostgres = `
		CREATE TABLE IF NOT EXISTS patterns (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			regex TEXT NOT NULL,
			ip_group INTEGER NOT NULL DEFAULT 1,
			severity INTEGER NOT NULL DEFAULT 1,
			description TEXT,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`

	createBanConfigTablePostgres = `
		CREATE TABLE IF NOT EXISTS ban_config (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			initial_ban_time_seconds INTEGER NOT NULL,
			max_ban_time_seconds INTEGER NOT NULL,
			escalation_factor DECIMAL(10,6) NOT NULL,
			max_attempts INTEGER NOT NULL,
			time_window_seconds INTEGER NOT NULL,
			cleanup_interval_seconds INTEGER NOT NULL,
			max_memory_ttl_seconds INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`

	createBlacklistTablePostgres = `
		CREATE TABLE IF NOT EXISTS blacklist (
			id SERIAL PRIMARY KEY,
			ip_address VARCHAR(45) NOT NULL UNIQUE,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by VARCHAR(255) DEFAULT 'system',
			enabled BOOLEAN NOT NULL DEFAULT TRUE
		);`

	createWhitelistTablePostgres = `
		CREATE TABLE IF NOT EXISTS whitelist (
			id SERIAL PRIMARY KEY,
			ip_address VARCHAR(45) NOT NULL UNIQUE,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by VARCHAR(255) DEFAULT 'system',
			enabled BOOLEAN NOT NULL DEFAULT TRUE
		);`
)

// Pattern represents a pattern configuration from database
type Pattern struct {
	Name        string
	Regex       string
	IPGroup     int
	Severity    int
	Description string
}

// BanConfig represents ban configuration from database
type BanConfig struct {
	InitialBanTime   time.Duration
	MaxBanTime       time.Duration
	EscalationFactor float64
	MaxAttempts      int
	TimeWindow       time.Duration
	CleanupInterval  time.Duration
	MaxMemoryTTL     time.Duration
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Enabled         bool
	Driver          string
	DSN             string
	RefreshInterval time.Duration
	MaxRetries      int
	RetryDelay      time.Duration
}

// BlacklistEntry represents a permanently banned IP
type BlacklistEntry struct {
	ID        int       `json:"id"`
	IPAddress string    `json:"ip_address"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Enabled   bool      `json:"enabled"`
}

// WhitelistEntry represents a permanently allowed IP
type WhitelistEntry struct {
	ID        int       `json:"id"`
	IPAddress string    `json:"ip_address"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Enabled   bool      `json:"enabled"`
}

type DB struct {
	conn   *sql.DB
	driver string
}

func NewDB(dbConfig DatabaseConfig) (*DB, error) {
	conn, err := sql.Open(dbConfig.Driver, dbConfig.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db := &DB{
		conn:   conn,
		driver: dbConfig.Driver,
	}

	if err := db.InitSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

func (db *DB) InitSchema() error {
	var patternsSQL, banConfigSQL, blacklistSQL, whitelistSQL string

	switch db.driver {
	case "mysql":
		patternsSQL = createPatternsTableMySQL
		banConfigSQL = createBanConfigTableMySQL
		blacklistSQL = createBlacklistTableMySQL
		whitelistSQL = createWhitelistTableMySQL
	case "postgres":
		patternsSQL = createPatternsTablePostgres
		banConfigSQL = createBanConfigTablePostgres
		blacklistSQL = createBlacklistTablePostgres
		whitelistSQL = createWhitelistTablePostgres
	default: // sqlite3
		patternsSQL = createPatternsTable
		banConfigSQL = createBanConfigTable
		blacklistSQL = createBlacklistTable
		whitelistSQL = createWhitelistTable
	}

	// Create tables
	if _, err := db.conn.Exec(patternsSQL); err != nil {
		return fmt.Errorf("failed to create patterns table: %w", err)
	}

	if _, err := db.conn.Exec(banConfigSQL); err != nil {
		return fmt.Errorf("failed to create ban_config table: %w", err)
	}

	if _, err := db.conn.Exec(blacklistSQL); err != nil {
		return fmt.Errorf("failed to create blacklist table: %w", err)
	}

	if _, err := db.conn.Exec(whitelistSQL); err != nil {
		return fmt.Errorf("failed to create whitelist table: %w", err)
	}

	// Create indexes
	if _, err := db.conn.Exec(createIndexes); err != nil {
		log.Printf("Warning: failed to create indexes: %v", err)
	}

	return nil
}

func (db *DB) GetPatterns() ([]Pattern, error) {
	rows, err := db.conn.Query(`
		SELECT name, regex, ip_group, severity, description
		FROM patterns
		WHERE enabled = TRUE
		ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("failed to query patterns: %w", err)
	}
	defer rows.Close()

	var patterns []Pattern
	for rows.Next() {
		var p Pattern
		var description sql.NullString

		err := rows.Scan(&p.Name, &p.Regex, &p.IPGroup, &p.Severity, &description)
		if err != nil {
			return nil, fmt.Errorf("failed to scan pattern: %w", err)
		}

		if description.Valid {
			p.Description = description.String
		}

		patterns = append(patterns, p)
	}

	return patterns, nil
}

func (db *DB) GetBanConfig() (*BanConfig, error) {
	row := db.conn.QueryRow(`
		SELECT initial_ban_time_seconds, max_ban_time_seconds, escalation_factor,
		       max_attempts, time_window_seconds, cleanup_interval_seconds, max_memory_ttl_seconds
		FROM ban_config
		WHERE enabled = TRUE
		ORDER BY created_at DESC
		LIMIT 1`)

	var banConfig BanConfig
	var initialBanSeconds, maxBanSeconds, timeWindowSeconds, cleanupIntervalSeconds, maxMemoryTTLSeconds int

	err := row.Scan(
		&initialBanSeconds,
		&maxBanSeconds,
		&banConfig.EscalationFactor,
		&banConfig.MaxAttempts,
		&timeWindowSeconds,
		&cleanupIntervalSeconds,
		&maxMemoryTTLSeconds,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No config found, will use file fallback
		}
		return nil, fmt.Errorf("failed to scan ban config: %w", err)
	}

	// Convert seconds to time.Duration
	banConfig.InitialBanTime = time.Duration(initialBanSeconds) * time.Second
	banConfig.MaxBanTime = time.Duration(maxBanSeconds) * time.Second
	banConfig.TimeWindow = time.Duration(timeWindowSeconds) * time.Second
	banConfig.CleanupInterval = time.Duration(cleanupIntervalSeconds) * time.Second
	banConfig.MaxMemoryTTL = time.Duration(maxMemoryTTLSeconds) * time.Second

	return &banConfig, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) Ping() error {
	return db.conn.Ping()
}

// Blacklist management
func (db *DB) AddToBlacklist(ipAddress, reason, createdBy string) error {
	_, err := db.conn.Exec(`
		INSERT INTO blacklist (ip_address, reason, created_by)
		VALUES (?, ?, ?)`,
		ipAddress, reason, createdBy)
	return err
}

func (db *DB) RemoveFromBlacklist(ipAddress string) error {
	_, err := db.conn.Exec(`
		UPDATE blacklist SET enabled = FALSE
		WHERE ip_address = ?`,
		ipAddress)
	return err
}

func (db *DB) IsBlacklisted(ipAddress string) (bool, error) {
	var count int
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM blacklist
		WHERE ip_address = ? AND enabled = TRUE`,
		ipAddress).Scan(&count)
	return count > 0, err
}

func (db *DB) GetBlacklist() ([]BlacklistEntry, error) {
	rows, err := db.conn.Query(`
		SELECT id, ip_address, reason, created_at, created_by, enabled
		FROM blacklist
		WHERE enabled = TRUE
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query blacklist: %w", err)
	}
	defer rows.Close()

	var entries []BlacklistEntry
	for rows.Next() {
		var entry BlacklistEntry
		var reason sql.NullString

		err := rows.Scan(&entry.ID, &entry.IPAddress, &reason, &entry.CreatedAt, &entry.CreatedBy, &entry.Enabled)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blacklist entry: %w", err)
		}

		if reason.Valid {
			entry.Reason = reason.String
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// Whitelist management
func (db *DB) AddToWhitelist(ipAddress, reason, createdBy string) error {
	_, err := db.conn.Exec(`
		INSERT INTO whitelist (ip_address, reason, created_by)
		VALUES (?, ?, ?)`,
		ipAddress, reason, createdBy)
	return err
}

func (db *DB) RemoveFromWhitelist(ipAddress string) error {
	_, err := db.conn.Exec(`
		UPDATE whitelist SET enabled = FALSE
		WHERE ip_address = ?`,
		ipAddress)
	return err
}

func (db *DB) IsWhitelisted(ipAddress string) (bool, error) {
	var count int
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM whitelist
		WHERE ip_address = ? AND enabled = TRUE`,
		ipAddress).Scan(&count)
	return count > 0, err
}

func (db *DB) GetWhitelist() ([]WhitelistEntry, error) {
	rows, err := db.conn.Query(`
		SELECT id, ip_address, reason, created_at, created_by, enabled
		FROM whitelist
		WHERE enabled = TRUE
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query whitelist: %w", err)
	}
	defer rows.Close()

	var entries []WhitelistEntry
	for rows.Next() {
		var entry WhitelistEntry
		var reason sql.NullString

		err := rows.Scan(&entry.ID, &entry.IPAddress, &reason, &entry.CreatedAt, &entry.CreatedBy, &entry.Enabled)
		if err != nil {
			return nil, fmt.Errorf("failed to scan whitelist entry: %w", err)
		}

		if reason.Valid {
			entry.Reason = reason.String
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// InsertDefaultData inserts some default patterns and ban config for testing
func (db *DB) InsertDefaultData() error {
	// Insert default patterns if none exist
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM patterns").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to count patterns: %w", err)
	}

	if count == 0 {
		defaultPatterns := []struct {
			name, regex, description string
			ipGroup, severity        int
		}{
			{
				"dovecot-auth-failure",
				`auth failed.*rip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`,
				"Dovecot authentication failures",
				1, 1,
			},
			{
				"postfix-auth-failure",
				`authentication failed.*client=.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]`,
				"Postfix authentication failures",
				1, 1,
			},
			{
				"sogo-auth-failure",
				`Login from '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' for user .* might not have worked`,
				"SOGo authentication failures",
				1, 1,
			},
		}

		for _, pattern := range defaultPatterns {
			_, err := db.conn.Exec(`
				INSERT INTO patterns (name, regex, ip_group, severity, description)
				VALUES (?, ?, ?, ?, ?)`,
				pattern.name, pattern.regex, pattern.ipGroup, pattern.severity, pattern.description)
			if err != nil {
				log.Printf("Warning: failed to insert default pattern %s: %v", pattern.name, err)
			}
		}
	}

	// Insert default ban config if none exists
	err = db.conn.QueryRow("SELECT COUNT(*) FROM ban_config").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to count ban config: %w", err)
	}

	if count == 0 {
		_, err := db.conn.Exec(`
			INSERT INTO ban_config (
				name, initial_ban_time_seconds, max_ban_time_seconds, escalation_factor,
				max_attempts, time_window_seconds, cleanup_interval_seconds, max_memory_ttl_seconds
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			"default",
			300,    // 5 minutes
			86400,  // 24 hours
			2.0,    // escalation factor
			5,      // max attempts
			600,    // 10 minutes
			60,     // 1 minute
			259200, // 72 hours
		)
		if err != nil {
			log.Printf("Warning: failed to insert default ban config: %v", err)
		}
	}

	return nil
}
