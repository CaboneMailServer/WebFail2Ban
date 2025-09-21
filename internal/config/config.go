package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Syslog SyslogConfig `mapstructure:"syslog"`
	SPOA   SPOAConfig   `mapstructure:"spoa"`
	Ban    BanConfig    `mapstructure:"ban"`
}

type SyslogConfig struct {
	Address  string          `mapstructure:"address"`
	Protocol string          `mapstructure:"protocol"`
	Patterns []PatternConfig `mapstructure:"patterns"`
}

type PatternConfig struct {
	Name        string `mapstructure:"name"`
	Regex       string `mapstructure:"regex"`
	IPGroup     int    `mapstructure:"ip_group"`
	Severity    int    `mapstructure:"severity"`
	Description string `mapstructure:"description"`
}

type SPOAConfig struct {
	Address     string        `mapstructure:"address"`
	Port        int           `mapstructure:"port"`
	MaxClients  int           `mapstructure:"max_clients"`
	ReadTimeout time.Duration `mapstructure:"read_timeout"`
}

type BanConfig struct {
	InitialBanTime   time.Duration `mapstructure:"initial_ban_time"`
	MaxBanTime       time.Duration `mapstructure:"max_ban_time"`
	EscalationFactor float64       `mapstructure:"escalation_factor"`
	MaxAttempts      int           `mapstructure:"max_attempts"`
	TimeWindow       time.Duration `mapstructure:"time_window"`
	CleanupInterval  time.Duration `mapstructure:"cleanup_interval"`
	MaxMemoryTTL     time.Duration `mapstructure:"max_memory_ttl"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/fail2ban-haproxy/")

	// Set defaults
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

func setDefaults() {
	viper.SetDefault("syslog.address", "127.0.0.1:514")
	viper.SetDefault("syslog.protocol", "udp")

	viper.SetDefault("spoa.address", "0.0.0.0")
	viper.SetDefault("spoa.port", 12345)
	viper.SetDefault("spoa.max_clients", 100)
	viper.SetDefault("spoa.read_timeout", "30s")

	viper.SetDefault("ban.initial_ban_time", "5m")
	viper.SetDefault("ban.max_ban_time", "24h")
	viper.SetDefault("ban.escalation_factor", 2.0)
	viper.SetDefault("ban.max_attempts", 5)
	viper.SetDefault("ban.time_window", "10m")
	viper.SetDefault("ban.cleanup_interval", "1m")
	viper.SetDefault("ban.max_memory_ttl", "72h")
}
