package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestLoad(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `
syslog:
  address: "192.168.1.1:514"
  protocol: "tcp"
  patterns:
    - name: "dovecot-auth-failure"
      regex: "auth failed.*rip=([0-9.]+)"
      ip_group: 1
      severity: 3
      description: "Dovecot authentication failure"

spoa:
  address: "127.0.0.1"
  port: 12346
  max_clients: 50
  read_timeout: "20s"
  enabled: false

envoy:
  address: "127.0.0.1"
  port: 9002
  enabled: true

nginx:
  address: "127.0.0.1"
  port: 8889
  enabled: true
  read_timeout: "5s"
  write_timeout: "5s"
  return_json: true

ban:
  initial_ban_time: "10m"
  max_ban_time: "48h"
  escalation_factor: 3.0
  max_attempts: 3
  time_window: "5m"
  cleanup_interval: "30s"
  max_memory_ttl: "48h"
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Set viper to use our test directory
	viper.Reset()
	viper.AddConfigPath(tmpDir)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Load config
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test syslog config
	if cfg.Syslog.Address != "192.168.1.1:514" {
		t.Errorf("Expected syslog address '192.168.1.1:514', got '%s'", cfg.Syslog.Address)
	}
	if cfg.Syslog.Protocol != "tcp" {
		t.Errorf("Expected syslog protocol 'tcp', got '%s'", cfg.Syslog.Protocol)
	}
	if len(cfg.Syslog.Patterns) != 1 {
		t.Errorf("Expected 1 pattern, got %d", len(cfg.Syslog.Patterns))
	} else {
		pattern := cfg.Syslog.Patterns[0]
		if pattern.Name != "dovecot-auth-failure" {
			t.Errorf("Expected pattern name 'dovecot-auth-failure', got '%s'", pattern.Name)
		}
		if pattern.IPGroup != 1 {
			t.Errorf("Expected IP group 1, got %d", pattern.IPGroup)
		}
		if pattern.Severity != 3 {
			t.Errorf("Expected severity 3, got %d", pattern.Severity)
		}
	}

	// Test SPOA config
	if cfg.SPOA.Address != "127.0.0.1" {
		t.Errorf("Expected SPOA address '127.0.0.1', got '%s'", cfg.SPOA.Address)
	}
	if cfg.SPOA.Port != 12346 {
		t.Errorf("Expected SPOA port 12346, got %d", cfg.SPOA.Port)
	}
	if cfg.SPOA.MaxClients != 50 {
		t.Errorf("Expected SPOA max_clients 50, got %d", cfg.SPOA.MaxClients)
	}
	if cfg.SPOA.ReadTimeout != 20*time.Second {
		t.Errorf("Expected SPOA read_timeout 20s, got %v", cfg.SPOA.ReadTimeout)
	}
	if cfg.SPOA.Enabled != false {
		t.Errorf("Expected SPOA enabled false, got %t", cfg.SPOA.Enabled)
	}

	// Test Envoy config
	if cfg.Envoy.Address != "127.0.0.1" {
		t.Errorf("Expected Envoy address '127.0.0.1', got '%s'", cfg.Envoy.Address)
	}
	if cfg.Envoy.Port != 9002 {
		t.Errorf("Expected Envoy port 9002, got %d", cfg.Envoy.Port)
	}
	if cfg.Envoy.Enabled != true {
		t.Errorf("Expected Envoy enabled true, got %t", cfg.Envoy.Enabled)
	}

	// Test Nginx config
	if cfg.Nginx.Address != "127.0.0.1" {
		t.Errorf("Expected Nginx address '127.0.0.1', got '%s'", cfg.Nginx.Address)
	}
	if cfg.Nginx.Port != 8889 {
		t.Errorf("Expected Nginx port 8889, got %d", cfg.Nginx.Port)
	}
	if cfg.Nginx.Enabled != true {
		t.Errorf("Expected Nginx enabled true, got %t", cfg.Nginx.Enabled)
	}
	if cfg.Nginx.ReadTimeout != 5*time.Second {
		t.Errorf("Expected Nginx read_timeout 5s, got %v", cfg.Nginx.ReadTimeout)
	}
	if cfg.Nginx.WriteTimeout != 5*time.Second {
		t.Errorf("Expected Nginx write_timeout 5s, got %v", cfg.Nginx.WriteTimeout)
	}
	if cfg.Nginx.ReturnJSON != true {
		t.Errorf("Expected Nginx return_json true, got %t", cfg.Nginx.ReturnJSON)
	}

	// Test Ban config
	if cfg.Ban.InitialBanTime != 10*time.Minute {
		t.Errorf("Expected initial_ban_time 10m, got %v", cfg.Ban.InitialBanTime)
	}
	if cfg.Ban.MaxBanTime != 48*time.Hour {
		t.Errorf("Expected max_ban_time 48h, got %v", cfg.Ban.MaxBanTime)
	}
	if cfg.Ban.EscalationFactor != 3.0 {
		t.Errorf("Expected escalation_factor 3.0, got %f", cfg.Ban.EscalationFactor)
	}
	if cfg.Ban.MaxAttempts != 3 {
		t.Errorf("Expected max_attempts 3, got %d", cfg.Ban.MaxAttempts)
	}
	if cfg.Ban.TimeWindow != 5*time.Minute {
		t.Errorf("Expected time_window 5m, got %v", cfg.Ban.TimeWindow)
	}
	if cfg.Ban.CleanupInterval != 30*time.Second {
		t.Errorf("Expected cleanup_interval 30s, got %v", cfg.Ban.CleanupInterval)
	}
	if cfg.Ban.MaxMemoryTTL != 48*time.Hour {
		t.Errorf("Expected max_memory_ttl 48h, got %v", cfg.Ban.MaxMemoryTTL)
	}
}

func TestLoadDefaults(t *testing.T) {
	// Create empty config file to test defaults
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write empty config file: %v", err)
	}

	// Set viper to use our test directory
	viper.Reset()
	viper.AddConfigPath(tmpDir)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Load config
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test default values
	if cfg.Syslog.Address != "127.0.0.1:514" {
		t.Errorf("Expected default syslog address '127.0.0.1:514', got '%s'", cfg.Syslog.Address)
	}
	if cfg.Syslog.Protocol != "udp" {
		t.Errorf("Expected default syslog protocol 'udp', got '%s'", cfg.Syslog.Protocol)
	}

	if cfg.SPOA.Address != "0.0.0.0" {
		t.Errorf("Expected default SPOA address '0.0.0.0', got '%s'", cfg.SPOA.Address)
	}
	if cfg.SPOA.Port != 12345 {
		t.Errorf("Expected default SPOA port 12345, got %d", cfg.SPOA.Port)
	}
	if cfg.SPOA.MaxClients != 100 {
		t.Errorf("Expected default SPOA max_clients 100, got %d", cfg.SPOA.MaxClients)
	}
	if cfg.SPOA.ReadTimeout != 30*time.Second {
		t.Errorf("Expected default SPOA read_timeout 30s, got %v", cfg.SPOA.ReadTimeout)
	}
	if cfg.SPOA.Enabled != true {
		t.Errorf("Expected default SPOA enabled true, got %t", cfg.SPOA.Enabled)
	}

	if cfg.Envoy.Address != "0.0.0.0" {
		t.Errorf("Expected default Envoy address '0.0.0.0', got '%s'", cfg.Envoy.Address)
	}
	if cfg.Envoy.Port != 9001 {
		t.Errorf("Expected default Envoy port 9001, got %d", cfg.Envoy.Port)
	}
	if cfg.Envoy.Enabled != true {
		t.Errorf("Expected default Envoy enabled true, got %t", cfg.Envoy.Enabled)
	}

	if cfg.Nginx.Address != "0.0.0.0" {
		t.Errorf("Expected default Nginx address '0.0.0.0', got '%s'", cfg.Nginx.Address)
	}
	if cfg.Nginx.Port != 8888 {
		t.Errorf("Expected default Nginx port 8888, got %d", cfg.Nginx.Port)
	}
	if cfg.Nginx.Enabled != true {
		t.Errorf("Expected default Nginx enabled true, got %t", cfg.Nginx.Enabled)
	}
	if cfg.Nginx.ReadTimeout != 10*time.Second {
		t.Errorf("Expected default Nginx read_timeout 10s, got %v", cfg.Nginx.ReadTimeout)
	}
	if cfg.Nginx.WriteTimeout != 10*time.Second {
		t.Errorf("Expected default Nginx write_timeout 10s, got %v", cfg.Nginx.WriteTimeout)
	}
	if cfg.Nginx.ReturnJSON != false {
		t.Errorf("Expected default Nginx return_json false, got %t", cfg.Nginx.ReturnJSON)
	}

	if cfg.Ban.InitialBanTime != 5*time.Minute {
		t.Errorf("Expected default initial_ban_time 5m, got %v", cfg.Ban.InitialBanTime)
	}
	if cfg.Ban.MaxBanTime != 24*time.Hour {
		t.Errorf("Expected default max_ban_time 24h, got %v", cfg.Ban.MaxBanTime)
	}
	if cfg.Ban.EscalationFactor != 2.0 {
		t.Errorf("Expected default escalation_factor 2.0, got %f", cfg.Ban.EscalationFactor)
	}
	if cfg.Ban.MaxAttempts != 5 {
		t.Errorf("Expected default max_attempts 5, got %d", cfg.Ban.MaxAttempts)
	}
	if cfg.Ban.TimeWindow != 10*time.Minute {
		t.Errorf("Expected default time_window 10m, got %v", cfg.Ban.TimeWindow)
	}
	if cfg.Ban.CleanupInterval != 1*time.Minute {
		t.Errorf("Expected default cleanup_interval 1m, got %v", cfg.Ban.CleanupInterval)
	}
	if cfg.Ban.MaxMemoryTTL != 72*time.Hour {
		t.Errorf("Expected default max_memory_ttl 72h, got %v", cfg.Ban.MaxMemoryTTL)
	}
}

func TestLoadMissingFile(t *testing.T) {
	// Use a non-existent directory
	viper.Reset()
	viper.AddConfigPath("/non/existent/path")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	_, err := Load()
	if err == nil {
		t.Error("Expected error when config file is missing, got nil")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	// Create invalid YAML file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	invalidYAML := `
syslog:
  address: "127.0.0.1:514"
  protocol: tcp
  patterns:
    - name: invalid
      regex: [unclosed bracket
`

	err := os.WriteFile(configFile, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid config file: %v", err)
	}

	viper.Reset()
	viper.AddConfigPath(tmpDir)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	_, err = Load()
	if err == nil {
		t.Error("Expected error when parsing invalid YAML, got nil")
	}
}
