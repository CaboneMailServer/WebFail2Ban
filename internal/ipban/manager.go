package ipban

import (
	"context"
	"fail2ban-haproxy/internal/config"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

type Manager struct {
	cfg    *config.Config
	logger *zap.Logger
	tree   *RadixTree
	mutex  sync.RWMutex
	stats  map[string]*IPStats
}

type IPStats struct {
	Violations    []Violation
	BanExpiry     time.Time
	BanCount      int
	FirstSeen     time.Time
	LastSeen      time.Time
	TotalSeverity int
}

type Violation struct {
	Timestamp   time.Time
	Severity    int
	Description string
}

type RadixTree struct {
	root *RadixNode
}

type RadixNode struct {
	children [2]*RadixNode // 0 and 1 for binary tree
	isEnd    bool
	ip       string
	banned   bool
}

func NewManager(cfg *config.Config, logger *zap.Logger) *Manager {
	return &Manager{
		cfg:    cfg,
		logger: logger,
		tree:   NewRadixTree(),
		stats:  make(map[string]*IPStats),
	}
}

func NewRadixTree() *RadixTree {
	return &RadixTree{
		root: &RadixNode{},
	}
}

func (m *Manager) RecordViolation(ip string, severity int, description string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()
	stats, exists := m.stats[ip]

	if !exists {
		stats = &IPStats{
			Violations: make([]Violation, 0),
			FirstSeen:  now,
			LastSeen:   now,
		}
		m.stats[ip] = stats
	}

	stats.LastSeen = now
	stats.TotalSeverity += severity
	stats.Violations = append(stats.Violations, Violation{
		Timestamp:   now,
		Severity:    severity,
		Description: description,
	})

	// Clean old violations outside time window
	cutoff := now.Add(-m.cfg.Ban.TimeWindow)
	validViolations := make([]Violation, 0)
	totalSeverity := 0

	for _, v := range stats.Violations {
		if v.Timestamp.After(cutoff) {
			validViolations = append(validViolations, v)
			totalSeverity += v.Severity
		}
	}

	stats.Violations = validViolations
	stats.TotalSeverity = totalSeverity

	// Check if IP should be banned
	if len(stats.Violations) >= m.cfg.Ban.MaxAttempts && stats.BanExpiry.Before(now) {
		m.banIP(ip, stats)
	}
}

func (m *Manager) banIP(ip string, stats *IPStats) {
	stats.BanCount++

	// Calculate ban duration with escalation
	banDuration := time.Duration(float64(m.cfg.Ban.InitialBanTime) *
		float64(stats.BanCount) * m.cfg.Ban.EscalationFactor)

	if banDuration > m.cfg.Ban.MaxBanTime {
		banDuration = m.cfg.Ban.MaxBanTime
	}

	stats.BanExpiry = time.Now().Add(banDuration)

	// Add to radix tree
	m.tree.Insert(ip)

	m.logger.Info("IP banned",
		zap.String("ip", ip),
		zap.Duration("duration", banDuration),
		zap.Int("ban_count", stats.BanCount),
		zap.Int("violations", len(stats.Violations)),
		zap.Time("expires", stats.BanExpiry))
}

func (m *Manager) IsBanned(ip string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats, exists := m.stats[ip]
	if !exists {
		return false
	}

	if stats.BanExpiry.After(time.Now()) {
		return m.tree.Search(ip)
	}

	// Ban expired, remove from tree
	m.tree.Delete(ip)
	return false
}

func (m *Manager) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.Ban.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *Manager) cleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-m.cfg.Ban.MaxMemoryTTL)

	for ip, stats := range m.stats {
		// Remove from memory if too old and not currently banned
		if stats.LastSeen.Before(cutoff) && stats.BanExpiry.Before(now) {
			delete(m.stats, ip)
			m.tree.Delete(ip)
			m.logger.Debug("Cleaned up old IP record", zap.String("ip", ip))
		} else if stats.BanExpiry.Before(now) {
			// Just remove from ban tree if ban expired
			m.tree.Delete(ip)
		}
	}
}

// GetIPStats returns the statistics for a specific IP (for testing)
func (m *Manager) GetIPStats(ip string) *IPStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.stats[ip]
}

// GetStatsCount returns the number of IPs in the stats map (for testing)
func (m *Manager) GetStatsCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.stats)
}

func (rt *RadixTree) Insert(ip string) {
	bytes := ipToBytes(ip)
	if bytes == nil {
		return
	}

	node := rt.root
	for _, b := range bytes {
		for i := 7; i >= 0; i-- {
			bit := (b >> i) & 1
			if node.children[bit] == nil {
				node.children[bit] = &RadixNode{}
			}
			node = node.children[bit]
		}
	}
	node.isEnd = true
	node.ip = ip
	node.banned = true
}

func (rt *RadixTree) Search(ip string) bool {
	bytes := ipToBytes(ip)
	if bytes == nil {
		return false
	}

	node := rt.root
	for _, b := range bytes {
		for i := 7; i >= 0; i-- {
			bit := (b >> i) & 1
			if node.children[bit] == nil {
				return false
			}
			node = node.children[bit]
		}
	}
	return node.isEnd && node.banned
}

func (rt *RadixTree) Delete(ip string) {
	bytes := ipToBytes(ip)
	if bytes == nil {
		return
	}

	node := rt.root
	for _, b := range bytes {
		for i := 7; i >= 0; i-- {
			bit := (b >> i) & 1
			if node.children[bit] == nil {
				return
			}
			node = node.children[bit]
		}
	}
	if node.isEnd {
		node.banned = false
	}
}

func ipToBytes(ip string) []byte {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}
	if parsedIP.To4() != nil {
		return parsedIP.To4()
	}
	return parsedIP.To16()
}
