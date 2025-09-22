package api

import (
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"fail2ban-haproxy/internal/config"
)

// SecurityMiddleware handles API security (IP filtering, auth, rate limiting)
type SecurityMiddleware struct {
	config      config.APIConfig
	allowedNets []*net.IPNet
	rateLimiter *RateLimiter
}

// RateLimiter implements simple in-memory rate limiting
type RateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*ClientLimiter
	limit   int
	window  time.Duration
	enabled bool
}

// ClientLimiter tracks requests for a specific client
type ClientLimiter struct {
	requests []time.Time
	mu       sync.Mutex
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(apiConfig config.APIConfig) (*SecurityMiddleware, error) {
	sm := &SecurityMiddleware{
		config: apiConfig,
	}

	// Parse allowed IP networks
	if err := sm.parseAllowedIPs(); err != nil {
		return nil, err
	}

	// Initialize rate limiter
	if apiConfig.RateLimiting.Enabled {
		sm.rateLimiter = &RateLimiter{
			clients: make(map[string]*ClientLimiter),
			limit:   apiConfig.RateLimiting.RequestsPer,
			window:  time.Minute,
			enabled: true,
		}
	}

	return sm, nil
}

// parseAllowedIPs parses the allowed IP addresses and CIDR ranges
func (sm *SecurityMiddleware) parseAllowedIPs() error {
	sm.allowedNets = make([]*net.IPNet, 0, len(sm.config.AllowedIPs))

	for _, ipStr := range sm.config.AllowedIPs {
		// Handle single IPs
		if !strings.Contains(ipStr, "/") {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				log.Printf("Warning: invalid IP address in API allowed_ips: %s", ipStr)
				continue
			}

			// Convert to CIDR
			if ip.To4() != nil {
				ipStr += "/32" // IPv4
			} else {
				ipStr += "/128" // IPv6
			}
		}

		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			log.Printf("Warning: invalid CIDR in API allowed_ips: %s - %v", ipStr, err)
			continue
		}

		sm.allowedNets = append(sm.allowedNets, ipNet)
	}

	log.Printf("API access configured for %d IP ranges", len(sm.allowedNets))
	return nil
}

// isIPAllowed checks if an IP address is in the allowed list
func (sm *SecurityMiddleware) isIPAllowed(ipStr string) bool {
	// If no restrictions configured, allow all
	if len(sm.allowedNets) == 0 {
		return true
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, ipNet := range sm.allowedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// getClientIP extracts the client IP from the request
func (sm *SecurityMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// checkBasicAuth validates basic authentication
func (sm *SecurityMiddleware) checkBasicAuth(r *http.Request) bool {
	if !sm.config.BasicAuth.Enabled {
		return true
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}

	// Check single user configuration
	if sm.config.BasicAuth.Username != "" && sm.config.BasicAuth.Password != "" {
		validUsername := subtle.ConstantTimeCompare([]byte(username), []byte(sm.config.BasicAuth.Username)) == 1
		validPassword := subtle.ConstantTimeCompare([]byte(password), []byte(sm.config.BasicAuth.Password)) == 1
		if validUsername && validPassword {
			return true
		}
	}

	// Check multiple users configuration
	if len(sm.config.BasicAuth.Users) > 0 {
		if expectedPassword, exists := sm.config.BasicAuth.Users[username]; exists {
			validPassword := subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) == 1
			if validPassword {
				return true
			}
		}
	}

	return false
}

// checkRateLimit validates rate limiting
func (sm *SecurityMiddleware) checkRateLimit(clientIP string) bool {
	if sm.rateLimiter == nil || !sm.rateLimiter.enabled {
		return true
	}

	return sm.rateLimiter.Allow(clientIP)
}

// Allow checks if a client is allowed to make a request
func (rl *RateLimiter) Allow(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Get or create client limiter
	client, exists := rl.clients[clientIP]
	if !exists {
		client = &ClientLimiter{
			requests: make([]time.Time, 0),
		}
		rl.clients[clientIP] = client
	}

	client.mu.Lock()
	defer client.mu.Unlock()

	// Remove old requests outside the window
	cutoff := now.Add(-rl.window)
	validRequests := make([]time.Time, 0)
	for _, reqTime := range client.requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}
	client.requests = validRequests

	// Check if limit is exceeded
	if len(client.requests) >= rl.limit {
		return false
	}

	// Add current request
	client.requests = append(client.requests, now)
	return true
}

// Cleanup removes old client entries to prevent memory leaks
func (rl *RateLimiter) Cleanup() {
	if rl == nil || !rl.enabled {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window * 2) // Keep data for 2 windows

	for clientIP, client := range rl.clients {
		client.mu.Lock()
		hasRecentRequests := false
		for _, reqTime := range client.requests {
			if reqTime.After(cutoff) {
				hasRecentRequests = true
				break
			}
		}
		client.mu.Unlock()

		if !hasRecentRequests {
			delete(rl.clients, clientIP)
		}
	}
}

// Middleware wraps HTTP handlers with security checks
func (sm *SecurityMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := sm.getClientIP(r)

		// Check IP allowlist
		if !sm.isIPAllowed(clientIP) {
			log.Printf("API access denied for IP: %s (not in allowed list)", clientIP)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Check basic authentication
		if !sm.checkBasicAuth(r) {
			log.Printf("API authentication failed for IP: %s", clientIP)
			w.Header().Set("WWW-Authenticate", `Basic realm="Fail2Ban API"`)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Check rate limiting
		if !sm.checkRateLimit(clientIP) {
			log.Printf("API rate limit exceeded for IP: %s", clientIP)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// All checks passed, proceed to handler
		next.ServeHTTP(w, r)
	})
}

// StartCleanupRoutine starts a background routine to clean up rate limiter data
func (sm *SecurityMiddleware) StartCleanupRoutine() {
	if sm.rateLimiter == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.rateLimiter.Cleanup()
			}
		}
	}()

	log.Printf("Started API rate limiter cleanup routine")
}

// GetStatus returns the current status of the security middleware
func (sm *SecurityMiddleware) GetStatus() map[string]interface{} {
	status := map[string]interface{}{
		"enabled":               sm.config.Enabled,
		"allowed_ips_count":     len(sm.allowedNets),
		"basic_auth_enabled":    sm.config.BasicAuth.Enabled,
		"rate_limiting_enabled": sm.config.RateLimiting.Enabled,
	}

	if sm.rateLimiter != nil {
		sm.rateLimiter.mu.RLock()
		status["active_clients"] = len(sm.rateLimiter.clients)
		status["rate_limit"] = sm.rateLimiter.limit
		sm.rateLimiter.mu.RUnlock()
	}

	return status
}
