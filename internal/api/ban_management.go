package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"fail2ban-haproxy/internal/config"
	"fail2ban-haproxy/internal/database"
	"fail2ban-haproxy/internal/ipban"
)

// BanManager handles manual ban/unban operations
type BanManager struct {
	configManager      *config.ConfigManager
	db                 *database.DB
	ipBanManager       *ipban.Manager
	securityMiddleware *SecurityMiddleware
}

// NewBanManager creates a new ban manager
func NewBanManager(configManager *config.ConfigManager, db *database.DB, ipBanManager *ipban.Manager) (*BanManager, error) {
	bm := &BanManager{
		configManager: configManager,
		db:            db,
		ipBanManager:  ipBanManager,
	}

	// Initialize security middleware if API is enabled
	apiConfig := configManager.GetConfig().API
	if apiConfig.Enabled {
		middleware, err := NewSecurityMiddleware(apiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize API security middleware: %w", err)
		}
		bm.securityMiddleware = middleware
		bm.securityMiddleware.StartCleanupRoutine()
	}

	return bm, nil
}

// BanRequest represents a manual ban request
type BanRequest struct {
	IPAddress string        `json:"ip_address"`
	Duration  time.Duration `json:"duration,omitempty"` // Optional: for temporary bans
	Reason    string        `json:"reason,omitempty"`
	CreatedBy string        `json:"created_by,omitempty"`
	Permanent bool          `json:"permanent,omitempty"` // If true, adds to blacklist
}

// UnbanRequest represents a manual unban request
type UnbanRequest struct {
	IPAddress string `json:"ip_address"`
	Reason    string `json:"reason,omitempty"`
}

// WhitelistRequest represents a whitelist request
type WhitelistRequest struct {
	IPAddress string `json:"ip_address"`
	Reason    string `json:"reason,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
}

// BanResponse represents the response to ban operations
type BanResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	IPAddress string `json:"ip_address"`
}

// ListResponse represents list responses
type ListResponse struct {
	Success   bool            `json:"success"`
	Message   string          `json:"message"`
	Count     int             `json:"count"`
	Blacklist []BlacklistItem `json:"blacklist,omitempty"`
	Whitelist []WhitelistItem `json:"whitelist,omitempty"`
}

type BlacklistItem struct {
	IPAddress string    `json:"ip_address"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

type WhitelistItem struct {
	IPAddress string    `json:"ip_address"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// validateIP validates if the IP address is valid
func validateIP(ipAddress string) error {
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}
	return nil
}

// HandleManualBan handles manual ban requests
func (bm *BanManager) HandleManualBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate IP address
	if err := validateIP(req.IPAddress); err != nil {
		response := BanResponse{
			Success:   false,
			Message:   err.Error(),
			IPAddress: req.IPAddress,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set defaults
	if req.CreatedBy == "" {
		req.CreatedBy = "api"
	}
	if req.Reason == "" {
		req.Reason = "Manual ban via API"
	}

	var message string
	var success bool

	if req.Permanent {
		// Add to permanent blacklist
		if bm.db != nil {
			err := bm.db.AddToBlacklist(req.IPAddress, req.Reason, req.CreatedBy)
			if err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					message = fmt.Sprintf("IP %s is already blacklisted", req.IPAddress)
					success = true
				} else {
					message = fmt.Sprintf("Failed to add to blacklist: %v", err)
					success = false
				}
			} else {
				message = fmt.Sprintf("IP %s permanently banned (blacklisted)", req.IPAddress)
				success = true
			}
		} else {
			message = "Database not available for permanent bans"
			success = false
		}
	} else {
		// Add temporary ban to radix tree
		if bm.ipBanManager != nil {
			duration := req.Duration
			if duration == 0 {
				// Use default ban time from config
				banConfig := bm.configManager.GetBanConfig()
				duration = banConfig.InitialBanTime
			}

			err := bm.ipBanManager.ManualBan(req.IPAddress, duration)
			if err != nil {
				message = fmt.Sprintf("Failed to add temporary ban: %v", err)
				success = false
			} else {
				message = fmt.Sprintf("IP %s temporarily banned for %v", req.IPAddress, duration)
				success = true
			}
		} else {
			message = "IP ban manager not available for temporary bans"
			success = false
		}
	}

	response := BanResponse{
		Success:   success,
		Message:   message,
		IPAddress: req.IPAddress,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)

	log.Printf("Manual ban request: IP=%s, Permanent=%v, Reason=%s, Success=%v",
		req.IPAddress, req.Permanent, req.Reason, success)
}

// HandleManualUnban handles manual unban requests
func (bm *BanManager) HandleManualUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UnbanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate IP address
	if err := validateIP(req.IPAddress); err != nil {
		response := BanResponse{
			Success:   false,
			Message:   err.Error(),
			IPAddress: req.IPAddress,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var message string
	var success bool

	// Remove from blacklist if present
	if bm.db != nil {
		// Check if blacklisted first
		isBlacklisted, err := bm.db.IsBlacklisted(req.IPAddress)
		if err != nil {
			message = fmt.Sprintf("Failed to check blacklist status: %v", err)
			success = false
		} else if isBlacklisted {
			err = bm.db.RemoveFromBlacklist(req.IPAddress)
			if err != nil {
				message = fmt.Sprintf("Failed to remove from blacklist: %v", err)
				success = false
			} else {
				message = fmt.Sprintf("IP %s removed from blacklist", req.IPAddress)
				success = true
			}
		} else {
			// Remove from temporary ban radix tree
			if bm.ipBanManager != nil {
				err = bm.ipBanManager.ManualUnban(req.IPAddress)
				if err != nil {
					message = fmt.Sprintf("Failed to remove temporary ban: %v", err)
					success = false
				} else {
					message = fmt.Sprintf("IP %s removed from temporary bans", req.IPAddress)
					success = true
				}
			} else {
				message = "IP ban manager not available for temporary unban"
				success = false
			}
		}
	} else {
		message = "Database not available for unban operations"
		success = false
	}

	response := BanResponse{
		Success:   success,
		Message:   message,
		IPAddress: req.IPAddress,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)

	log.Printf("Manual unban request: IP=%s, Reason=%s, Success=%v",
		req.IPAddress, req.Reason, success)
}

// HandleWhitelist handles whitelist management
func (bm *BanManager) HandleWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		bm.handleAddToWhitelist(w, r)
	case http.MethodDelete:
		bm.handleRemoveFromWhitelist(w, r)
	case http.MethodGet:
		bm.handleGetWhitelist(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (bm *BanManager) handleAddToWhitelist(w http.ResponseWriter, r *http.Request) {
	var req WhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate IP address
	if err := validateIP(req.IPAddress); err != nil {
		response := BanResponse{
			Success:   false,
			Message:   err.Error(),
			IPAddress: req.IPAddress,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set defaults
	if req.CreatedBy == "" {
		req.CreatedBy = "api"
	}
	if req.Reason == "" {
		req.Reason = "Manual whitelist via API"
	}

	var message string
	var success bool

	if bm.db != nil {
		err := bm.db.AddToWhitelist(req.IPAddress, req.Reason, req.CreatedBy)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				message = fmt.Sprintf("IP %s is already whitelisted", req.IPAddress)
				success = true
			} else {
				message = fmt.Sprintf("Failed to add to whitelist: %v", err)
				success = false
			}
		} else {
			message = fmt.Sprintf("IP %s added to whitelist", req.IPAddress)
			success = true
		}
	} else {
		message = "Database not available for whitelist operations"
		success = false
	}

	response := BanResponse{
		Success:   success,
		Message:   message,
		IPAddress: req.IPAddress,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)

	log.Printf("Add to whitelist request: IP=%s, Reason=%s, Success=%v",
		req.IPAddress, req.Reason, success)
}

func (bm *BanManager) handleRemoveFromWhitelist(w http.ResponseWriter, r *http.Request) {
	var req UnbanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate IP address
	if err := validateIP(req.IPAddress); err != nil {
		response := BanResponse{
			Success:   false,
			Message:   err.Error(),
			IPAddress: req.IPAddress,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var message string
	var success bool

	if bm.db != nil {
		err := bm.db.RemoveFromWhitelist(req.IPAddress)
		if err != nil {
			message = fmt.Sprintf("Failed to remove from whitelist: %v", err)
			success = false
		} else {
			message = fmt.Sprintf("IP %s removed from whitelist", req.IPAddress)
			success = true
		}
	} else {
		message = "Database not available for whitelist operations"
		success = false
	}

	response := BanResponse{
		Success:   success,
		Message:   message,
		IPAddress: req.IPAddress,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)

	log.Printf("Remove from whitelist request: IP=%s, Success=%v", req.IPAddress, success)
}

func (bm *BanManager) handleGetWhitelist(w http.ResponseWriter, r *http.Request) {
	var whitelist []WhitelistItem
	var success bool
	var message string

	if bm.db != nil {
		entries, err := bm.db.GetWhitelist()
		if err != nil {
			message = fmt.Sprintf("Failed to get whitelist: %v", err)
			success = false
		} else {
			for _, entry := range entries {
				whitelist = append(whitelist, WhitelistItem{
					IPAddress: entry.IPAddress,
					Reason:    entry.Reason,
					CreatedAt: entry.CreatedAt,
					CreatedBy: entry.CreatedBy,
				})
			}
			success = true
		}
	} else {
		message = "Database not available"
		success = false
	}

	response := ListResponse{
		Success:   success,
		Count:     len(whitelist),
		Message:   message,
		Whitelist: whitelist,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)
}

// HandleBlacklist handles blacklist listing
func (bm *BanManager) HandleBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var blacklist []BlacklistItem
	var success bool
	var message string

	if bm.db != nil {
		entries, err := bm.db.GetBlacklist()
		if err != nil {
			message = fmt.Sprintf("Failed to get blacklist: %v", err)
			success = false
		} else {
			for _, entry := range entries {
				blacklist = append(blacklist, BlacklistItem{
					IPAddress: entry.IPAddress,
					Reason:    entry.Reason,
					CreatedAt: entry.CreatedAt,
					CreatedBy: entry.CreatedBy,
				})
			}
			success = true
		}
	} else {
		message = "Database not available"
		success = false
	}

	response := ListResponse{
		Success:   success,
		Count:     len(blacklist),
		Message:   message,
		Blacklist: blacklist,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)
}

// HandleTemporaryBans handles listing of temporary bans
func (bm *BanManager) HandleTemporaryBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tempBans []TempBanItem
	var success bool
	var message string

	if bm.ipBanManager != nil {
		bannedIPs := bm.ipBanManager.GetAllBannedIPs()
		for ip, expiry := range bannedIPs {
			tempBans = append(tempBans, TempBanItem{
				IPAddress: ip,
				ExpiresAt: expiry,
				Duration:  time.Until(expiry),
			})
		}
		success = true
	} else {
		message = "IP ban manager not available"
		success = false
	}

	response := TempBanListResponse{
		Success:  success,
		Count:    len(tempBans),
		TempBans: tempBans,
		Message:  message,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)
}

// HandlePurgeBans handles purging of all temporary bans
func (bm *BanManager) HandlePurgeBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var message string
	var success bool
	var count int

	if bm.ipBanManager != nil {
		count = bm.ipBanManager.PurgeAllBans()
		message = fmt.Sprintf("Purged %d temporary bans", count)
		success = true
	} else {
		message = "IP ban manager not available"
		success = false
	}

	response := PurgeResponse{
		Success:     success,
		Message:     message,
		PurgedCount: count,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)

	log.Printf("Purge bans request: Success=%v, Count=%d", success, count)
}

// HandleRadixStats handles radix tree statistics
func (bm *BanManager) HandleRadixStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var stats map[string]interface{}
	var success bool
	var message string

	if bm.ipBanManager != nil {
		stats = bm.ipBanManager.GetRadixTreeStats()
		success = true
	} else {
		message = "IP ban manager not available"
		success = false
	}

	response := RadixStatsResponse{
		Success: success,
		Message: message,
		Stats:   stats,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)
}

// Additional response types
type TempBanItem struct {
	IPAddress string        `json:"ip_address"`
	ExpiresAt time.Time     `json:"expires_at"`
	Duration  time.Duration `json:"duration_remaining"`
}

type TempBanListResponse struct {
	Success  bool          `json:"success"`
	Count    int           `json:"count"`
	TempBans []TempBanItem `json:"temp_bans,omitempty"`
	Message  string        `json:"message,omitempty"`
}

type PurgeResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	PurgedCount int    `json:"purged_count"`
}

type RadixStatsResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Stats   map[string]interface{} `json:"stats,omitempty"`
}

// HandleSecurityStatus handles API security status requests
func (bm *BanManager) HandleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var status map[string]interface{}
	var success bool

	if bm.securityMiddleware != nil {
		status = bm.securityMiddleware.GetStatus()
		success = true
	} else {
		status = map[string]interface{}{
			"enabled": false,
			"message": "API security middleware not initialized",
		}
		success = false
	}

	response := map[string]interface{}{
		"success":  success,
		"security": status,
	}

	w.Header().Set("Content-Type", "application/json")
	if success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(response)
}

// SetupRoutes sets up the API routes for ban management with security middleware
func (bm *BanManager) SetupRoutes(mux *http.ServeMux) {
	// Create handlers
	handlers := map[string]http.HandlerFunc{
		"/api/ban":             bm.HandleManualBan,
		"/api/unban":           bm.HandleManualUnban,
		"/api/whitelist":       bm.HandleWhitelist,
		"/api/blacklist":       bm.HandleBlacklist,
		"/api/temp-bans":       bm.HandleTemporaryBans,
		"/api/purge-bans":      bm.HandlePurgeBans,
		"/api/radix-stats":     bm.HandleRadixStats,
		"/api/security-status": bm.HandleSecurityStatus,
	}

	// Apply security middleware if enabled
	if bm.securityMiddleware != nil {
		log.Printf("Applying API security middleware to %d endpoints", len(handlers))
		for path, handler := range handlers {
			securedHandler := bm.securityMiddleware.Middleware(handler)
			mux.Handle(path, securedHandler)
		}
	} else {
		log.Printf("API security middleware disabled, setting up unsecured endpoints")
		for path, handler := range handlers {
			mux.HandleFunc(path, handler)
		}
	}
}
