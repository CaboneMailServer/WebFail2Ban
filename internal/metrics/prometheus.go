package metrics

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"fail2ban-haproxy/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

var (
	// Request counters
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "fail2ban",
			Name:      "requests_total",
			Help:      "Total number of requests processed by service type",
		},
		[]string{"service", "result"},
	)

	// Ban metrics
	bansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "fail2ban",
			Name:      "bans_total",
			Help:      "Total number of IPs banned",
		},
		[]string{"pattern"},
	)

	currentBans = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "fail2ban",
			Name:      "current_bans",
			Help:      "Current number of banned IPs",
		},
		[]string{"pattern"},
	)

	banDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "fail2ban",
			Name:      "ban_duration_seconds",
			Help:      "Duration of bans in seconds",
			Buckets:   []float64{300, 600, 1800, 3600, 7200, 14400, 28800, 86400, 172800, 259200}, // 5m to 72h
		},
		[]string{"pattern"},
	)

	// Pattern matching metrics
	patternMatches = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "fail2ban",
			Name:      "pattern_matches_total",
			Help:      "Total number of pattern matches",
		},
		[]string{"pattern", "severity"},
	)

	// Service metrics
	serviceRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "fail2ban",
			Name:      "service_requests_total",
			Help:      "Total number of service requests",
		},
		[]string{"service", "status"},
	)

	serviceRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "fail2ban",
			Name:      "service_request_duration_seconds",
			Help:      "Duration of service requests",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"service"},
	)

	// Database metrics
	databaseOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "fail2ban",
			Name:      "database_operations_total",
			Help:      "Total number of database operations",
		},
		[]string{"operation", "status"},
	)

	databaseConnectionsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "fail2ban",
			Name:      "database_connections_active",
			Help:      "Number of active database connections",
		},
	)

	// Configuration metrics
	configReloads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "fail2ban",
			Name:      "config_reloads_total",
			Help:      "Total number of configuration reloads",
		},
		[]string{"source", "status"},
	)

	configPatternsLoaded = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "fail2ban",
			Name:      "config_patterns_loaded",
			Help:      "Number of patterns currently loaded",
		},
	)

	// System metrics
	uptime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "fail2ban",
			Name:      "uptime_seconds",
			Help:      "Service uptime in seconds",
		},
	)

	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "fail2ban",
			Name:      "build_info",
			Help:      "Build information",
		},
		[]string{"version", "commit", "go_version"},
	)
)

type PrometheusMetrics struct {
	server    *http.Server
	registry  *prometheus.Registry
	startTime time.Time
	config    config.PrometheusConfig
}

func NewPrometheusMetrics(cfg config.PrometheusConfig) *PrometheusMetrics {
	registry := prometheus.NewRegistry()

	// Register all metrics
	registry.MustRegister(
		requestsTotal,
		bansTotal,
		currentBans,
		banDuration,
		patternMatches,
		serviceRequests,
		serviceRequestDuration,
		databaseOperations,
		databaseConnectionsActive,
		configReloads,
		configPatternsLoaded,
		uptime,
		buildInfo,
	)

	return &PrometheusMetrics{
		registry:  registry,
		startTime: time.Now(),
		config:    cfg,
	}
}

func (m *PrometheusMetrics) Start() error {
	if !m.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle(m.config.Path, promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	addr := fmt.Sprintf("%s:%d", m.config.Address, m.config.Port)
	m.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("Starting Prometheus metrics server on %s%s", addr, m.config.Path)

	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Error starting Prometheus metrics server: %v", err)
		}
	}()

	// Start uptime updater
	go m.updateUptime()

	return nil
}

func (m *PrometheusMetrics) Stop() error {
	if m.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.server.Shutdown(ctx)
}

func (m *PrometheusMetrics) updateUptime() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		uptime.Set(time.Since(m.startTime).Seconds())
	}
}

// Request metrics
func (m *PrometheusMetrics) IncRequests(service, result string) {
	requestsTotal.WithLabelValues(service, result).Inc()
}

func (m *PrometheusMetrics) IncServiceRequests(service, status string) {
	serviceRequests.WithLabelValues(service, status).Inc()
}

func (m *PrometheusMetrics) ObserveServiceRequestDuration(service string, duration time.Duration) {
	serviceRequestDuration.WithLabelValues(service).Observe(duration.Seconds())
}

// Ban metrics
func (m *PrometheusMetrics) IncBans(pattern string) {
	bansTotal.WithLabelValues(pattern).Inc()
}

func (m *PrometheusMetrics) SetCurrentBans(pattern string, count float64) {
	currentBans.WithLabelValues(pattern).Set(count)
}

func (m *PrometheusMetrics) ObserveBanDuration(pattern string, duration time.Duration) {
	banDuration.WithLabelValues(pattern).Observe(duration.Seconds())
}

// Pattern metrics
func (m *PrometheusMetrics) IncPatternMatches(pattern string, severity int) {
	patternMatches.WithLabelValues(pattern, strconv.Itoa(severity)).Inc()
}

// Database metrics
func (m *PrometheusMetrics) IncDatabaseOperations(operation, status string) {
	databaseOperations.WithLabelValues(operation, status).Inc()
}

func (m *PrometheusMetrics) SetDatabaseConnectionsActive(count float64) {
	databaseConnectionsActive.Set(count)
}

// Configuration metrics
func (m *PrometheusMetrics) IncConfigReloads(source, status string) {
	configReloads.WithLabelValues(source, status).Inc()
}

func (m *PrometheusMetrics) SetConfigPatternsLoaded(count float64) {
	configPatternsLoaded.Set(count)
}

// Build info
func (m *PrometheusMetrics) SetBuildInfo(version, commit, goVersion string) {
	buildInfo.WithLabelValues(version, commit, goVersion).Set(1)
}

// Timer helper for measuring request duration
type Timer struct {
	start   time.Time
	metrics *PrometheusMetrics
	service string
}

func (m *PrometheusMetrics) Timer(service string) *Timer {
	return &Timer{
		start:   time.Now(),
		metrics: m,
		service: service,
	}
}

func (t *Timer) ObserveDuration() {
	t.metrics.ObserveServiceRequestDuration(t.service, time.Since(t.start))
}

// Helper function to get all current metric values for debugging
func (m *PrometheusMetrics) GetMetricFamilies() ([]*dto.MetricFamily, error) {
	return m.registry.Gather()
}
