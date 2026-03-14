package monitoring

import (
	"fmt"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metrics for KYC Blockchain
var (
	HttpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	HttpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	BlockchainBlocksTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "blockchain_blocks_total",
			Help: "Total number of blocks in the blockchain",
		},
	)

	BlockchainTransactionsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "blockchain_transactions_total",
			Help: "Total number of transactions processed",
		},
	)

	KYCVerificationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kyc_verifications_total",
			Help: "Total KYC verifications by status",
		},
		[]string{"status"},
	)

	ActiveConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_connections",
			Help: "Number of active connections",
		},
	)

	DatabaseQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "database_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
		},
		[]string{"query_type"},
	)
)

// StartMetricsServer starts a separate HTTP server for Prometheus metrics
// on the configured metrics_port (default: 9090)
func StartMetricsServer(port int) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	log.Printf("   ✓ Prometheus metrics server starting on %s/metrics", addr)

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("   ⚠ Metrics server error: %v", err)
		}
	}()
}
