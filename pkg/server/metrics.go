package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds all Prometheus metrics for the wormhole server.
type Metrics struct {
	// ActiveClients is the number of currently connected clients.
	ActiveClients prometheus.Gauge

	// ActiveTunnels is the number of currently active tunnels.
	ActiveTunnels prometheus.Gauge

	// ConnectionsTotal is the total number of client connections accepted.
	ConnectionsTotal prometheus.Counter

	// BytesTransferredTotal is the total bytes transferred, labeled by direction (in/out).
	BytesTransferredTotal *prometheus.CounterVec

	// RequestsTotal is the total number of requests, labeled by protocol and status.
	RequestsTotal *prometheus.CounterVec

	// RequestDurationSeconds is the histogram of request durations in seconds.
	RequestDurationSeconds prometheus.Histogram

	// AuthAttemptsTotal is the total number of authentication attempts, labeled by result (success/failure).
	AuthAttemptsTotal *prometheus.CounterVec

	// P2PConnectionsTotal is the total number of P2P connection attempts, labeled by result (success/fallback).
	P2PConnectionsTotal *prometheus.CounterVec

	// TunnelDurationSeconds is the histogram of tunnel lifetimes in seconds.
	TunnelDurationSeconds prometheus.Histogram

	registry *prometheus.Registry
}

// NewMetrics creates and registers all Prometheus metrics.
// It uses a custom registry to avoid polluting the global default.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	// Register default Go runtime and process collectors.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{
		ActiveClients: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "wormhole",
			Name:      "active_clients",
			Help:      "Number of currently connected clients.",
		}),
		ActiveTunnels: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "wormhole",
			Name:      "active_tunnels",
			Help:      "Number of currently active tunnels.",
		}),
		ConnectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "wormhole",
			Name:      "connections_total",
			Help:      "Total number of client connections accepted.",
		}),
		BytesTransferredTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "wormhole",
			Name:      "bytes_transferred_total",
			Help:      "Total bytes transferred, labeled by direction.",
		}, []string{"direction"}),
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "wormhole",
			Name:      "requests_total",
			Help:      "Total number of proxied requests, labeled by protocol and status.",
		}, []string{"protocol", "status"}),
		RequestDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "wormhole",
			Name:      "request_duration_seconds",
			Help:      "Histogram of request durations in seconds.",
			Buckets:   prometheus.DefBuckets,
		}),
		AuthAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "wormhole",
			Name:      "auth_attempts_total",
			Help:      "Total number of authentication attempts, labeled by result.",
		}, []string{"result"}),
		P2PConnectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "wormhole",
			Name:      "p2p_connections_total",
			Help:      "Total number of P2P connection attempts, labeled by result.",
		}, []string{"result"}),
		TunnelDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "wormhole",
			Name:      "tunnel_duration_seconds",
			Help:      "Histogram of tunnel lifetimes in seconds.",
			Buckets:   []float64{1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600, 7200, 86400},
		}),
		registry: reg,
	}

	// Register all metrics with the custom registry.
	reg.MustRegister(
		m.ActiveClients,
		m.ActiveTunnels,
		m.ConnectionsTotal,
		m.BytesTransferredTotal,
		m.RequestsTotal,
		m.RequestDurationSeconds,
		m.AuthAttemptsTotal,
		m.P2PConnectionsTotal,
		m.TunnelDurationSeconds,
	)

	return m
}

// Registry returns the Prometheus registry used by these metrics.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}
