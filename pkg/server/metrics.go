package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// metricsNamespace is the shared Prometheus namespace prefix for all
// wormhole server metrics (e.g. "wormhole_active_clients").
const metricsNamespace = "wormhole"

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

	// ClusterRouteSyncFailuresTotal counts state-store RegisterRoute
	// calls (initial registration or heartbeat refresh) that failed for
	// a reason other than a genuine conflict — e.g. Redis unreachable.
	// These self-heal on a later heartbeat but a sustained non-zero
	// rate indicates the cluster state store is degraded.
	ClusterRouteSyncFailuresTotal prometheus.Counter

	// ClusterRouteConflictsTotal counts routes this node believed it
	// owned (present in a client's clusterRoutes) that a later
	// refresh discovered are now claimed by a different route entry —
	// i.e. a split-brain window opened by a transient state-store
	// outage has been detected. There is no automatic remediation;
	// operators should alert on this being non-zero.
	ClusterRouteConflictsTotal prometheus.Counter

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
			Namespace: metricsNamespace,
			Name:      "active_clients",
			Help:      "Number of currently connected clients.",
		}),
		ActiveTunnels: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "active_tunnels",
			Help:      "Number of currently active tunnels.",
		}),
		ConnectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "connections_total",
			Help:      "Total number of client connections accepted.",
		}),
		BytesTransferredTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "bytes_transferred_total",
			Help:      "Total bytes transferred, labeled by direction.",
		}, []string{"direction"}),
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "requests_total",
			Help:      "Total number of proxied requests, labeled by protocol and status.",
		}, []string{"protocol", "status"}),
		RequestDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "request_duration_seconds",
			Help:      "Histogram of request durations in seconds.",
			Buckets:   prometheus.DefBuckets,
		}),
		AuthAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "auth_attempts_total",
			Help:      "Total number of authentication attempts, labeled by result.",
		}, []string{"result"}),
		P2PConnectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "p2p_connections_total",
			Help:      "Total number of P2P connection attempts, labeled by result.",
		}, []string{"result"}),
		TunnelDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "tunnel_duration_seconds",
			Help:      "Histogram of tunnel lifetimes in seconds.",
			Buckets:   []float64{1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600, 7200, 86400},
		}),
		ClusterRouteSyncFailuresTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "cluster_route_sync_failures_total",
			Help:      "Total state-store route registrations/refreshes that failed for a reason other than a genuine conflict (e.g. Redis unreachable). Self-heals on a later heartbeat.",
		}),
		ClusterRouteConflictsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "cluster_route_conflicts_total",
			Help:      "Total routes this node believed it owned that a later refresh found claimed by a different node — a split-brain window detected with no automatic remediation.",
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
		m.ClusterRouteSyncFailuresTotal,
		m.ClusterRouteConflictsTotal,
	)

	return m
}

// Registry returns the Prometheus registry used by these metrics.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}
