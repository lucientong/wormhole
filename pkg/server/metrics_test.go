package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics()
	require.NotNil(t, m)
	require.NotNil(t, m.Registry())
	require.NotNil(t, m.ActiveClients)
	require.NotNil(t, m.ActiveTunnels)
	require.NotNil(t, m.ConnectionsTotal)
	require.NotNil(t, m.BytesTransferredTotal)
	require.NotNil(t, m.RequestsTotal)
	require.NotNil(t, m.RequestDurationSeconds)
	require.NotNil(t, m.AuthAttemptsTotal)
	require.NotNil(t, m.P2PConnectionsTotal)
	require.NotNil(t, m.TunnelDurationSeconds)
}

func TestMetricsGaugeOperations(t *testing.T) {
	m := NewMetrics()

	// Test ActiveClients gauge.
	m.ActiveClients.Inc()
	m.ActiveClients.Inc()
	m.ActiveClients.Dec()

	// Test ActiveTunnels gauge.
	m.ActiveTunnels.Inc()
	m.ActiveTunnels.Inc()
	m.ActiveTunnels.Inc()
	m.ActiveTunnels.Dec()

	// Verify via Prometheus scrape endpoint.
	handler := promhttp.HandlerFor(m.Registry(), promhttp.HandlerOpts{})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	output := string(body)

	assert.Contains(t, output, "wormhole_active_clients 1")
	assert.Contains(t, output, "wormhole_active_tunnels 2")
}

func TestMetricsCounterOperations(t *testing.T) {
	m := NewMetrics()

	// Increment counters.
	m.ConnectionsTotal.Inc()
	m.ConnectionsTotal.Inc()
	m.BytesTransferredTotal.WithLabelValues("in").Add(1024)
	m.BytesTransferredTotal.WithLabelValues("out").Add(2048)
	m.RequestsTotal.WithLabelValues("http", "success").Inc()
	m.RequestsTotal.WithLabelValues("http", "error").Inc()
	m.RequestsTotal.WithLabelValues("http", "not_found").Inc()
	m.AuthAttemptsTotal.WithLabelValues("success").Inc()
	m.AuthAttemptsTotal.WithLabelValues("failure").Inc()
	m.AuthAttemptsTotal.WithLabelValues("failure").Inc()
	m.P2PConnectionsTotal.WithLabelValues("success").Inc()
	m.P2PConnectionsTotal.WithLabelValues("fallback").Inc()

	// Verify via Prometheus scrape.
	handler := promhttp.HandlerFor(m.Registry(), promhttp.HandlerOpts{})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	output := string(body)

	assert.Contains(t, output, "wormhole_connections_total 2")
	assert.Contains(t, output, `wormhole_bytes_transferred_total{direction="in"} 1024`)
	assert.Contains(t, output, `wormhole_bytes_transferred_total{direction="out"} 2048`)
	assert.Contains(t, output, `wormhole_requests_total{protocol="http",status="success"} 1`)
	assert.Contains(t, output, `wormhole_requests_total{protocol="http",status="error"} 1`)
	assert.Contains(t, output, `wormhole_auth_attempts_total{result="success"} 1`)
	assert.Contains(t, output, `wormhole_auth_attempts_total{result="failure"} 2`)
	assert.Contains(t, output, `wormhole_p2p_connections_total{result="success"} 1`)
	assert.Contains(t, output, `wormhole_p2p_connections_total{result="fallback"} 1`)
}

func TestMetricsHistogramOperations(t *testing.T) {
	m := NewMetrics()

	// Record some durations.
	m.RequestDurationSeconds.Observe(0.001)
	m.RequestDurationSeconds.Observe(0.05)
	m.RequestDurationSeconds.Observe(0.5)
	m.TunnelDurationSeconds.Observe(60)
	m.TunnelDurationSeconds.Observe(3600)

	// Verify via Prometheus scrape.
	handler := promhttp.HandlerFor(m.Registry(), promhttp.HandlerOpts{})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	output := string(body)

	assert.Contains(t, output, "wormhole_request_duration_seconds_count 3")
	assert.Contains(t, output, "wormhole_tunnel_duration_seconds_count 2")
}

func TestMetricsEndpointIntegration(t *testing.T) {
	m := NewMetrics()

	// Simulate some server activity.
	m.ActiveClients.Set(5)
	m.ActiveTunnels.Set(10)
	m.ConnectionsTotal.Add(100)
	m.BytesTransferredTotal.WithLabelValues("in").Add(1048576)
	m.BytesTransferredTotal.WithLabelValues("out").Add(2097152)
	m.RequestsTotal.WithLabelValues("http", "success").Add(500)
	m.RequestDurationSeconds.Observe(0.123)
	m.AuthAttemptsTotal.WithLabelValues("success").Add(50)
	m.P2PConnectionsTotal.WithLabelValues("success").Add(3)
	m.TunnelDurationSeconds.Observe(300)

	// Create an HTTP handler that mimics the admin API /metrics endpoint.
	handler := promhttp.HandlerFor(m.Registry(), promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	assert.Equal(t, http.StatusOK, rec.Code)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	output := string(body)

	// Verify all 9 metrics are present.
	expectedMetrics := []string{
		"wormhole_active_clients",
		"wormhole_active_tunnels",
		"wormhole_connections_total",
		"wormhole_bytes_transferred_total",
		"wormhole_requests_total",
		"wormhole_request_duration_seconds",
		"wormhole_auth_attempts_total",
		"wormhole_p2p_connections_total",
		"wormhole_tunnel_duration_seconds",
	}
	for _, name := range expectedMetrics {
		assert.True(t, strings.Contains(output, name), "missing metric: %s", name)
	}

	// Verify Go runtime metrics are included.
	assert.Contains(t, output, "go_goroutines")
	assert.Contains(t, output, "process_resident_memory_bytes")
}

func TestMetricsDisabled(t *testing.T) {
	// When EnableMetrics is false, NewServer should not initialize metrics.
	config := DefaultConfig()
	config.EnableMetrics = false

	s := NewServer(config)
	assert.Nil(t, s.metrics)
}

func TestMetricsEnabled(t *testing.T) {
	config := DefaultConfig()
	config.EnableMetrics = true

	s := NewServer(config)
	require.NotNil(t, s.metrics)
	require.NotNil(t, s.metrics.Registry())
}
