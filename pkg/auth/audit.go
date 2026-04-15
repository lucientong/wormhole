package auth

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// AuditEventType represents the type of audit event.
type AuditEventType string

const (
	// EventAuthSuccess indicates successful authentication.
	EventAuthSuccess AuditEventType = "auth_success"
	// EventAuthFailure indicates failed authentication.
	EventAuthFailure AuditEventType = "auth_failure"
	// EventIPBlocked indicates an IP was blocked due to failures.
	EventIPBlocked AuditEventType = "ip_blocked"
	// EventIPUnblocked indicates an IP was manually unblocked.
	EventIPUnblocked AuditEventType = "ip_unblocked"
	// EventTokenGenerated indicates a new token was generated.
	EventTokenGenerated AuditEventType = "token_generated"
	// EventTokenRevoked indicates a token was revoked.
	EventTokenRevoked AuditEventType = "token_revoked"
	// EventTeamTokensRevoked indicates all tokens for a team were revoked.
	EventTeamTokensRevoked AuditEventType = "team_tokens_revoked" //nolint:gosec // audit event type string, not a credential
	// EventClientConnected indicates a client connected.
	EventClientConnected AuditEventType = "client_connected"
	// EventClientDisconnected indicates a client disconnected.
	EventClientDisconnected AuditEventType = "client_disconnected"
	// EventTunnelCreated indicates a tunnel was created.
	EventTunnelCreated AuditEventType = "tunnel_created"
	// EventTunnelClosed indicates a tunnel was closed.
	EventTunnelClosed AuditEventType = "tunnel_closed"
	// EventP2PEstablished indicates a P2P connection was established.
	EventP2PEstablished AuditEventType = "p2p_established"
	// EventP2PFallback indicates a P2P attempt fell back to relay.
	EventP2PFallback AuditEventType = "p2p_fallback"
)

// AuditEvent represents a single audit log entry.
type AuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Type      AuditEventType         `json:"type"`
	IP        string                 `json:"ip,omitempty"`
	TeamName  string                 `json:"team,omitempty"`
	Role      string                 `json:"role,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	Subdomain string                 `json:"subdomain,omitempty"`
	TunnelID  string                 `json:"tunnel_id,omitempty"`
	Protocol  string                 `json:"protocol,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// AuditLogger logs authentication and authorization events to a writer and
// optionally to a persistent AuditStore.
type AuditLogger struct {
	writer  io.Writer
	store   AuditStore
	mu      sync.Mutex
	enabled bool
}

// AuditLoggerConfig configures the audit logger.
type AuditLoggerConfig struct {
	// Enabled turns audit logging on or off.
	Enabled bool

	// Writer is the destination for JSON-line audit logs (defaults to os.Stdout).
	Writer io.Writer

	// Store is an optional persistent backend for structured queries.
	// When set, every logged event is also stored for later retrieval.
	Store AuditStore
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(config AuditLoggerConfig) *AuditLogger {
	writer := config.Writer
	if writer == nil {
		writer = os.Stdout
	}

	return &AuditLogger{
		writer:  writer,
		store:   config.Store,
		enabled: config.Enabled,
	}
}

// Log writes an audit event to the log writer and, when configured, to the store.
func (l *AuditLogger) Log(event AuditEvent) {
	if !l.enabled {
		return
	}

	// Ensure timestamp is set.
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Persist to store (non-blocking; errors are silently dropped to avoid
	// impacting the hot path).
	if l.store != nil {
		_ = l.store.Store(event)
	}

	// Encode as JSON and write to writer.
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	_, _ = l.writer.Write(data)
	_, _ = l.writer.Write([]byte("\n"))
}

// LogAuthSuccess logs a successful authentication event.
func (l *AuditLogger) LogAuthSuccess(ip, teamName string, role Role, sessionID, subdomain string) {
	l.Log(AuditEvent{
		Type:      EventAuthSuccess,
		IP:        ip,
		TeamName:  teamName,
		Role:      string(role),
		SessionID: sessionID,
		Subdomain: subdomain,
	})
}

// LogAuthFailure logs a failed authentication event.
func (l *AuditLogger) LogAuthFailure(ip, reason string) {
	l.Log(AuditEvent{
		Type:  EventAuthFailure,
		IP:    ip,
		Error: reason,
	})
}

// LogIPBlocked logs an IP blocking event.
func (l *AuditLogger) LogIPBlocked(ip string, failureCount int) {
	l.Log(AuditEvent{
		Type: EventIPBlocked,
		IP:   ip,
		Details: map[string]interface{}{
			"failure_count": failureCount,
		},
	})
}

// LogIPUnblocked logs an IP unblocking event.
func (l *AuditLogger) LogIPUnblocked(ip string, manual bool) {
	l.Log(AuditEvent{
		Type: EventIPUnblocked,
		IP:   ip,
		Details: map[string]interface{}{
			"manual": manual,
		},
	})
}

// LogTokenGenerated logs a token generation event.
func (l *AuditLogger) LogTokenGenerated(teamName string, role Role) {
	l.Log(AuditEvent{
		Type:     EventTokenGenerated,
		TeamName: teamName,
		Role:     string(role),
	})
}

// LogClientConnected logs a client connection event.
func (l *AuditLogger) LogClientConnected(ip, sessionID, subdomain, teamName string, role Role) {
	l.Log(AuditEvent{
		Type:      EventClientConnected,
		IP:        ip,
		SessionID: sessionID,
		Subdomain: subdomain,
		TeamName:  teamName,
		Role:      string(role),
	})
}

// LogClientDisconnected logs a client disconnection event.
func (l *AuditLogger) LogClientDisconnected(sessionID, subdomain string, duration time.Duration) {
	l.Log(AuditEvent{
		Type:      EventClientDisconnected,
		SessionID: sessionID,
		Subdomain: subdomain,
		Details: map[string]interface{}{
			"duration_seconds": duration.Seconds(),
		},
	})
}

// LogTokenRevoked logs a token revocation event.
func (l *AuditLogger) LogTokenRevoked(tokenID, teamName string) {
	l.Log(AuditEvent{
		Type:     EventTokenRevoked,
		TeamName: teamName,
		Details: map[string]interface{}{
			"token_id": tokenID,
		},
	})
}

// LogTeamTokensRevoked logs a team-level token revocation event.
func (l *AuditLogger) LogTeamTokensRevoked(teamName string) {
	l.Log(AuditEvent{
		Type:     EventTeamTokensRevoked,
		TeamName: teamName,
	})
}

// LogTunnelCreated logs a tunnel creation event.
func (l *AuditLogger) LogTunnelCreated(sessionID, tunnelID, protocol, publicURL string) {
	l.Log(AuditEvent{
		Type:      EventTunnelCreated,
		SessionID: sessionID,
		TunnelID:  tunnelID,
		Protocol:  protocol,
		Details: map[string]interface{}{
			"public_url": publicURL,
		},
	})
}

// LogTunnelClosed logs a tunnel closure event.
func (l *AuditLogger) LogTunnelClosed(sessionID, tunnelID, protocol, reason string) {
	l.Log(AuditEvent{
		Type:      EventTunnelClosed,
		SessionID: sessionID,
		TunnelID:  tunnelID,
		Protocol:  protocol,
		Details: map[string]interface{}{
			"reason": reason,
		},
	})
}

// LogP2PEstablished logs a successful P2P connection establishment.
func (l *AuditLogger) LogP2PEstablished(sessionID, peerAddr string) {
	l.Log(AuditEvent{
		Type:      EventP2PEstablished,
		SessionID: sessionID,
		Details: map[string]interface{}{
			"peer_addr": peerAddr,
		},
	})
}

// LogP2PFallback logs a P2P failure that caused relay fallback.
func (l *AuditLogger) LogP2PFallback(sessionID, reason string) {
	l.Log(AuditEvent{
		Type:      EventP2PFallback,
		SessionID: sessionID,
		Error:     reason,
	})
}

// IsEnabled returns whether audit logging is enabled.
func (l *AuditLogger) IsEnabled() bool {
	return l.enabled
}

// SetEnabled enables or disables audit logging.
func (l *AuditLogger) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// Store returns the underlying AuditStore, if any.
func (l *AuditLogger) Store() AuditStore {
	return l.store
}
