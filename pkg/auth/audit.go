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
	// EventClientConnected indicates a client connected.
	EventClientConnected AuditEventType = "client_connected"
	// EventClientDisconnected indicates a client disconnected.
	EventClientDisconnected AuditEventType = "client_disconnected"
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
	Error     string                 `json:"error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// AuditLogger logs authentication and authorization events.
type AuditLogger struct {
	writer  io.Writer
	mu      sync.Mutex
	enabled bool
}

// AuditLoggerConfig configures the audit logger.
type AuditLoggerConfig struct {
	// Enabled turns audit logging on or off.
	Enabled bool

	// Writer is the destination for audit logs (defaults to os.Stdout).
	Writer io.Writer
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(config AuditLoggerConfig) *AuditLogger {
	writer := config.Writer
	if writer == nil {
		writer = os.Stdout
	}

	return &AuditLogger{
		writer:  writer,
		enabled: config.Enabled,
	}
}

// Log writes an audit event to the log.
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

	// Encode as JSON and write.
	data, err := json.Marshal(event)
	if err != nil {
		return // Silently drop malformed events.
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
