package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Sentinel errors for authentication.
var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrTokenExpired    = errors.New("token expired")
	ErrForbidden       = errors.New("forbidden")
	ErrTeamNotFound    = errors.New("team not found")
	ErrInvalidSecret   = errors.New("secret must be at least 16 bytes")
	ErrDuplicateTeam   = errors.New("team already exists")
	ErrInvalidTeamName = errors.New("invalid team name")
)

// Role represents a user role in the system.
type Role string

const (
	// RoleAdmin has full access including team management.
	RoleAdmin Role = "admin"
	// RoleMember can create tunnels and use the service.
	RoleMember Role = "member"
	// RoleViewer can only view tunnels and statistics.
	RoleViewer Role = "viewer"
)

// Permission represents an action that can be authorized.
type Permission string

const (
	// PermissionConnect allows establishing a tunnel connection.
	PermissionConnect Permission = "connect"
	// PermissionWrite allows creating and managing tunnels.
	PermissionWrite Permission = "write"
	// PermissionRead allows viewing tunnels and statistics.
	PermissionRead Permission = "read"
	// PermissionAdmin allows administrative operations.
	PermissionAdmin Permission = "admin"
)

// rolePermissions maps each role to its allowed permissions.
var rolePermissions = map[Role][]Permission{
	RoleAdmin:  {PermissionConnect, PermissionWrite, PermissionRead, PermissionAdmin},
	RoleMember: {PermissionConnect, PermissionWrite, PermissionRead},
	RoleViewer: {PermissionRead},
}

// Config holds the authentication configuration.
type Config struct {
	// Secret is the HMAC signing key (must be at least 16 bytes).
	Secret []byte

	// TokenExpiry is the default expiry duration for new tokens.
	TokenExpiry time.Duration

	// AllowedTokens is a list of pre-shared plain tokens (simple mode).
	// When set, these tokens bypass HMAC validation entirely.
	AllowedTokens []string
}

// Claims contains the validated token information.
type Claims struct {
	// TeamName is the team this token belongs to.
	TeamName string `json:"team"`
	// Role is the role assigned to this token.
	Role Role `json:"role"`
	// IssuedAt is when the token was issued.
	IssuedAt time.Time `json:"iat"`
	// ExpiresAt is when the token expires (zero means no expiry).
	ExpiresAt time.Time `json:"exp,omitempty"`
}

// tokenPayload is the internal structure embedded in the token.
type tokenPayload struct {
	TeamName  string `json:"team"`
	Role      Role   `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Nonce     string `json:"nonce"`
}

// TeamInfo stores metadata about a team.
type TeamInfo struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Tokens    int       `json:"tokens"` // Number of active tokens.
}

// Auth provides token-based authentication and authorization.
type Auth struct {
	config Config

	// teams stores team metadata (team name → info).
	teams map[string]*TeamInfo
	mu    sync.RWMutex
}

// New creates a new Auth instance.
func New(config Config) (*Auth, error) {
	// If HMAC mode is desired, validate the secret length.
	if len(config.AllowedTokens) == 0 && len(config.Secret) < 16 {
		return nil, ErrInvalidSecret
	}

	if config.TokenExpiry == 0 {
		config.TokenExpiry = 24 * time.Hour
	}

	return &Auth{
		config: config,
		teams:  make(map[string]*TeamInfo),
	}, nil
}

// NewSimple creates an Auth instance for simple pre-shared token mode.
// In this mode, tokens are compared directly against the allowed list.
func NewSimple(allowedTokens []string) *Auth {
	return &Auth{
		config: Config{
			AllowedTokens: allowedTokens,
		},
		teams: make(map[string]*TeamInfo),
	}
}

// GenerateTeamToken generates a new signed token for the given team and role.
func (a *Auth) GenerateTeamToken(teamName string, role Role) (string, error) {
	if teamName == "" {
		return "", ErrInvalidTeamName
	}
	if len(a.config.Secret) < 16 {
		return "", ErrInvalidSecret
	}

	nonce, err := generateNonce(16)
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	now := time.Now()
	payload := tokenPayload{
		TeamName: teamName,
		Role:     role,
		IssuedAt: now.Unix(),
		Nonce:    nonce,
	}
	if a.config.TokenExpiry > 0 {
		payload.ExpiresAt = now.Add(a.config.TokenExpiry).Unix()
	}

	// Encode payload to JSON.
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	// Base64-encode the payload.
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Compute HMAC-SHA256 signature.
	sig := computeHMAC(a.config.Secret, payloadJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// Token format: <payload>.<signature>
	token := payloadB64 + "." + sigB64

	// Track team.
	a.mu.Lock()
	if info, ok := a.teams[teamName]; ok {
		info.Tokens++
	} else {
		a.teams[teamName] = &TeamInfo{
			Name:      teamName,
			CreatedAt: now,
			Tokens:    1,
		}
	}
	a.mu.Unlock()

	return token, nil
}

// ValidateToken validates a token and returns its claims.
// It supports both HMAC-signed tokens and simple pre-shared tokens.
func (a *Auth) ValidateToken(token string) (*Claims, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}

	// Try simple pre-shared token mode first.
	if len(a.config.AllowedTokens) > 0 {
		for _, allowed := range a.config.AllowedTokens {
			if hmac.Equal([]byte(token), []byte(allowed)) {
				return &Claims{
					TeamName: "default",
					Role:     RoleMember,
					IssuedAt: time.Now(),
				}, nil
			}
		}
		// If only simple mode is configured, reject unmatched tokens.
		if len(a.config.Secret) < 16 {
			return nil, ErrInvalidToken
		}
	}

	// HMAC-signed token validation.
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidToken
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Decode signature.
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Verify HMAC signature.
	expectedSig := computeHMAC(a.config.Secret, payloadJSON)
	if !hmac.Equal(sig, expectedSig) {
		return nil, ErrInvalidToken
	}

	// Unmarshal payload.
	var payload tokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, ErrInvalidToken
	}

	// Check expiration.
	if payload.ExpiresAt > 0 {
		if time.Now().Unix() > payload.ExpiresAt {
			return nil, ErrTokenExpired
		}
	}

	claims := &Claims{
		TeamName: payload.TeamName,
		Role:     payload.Role,
		IssuedAt: time.Unix(payload.IssuedAt, 0),
	}
	if payload.ExpiresAt > 0 {
		claims.ExpiresAt = time.Unix(payload.ExpiresAt, 0)
	}

	return claims, nil
}

// HasPermission checks if the claims grant the specified permission.
func HasPermission(claims *Claims, perm Permission) bool {
	if claims == nil {
		return false
	}
	perms, ok := rolePermissions[claims.Role]
	if !ok {
		return false
	}
	return slices.Contains(perms, perm)
}

// RegisterTeam registers a team in the in-memory store.
func (a *Auth) RegisterTeam(name string) error {
	if name == "" {
		return ErrInvalidTeamName
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.teams[name]; ok {
		return ErrDuplicateTeam
	}

	a.teams[name] = &TeamInfo{
		Name:      name,
		CreatedAt: time.Now(),
	}
	return nil
}

// GetTeam returns team information.
func (a *Auth) GetTeam(name string) (*TeamInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	info, ok := a.teams[name]
	if !ok {
		return nil, ErrTeamNotFound
	}
	return info, nil
}

// ListTeams returns all registered teams.
func (a *Auth) ListTeams() []TeamInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()

	teams := make([]TeamInfo, 0, len(a.teams))
	for _, info := range a.teams {
		teams = append(teams, *info)
	}
	return teams
}

// computeHMAC computes an HMAC-SHA256 digest.
func computeHMAC(secret, data []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return mac.Sum(nil)
}

// generateNonce generates a cryptographically random nonce.
func generateNonce(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
