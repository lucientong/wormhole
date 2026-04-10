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
	ErrTokenRevoked    = errors.New("token revoked")
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

	// Store is the storage backend for teams and revoked tokens.
	// If nil, a MemoryStore is used (no persistence).
	Store Store
}

// Claims contains the validated token information.
type Claims struct {
	// TokenID is the unique identifier for this token.
	TokenID string `json:"jti,omitempty"`
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
	TokenID   string `json:"jti,omitempty"`
	TeamName  string `json:"team"`
	Role      Role   `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Version   int64  `json:"ver,omitempty"`
	Nonce     string `json:"nonce"`
}

// TeamInfo stores metadata about a team.
type TeamInfo struct {
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"created_at"`
	Tokens         int       `json:"tokens"`          // Number of active tokens.
	RevokedVersion int64     `json:"revoked_version"` // Minimum valid token version.
}

// Auth provides token-based authentication and authorization.
type Auth struct {
	config Config

	// store is the storage backend for teams and revoked tokens.
	store Store

	mu sync.RWMutex
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

	// Use provided store or default to memory.
	store := config.Store
	if store == nil {
		store = NewMemoryStore()
	}

	return &Auth{
		config: config,
		store:  store,
	}, nil
}

// NewSimple creates an Auth instance for simple pre-shared token mode.
// In this mode, tokens are compared directly against the allowed list.
func NewSimple(allowedTokens []string) *Auth {
	return &Auth{
		config: Config{
			AllowedTokens: allowedTokens,
		},
		store: NewMemoryStore(),
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

	// Generate a unique token ID.
	tokenID, err := generateNonce(12)
	if err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}

	now := time.Now()

	// Determine the token version from the current team revoked version.
	a.mu.RLock()
	var tokenVersion int64
	if info, teamErr := a.store.GetTeam(teamName); teamErr == nil {
		tokenVersion = info.RevokedVersion + 1
	} else {
		tokenVersion = 1
	}
	a.mu.RUnlock()

	payload := tokenPayload{
		TokenID:  tokenID,
		TeamName: teamName,
		Role:     role,
		IssuedAt: now.Unix(),
		Version:  tokenVersion,
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
	info, err := a.store.GetTeam(teamName)
	switch {
	case errors.Is(err, ErrTeamNotFound):
		info = &TeamInfo{
			Name:      teamName,
			CreatedAt: now,
			Tokens:    1,
		}
	case err == nil:
		info.Tokens++
	default:
	}
	if err == nil || errors.Is(err, ErrTeamNotFound) {
		_ = a.store.SaveTeam(info)
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
	if claims := a.checkPreSharedToken(token); claims != nil {
		return claims, nil
	}

	// If only simple mode is configured (no HMAC secret), reject unmatched tokens.
	if len(a.config.AllowedTokens) > 0 && len(a.config.Secret) < 16 {
		return nil, ErrInvalidToken
	}

	// HMAC-signed token validation.
	return a.validateHMACToken(token)
}

// checkPreSharedToken checks if the token matches any pre-shared allowed token.
func (a *Auth) checkPreSharedToken(token string) *Claims {
	for _, allowed := range a.config.AllowedTokens {
		if hmac.Equal([]byte(token), []byte(allowed)) {
			return &Claims{
				TeamName: "default",
				Role:     RoleMember,
				IssuedAt: time.Now(),
			}
		}
	}
	return nil
}

// validateHMACToken validates an HMAC-signed token.
func (a *Auth) validateHMACToken(token string) (*Claims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidToken
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// Decode and verify signature.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	expectedSig := computeHMAC(a.config.Secret, payloadJSON)
	if !hmac.Equal(sig, expectedSig) {
		return nil, ErrInvalidToken
	}

	// Unmarshal and validate payload.
	var payload tokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, ErrInvalidToken
	}

	if err := a.validatePayload(&payload); err != nil {
		return nil, err
	}

	return a.payloadToClaims(&payload), nil
}

// validatePayload checks expiration, revocation status, and team version.
func (a *Auth) validatePayload(payload *tokenPayload) error {
	// Check expiration.
	if payload.ExpiresAt > 0 && time.Now().Unix() > payload.ExpiresAt {
		return ErrTokenExpired
	}

	// Check if token is individually revoked.
	if payload.TokenID != "" {
		revoked, err := a.store.IsTokenRevoked(payload.TokenID)
		if err == nil && revoked {
			return ErrTokenRevoked
		}
	}

	// Check team-level revocation version.
	if payload.TeamName != "" && payload.Version > 0 {
		if info, err := a.store.GetTeam(payload.TeamName); err == nil {
			if payload.Version <= info.RevokedVersion {
				return ErrTokenRevoked
			}
		}
	}

	return nil
}

// payloadToClaims converts a token payload to claims.
func (a *Auth) payloadToClaims(payload *tokenPayload) *Claims {
	claims := &Claims{
		TokenID:  payload.TokenID,
		TeamName: payload.TeamName,
		Role:     payload.Role,
		IssuedAt: time.Unix(payload.IssuedAt, 0),
	}
	if payload.ExpiresAt > 0 {
		claims.ExpiresAt = time.Unix(payload.ExpiresAt, 0)
	}
	return claims
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

// RegisterTeam registers a team in the store.
func (a *Auth) RegisterTeam(name string) error {
	if name == "" {
		return ErrInvalidTeamName
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if team already exists.
	if _, err := a.store.GetTeam(name); err == nil {
		return ErrDuplicateTeam
	}

	return a.store.SaveTeam(&TeamInfo{
		Name:      name,
		CreatedAt: time.Now(),
	})
}

// GetTeam returns team information.
func (a *Auth) GetTeam(name string) (*TeamInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.store.GetTeam(name)
}

// ListTeams returns all registered teams.
func (a *Auth) ListTeams() []TeamInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()

	teams, err := a.store.ListTeams()
	if err != nil {
		return nil
	}
	return teams
}

// RevokeToken adds a token ID to the revocation blacklist.
// The expiresAt parameter indicates when the token would have expired;
// after that time, the revocation entry can be cleaned up.
// If expiresAt is zero, the revocation is permanent until manually cleared.
func (a *Auth) RevokeToken(tokenID string, expiresAt time.Time) error {
	if tokenID == "" {
		return ErrInvalidToken
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	return a.store.SaveRevokedToken(tokenID, expiresAt)
}

// RevokeTokenByString parses a token string and revokes it by ID.
// Returns ErrInvalidToken if the token cannot be parsed or has no ID.
func (a *Auth) RevokeTokenByString(token string) error {
	claims, err := a.ValidateToken(token)
	if err != nil && !errors.Is(err, ErrTokenRevoked) {
		// Allow revoking already-revoked tokens (idempotent).
		return err
	}

	if claims == nil || claims.TokenID == "" {
		return ErrInvalidToken
	}

	return a.RevokeToken(claims.TokenID, claims.ExpiresAt)
}

// IsRevoked checks if a token ID is in the revocation blacklist.
func (a *Auth) IsRevoked(tokenID string) bool {
	if tokenID == "" {
		return false
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	revoked, err := a.store.IsTokenRevoked(tokenID)
	return err == nil && revoked
}

// UnrevokeToken removes a token ID from the revocation blacklist.
func (a *Auth) UnrevokeToken(tokenID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	_ = a.store.RemoveRevokedToken(tokenID)
}

// CleanupRevokedTokens removes expired entries from the revocation blacklist.
// This should be called periodically to prevent the blacklist from growing unbounded.
func (a *Auth) CleanupRevokedTokens() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	cleaned, err := a.store.CleanupExpiredRevocations()
	if err != nil {
		return 0
	}
	return cleaned
}

// RevokedTokenCount returns the number of tokens in the revocation blacklist.
func (a *Auth) RevokedTokenCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	count, err := a.store.CountRevokedTokens()
	if err != nil {
		return 0
	}
	return count
}

// RevokeAllTeamTokens invalidates all existing tokens for a team by incrementing
// the team's revoked version. Any token whose version is less than or equal to
// the new revoked version will be rejected during validation.
// Returns ErrTeamNotFound if the team does not exist.
func (a *Auth) RevokeAllTeamTokens(teamName string) error {
	if teamName == "" {
		return ErrInvalidTeamName
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	info, err := a.store.GetTeam(teamName)
	if err != nil {
		return err
	}

	// Increment the revoked version. All tokens with version <= this value
	// will be considered revoked.
	info.RevokedVersion++

	return a.store.SaveTeam(info)
}

// RefreshToken generates a new token with the same claims as the original,
// but with a fresh issuance time and expiry. The original token is NOT revoked.
// Use RevokeToken to invalidate the old token if desired.
func (a *Auth) RefreshToken(token string) (string, error) {
	claims, err := a.ValidateToken(token)
	if err != nil {
		return "", err
	}

	// Generate a new token with the same team and role.
	return a.GenerateTeamToken(claims.TeamName, claims.Role)
}

// RefreshAndRevokeToken generates a new token and revokes the old one atomically.
// This is the recommended way to refresh tokens when rotation is desired.
func (a *Auth) RefreshAndRevokeToken(oldToken string) (string, error) {
	claims, err := a.ValidateToken(oldToken)
	if err != nil {
		return "", err
	}

	// Generate a new token first.
	newToken, err := a.GenerateTeamToken(claims.TeamName, claims.Role)
	if err != nil {
		return "", err
	}

	// Revoke the old token (if it has an ID).
	if claims.TokenID != "" {
		if err := a.RevokeToken(claims.TokenID, claims.ExpiresAt); err != nil {
			// Log but don't fail — the new token is already generated.
			// In a production system, you might want to handle this differently.
			_ = err
		}
	}

	return newToken, nil
}

// ExtendTokenExpiry creates a new token with an extended expiry time.
// The original token is NOT revoked.
func (a *Auth) ExtendTokenExpiry(token string, extension time.Duration) (string, error) {
	claims, err := a.ValidateToken(token)
	if err != nil {
		return "", err
	}

	// Temporarily override the config expiry to extend.
	originalExpiry := a.config.TokenExpiry
	if !claims.ExpiresAt.IsZero() {
		// Extend from the original expiry time.
		remaining := time.Until(claims.ExpiresAt)
		a.config.TokenExpiry = remaining + extension
	} else {
		// Token had no expiry, set one now.
		a.config.TokenExpiry = extension
	}

	newToken, err := a.GenerateTeamToken(claims.TeamName, claims.Role)

	// Restore original config.
	a.config.TokenExpiry = originalExpiry

	return newToken, err
}

// Close releases any resources held by the Auth instance.
// This should be called when the Auth instance is no longer needed.
func (a *Auth) Close() error {
	return a.store.Close()
}

// Store returns the underlying storage backend.
// This is useful for advanced operations or testing.
func (a *Auth) Store() Store {
	return a.store
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
