package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSecret is a valid 32-byte key for testing.
var testSecret = []byte("test-secret-key-0123456789abcdef")

func newTestAuth(t *testing.T) *Auth {
	t.Helper()
	a, err := New(Config{
		Secret:      testSecret,
		TokenExpiry: 1 * time.Hour,
	})
	require.NoError(t, err)
	return a
}

func TestNew_ValidConfig(t *testing.T) {
	a, err := New(Config{
		Secret:      testSecret,
		TokenExpiry: 24 * time.Hour,
	})
	require.NoError(t, err)
	assert.NotNil(t, a)
}

func TestNew_ShortSecret(t *testing.T) {
	_, err := New(Config{
		Secret: []byte("short"),
	})
	assert.ErrorIs(t, err, ErrInvalidSecret)
}

func TestNew_DefaultExpiry(t *testing.T) {
	a, err := New(Config{
		Secret: testSecret,
	})
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, a.config.TokenExpiry)
}

func TestNewSimple(t *testing.T) {
	a := NewSimple([]string{"token-abc", "token-xyz"})
	require.NotNil(t, a)
	assert.Len(t, a.config.AllowedTokens, 2)
}

func TestGenerateTeamToken(t *testing.T) {
	a := newTestAuth(t)

	token, err := a.GenerateTeamToken("my-team", RoleMember)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Token format: payload.signature
	parts := strings.SplitN(token, ".", 2)
	assert.Len(t, parts, 2)
}

func TestGenerateTeamToken_EmptyName(t *testing.T) {
	a := newTestAuth(t)
	_, err := a.GenerateTeamToken("", RoleMember)
	assert.ErrorIs(t, err, ErrInvalidTeamName)
}

func TestGenerateTeamToken_NoSecret(t *testing.T) {
	a := NewSimple([]string{"abc"})
	_, err := a.GenerateTeamToken("team", RoleMember)
	assert.ErrorIs(t, err, ErrInvalidSecret)
}

func TestValidateToken_HMAC(t *testing.T) {
	a := newTestAuth(t)

	token, err := a.GenerateTeamToken("team-alpha", RoleAdmin)
	require.NoError(t, err)

	claims, err := a.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "team-alpha", claims.TeamName)
	assert.Equal(t, RoleAdmin, claims.Role)
	assert.False(t, claims.IssuedAt.IsZero())
	assert.False(t, claims.ExpiresAt.IsZero())
}

func TestValidateToken_EmptyToken(t *testing.T) {
	a := newTestAuth(t)
	_, err := a.ValidateToken("")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_MalformedToken(t *testing.T) {
	a := newTestAuth(t)
	_, err := a.ValidateToken("not-a-real-token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_TamperedPayload(t *testing.T) {
	a := newTestAuth(t)

	token, err := a.GenerateTeamToken("team-alpha", RoleMember)
	require.NoError(t, err)

	// Tamper with the payload.
	parts := strings.SplitN(token, ".", 2)
	tampered := parts[0] + "X." + parts[1]
	_, err = a.ValidateToken(tampered)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_TamperedSignature(t *testing.T) {
	a := newTestAuth(t)

	token, err := a.GenerateTeamToken("team-alpha", RoleMember)
	require.NoError(t, err)

	// Tamper with the signature.
	parts := strings.SplitN(token, ".", 2)
	tampered := parts[0] + "." + parts[1] + "X"
	_, err = a.ValidateToken(tampered)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_WrongSecret(t *testing.T) {
	a1 := newTestAuth(t)
	a2, err := New(Config{
		Secret:      []byte("different-secret-0123456789abcde"),
		TokenExpiry: 1 * time.Hour,
	})
	require.NoError(t, err)

	token, err := a1.GenerateTeamToken("team-alpha", RoleMember)
	require.NoError(t, err)

	_, err = a2.ValidateToken(token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_Expired(t *testing.T) {
	a, err := New(Config{
		Secret:      testSecret,
		TokenExpiry: 1 * time.Second,
	})
	require.NoError(t, err)

	token, genErr := a.GenerateTeamToken("team-alpha", RoleMember)
	require.NoError(t, genErr)

	// Wait for token to expire (must exceed 1 full second for Unix-second resolution).
	time.Sleep(2 * time.Second)

	_, err = a.ValidateToken(token)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestValidateToken_SimpleMode(t *testing.T) {
	a := NewSimple([]string{"secret-abc", "secret-xyz"})

	// Valid token.
	claims, err := a.ValidateToken("secret-abc")
	require.NoError(t, err)
	assert.Equal(t, "default", claims.TeamName)
	assert.Equal(t, RoleMember, claims.Role)

	// Valid second token.
	claims, err = a.ValidateToken("secret-xyz")
	require.NoError(t, err)
	assert.Equal(t, "default", claims.TeamName)

	// Invalid token.
	_, err = a.ValidateToken("wrong-token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestHasPermission(t *testing.T) {
	tests := []struct {
		name   string
		role   Role
		perm   Permission
		expect bool
	}{
		{"admin can admin", RoleAdmin, PermissionAdmin, true},
		{"admin can write", RoleAdmin, PermissionWrite, true},
		{"admin can read", RoleAdmin, PermissionRead, true},
		{"admin can connect", RoleAdmin, PermissionConnect, true},
		{"member cannot admin", RoleMember, PermissionAdmin, false},
		{"member can write", RoleMember, PermissionWrite, true},
		{"member can read", RoleMember, PermissionRead, true},
		{"member can connect", RoleMember, PermissionConnect, true},
		{"viewer cannot admin", RoleViewer, PermissionAdmin, false},
		{"viewer cannot write", RoleViewer, PermissionWrite, false},
		{"viewer cannot connect", RoleViewer, PermissionConnect, false},
		{"viewer can read", RoleViewer, PermissionRead, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &Claims{Role: tt.role}
			assert.Equal(t, tt.expect, HasPermission(claims, tt.perm))
		})
	}
}

func TestHasPermission_NilClaims(t *testing.T) {
	assert.False(t, HasPermission(nil, PermissionRead))
}

func TestHasPermission_UnknownRole(t *testing.T) {
	claims := &Claims{Role: Role("unknown")}
	assert.False(t, HasPermission(claims, PermissionRead))
}

func TestRegisterTeam(t *testing.T) {
	a := newTestAuth(t)

	err := a.RegisterTeam("team-one")
	require.NoError(t, err)

	info, err := a.GetTeam("team-one")
	require.NoError(t, err)
	assert.Equal(t, "team-one", info.Name)
	assert.False(t, info.CreatedAt.IsZero())
}

func TestRegisterTeam_Duplicate(t *testing.T) {
	a := newTestAuth(t)

	err := a.RegisterTeam("team-one")
	require.NoError(t, err)

	err = a.RegisterTeam("team-one")
	assert.ErrorIs(t, err, ErrDuplicateTeam)
}

func TestRegisterTeam_Empty(t *testing.T) {
	a := newTestAuth(t)
	err := a.RegisterTeam("")
	assert.ErrorIs(t, err, ErrInvalidTeamName)
}

func TestGetTeam_NotFound(t *testing.T) {
	a := newTestAuth(t)
	_, err := a.GetTeam("nonexistent")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestListTeams(t *testing.T) {
	a := newTestAuth(t)

	_ = a.RegisterTeam("alpha")
	_ = a.RegisterTeam("beta")

	teams := a.ListTeams()
	assert.Len(t, teams, 2)

	names := make(map[string]bool)
	for _, team := range teams {
		names[team.Name] = true
	}
	assert.True(t, names["alpha"])
	assert.True(t, names["beta"])
}

func TestGenerateTeamToken_TracksTeam(t *testing.T) {
	a := newTestAuth(t)

	_, err := a.GenerateTeamToken("new-team", RoleMember)
	require.NoError(t, err)

	info, err := a.GetTeam("new-team")
	require.NoError(t, err)
	assert.Equal(t, 1, info.Tokens)

	// Second token increments count.
	_, err = a.GenerateTeamToken("new-team", RoleAdmin)
	require.NoError(t, err)

	info, err = a.GetTeam("new-team")
	require.NoError(t, err)
	assert.Equal(t, 2, info.Tokens)
}

func TestAllRoles(t *testing.T) {
	a := newTestAuth(t)

	roles := []Role{RoleAdmin, RoleMember, RoleViewer}
	for _, role := range roles {
		token, err := a.GenerateTeamToken("team", role)
		require.NoError(t, err)

		claims, err := a.ValidateToken(token)
		require.NoError(t, err)
		assert.Equal(t, role, claims.Role)
	}
}

func TestRevokeToken(t *testing.T) {
	a := newTestAuth(t)

	// Generate a token.
	token, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)

	// Validate it works.
	claims, err := a.ValidateToken(token)
	require.NoError(t, err)
	assert.NotEmpty(t, claims.TokenID)

	// Revoke the token.
	err = a.RevokeToken(claims.TokenID, claims.ExpiresAt)
	require.NoError(t, err)

	// Validate should now fail.
	_, err = a.ValidateToken(token)
	assert.ErrorIs(t, err, ErrTokenRevoked)
}

func TestRevokeToken_EmptyID(t *testing.T) {
	a := newTestAuth(t)

	err := a.RevokeToken("", time.Now())
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestRevokeTokenByString(t *testing.T) {
	a := newTestAuth(t)

	// Generate a token.
	token, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)

	// Revoke using the token string.
	err = a.RevokeTokenByString(token)
	require.NoError(t, err)

	// Validate should now fail.
	_, err = a.ValidateToken(token)
	assert.ErrorIs(t, err, ErrTokenRevoked)
}

func TestRevokeTokenByString_InvalidToken(t *testing.T) {
	a := newTestAuth(t)

	err := a.RevokeTokenByString("invalid-token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestIsRevoked(t *testing.T) {
	a := newTestAuth(t)

	// Generate a token.
	token, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)

	claims, err := a.ValidateToken(token)
	require.NoError(t, err)

	// Initially not revoked.
	assert.False(t, a.IsRevoked(claims.TokenID))

	// Revoke it.
	err = a.RevokeToken(claims.TokenID, time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	// Now revoked.
	assert.True(t, a.IsRevoked(claims.TokenID))

	// Empty ID should return false.
	assert.False(t, a.IsRevoked(""))
}

func TestUnrevokeToken(t *testing.T) {
	a := newTestAuth(t)

	// Generate and revoke a token.
	token, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)

	claims, err := a.ValidateToken(token)
	require.NoError(t, err)

	err = a.RevokeToken(claims.TokenID, time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	// Verify it's revoked.
	_, err = a.ValidateToken(token)
	assert.ErrorIs(t, err, ErrTokenRevoked)

	// Unrevoke it.
	a.UnrevokeToken(claims.TokenID)

	// Now it should work again.
	_, err = a.ValidateToken(token)
	require.NoError(t, err)
}

func TestCleanupRevokedTokens(t *testing.T) {
	a := newTestAuth(t)

	// Revoke a token that "expired" in the past.
	err := a.RevokeToken("expired-token", time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	// Revoke a token that expires in the future.
	err = a.RevokeToken("future-token", time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	// Revoke a permanent token (zero time).
	err = a.RevokeToken("permanent-token", time.Time{})
	require.NoError(t, err)

	assert.Equal(t, 3, a.RevokedTokenCount())

	// Cleanup should remove only the expired one.
	cleaned := a.CleanupRevokedTokens()
	assert.Equal(t, 1, cleaned)
	assert.Equal(t, 2, a.RevokedTokenCount())

	// Verify correct tokens remain.
	assert.False(t, a.IsRevoked("expired-token"))
	assert.True(t, a.IsRevoked("future-token"))
	assert.True(t, a.IsRevoked("permanent-token"))
}

func TestRevokedTokenCount(t *testing.T) {
	a := newTestAuth(t)

	assert.Equal(t, 0, a.RevokedTokenCount())

	err := a.RevokeToken("token1", time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, a.RevokedTokenCount())

	err = a.RevokeToken("token2", time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 2, a.RevokedTokenCount())

	a.UnrevokeToken("token1")
	assert.Equal(t, 1, a.RevokedTokenCount())
}

func TestTokenID_InClaims(t *testing.T) {
	a := newTestAuth(t)

	token, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)

	claims, err := a.ValidateToken(token)
	require.NoError(t, err)

	// Token ID should be present and non-empty.
	assert.NotEmpty(t, claims.TokenID)
	// Token ID should be unique per token.
	token2, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)
	claims2, err := a.ValidateToken(token2)
	require.NoError(t, err)
	assert.NotEqual(t, claims.TokenID, claims2.TokenID)
}

func TestRevokeAllTeamTokens_NotImplemented(t *testing.T) {
	a := newTestAuth(t)

	err := a.RevokeAllTeamTokens("team1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestRefreshToken(t *testing.T) {
	a := newTestAuth(t)

	// Generate original token.
	originalToken, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)

	originalClaims, err := a.ValidateToken(originalToken)
	require.NoError(t, err)

	// Sleep briefly to ensure different issuance time.
	time.Sleep(10 * time.Millisecond)

	// Refresh the token.
	newToken, err := a.RefreshToken(originalToken)
	require.NoError(t, err)
	assert.NotEqual(t, originalToken, newToken)

	// Validate new token.
	newClaims, err := a.ValidateToken(newToken)
	require.NoError(t, err)

	// Same team and role.
	assert.Equal(t, originalClaims.TeamName, newClaims.TeamName)
	assert.Equal(t, originalClaims.Role, newClaims.Role)

	// Different token IDs.
	assert.NotEqual(t, originalClaims.TokenID, newClaims.TokenID)

	// New issuance time.
	assert.True(t, newClaims.IssuedAt.After(originalClaims.IssuedAt) ||
		newClaims.IssuedAt.Equal(originalClaims.IssuedAt))

	// Original token should still work (not revoked).
	_, err = a.ValidateToken(originalToken)
	require.NoError(t, err)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	a := newTestAuth(t)

	_, err := a.RefreshToken("invalid-token")
	assert.Error(t, err)
}

func TestRefreshAndRevokeToken(t *testing.T) {
	a := newTestAuth(t)

	// Generate original token.
	originalToken, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)

	originalClaims, err := a.ValidateToken(originalToken)
	require.NoError(t, err)

	// Refresh and revoke.
	newToken, err := a.RefreshAndRevokeToken(originalToken)
	require.NoError(t, err)
	assert.NotEqual(t, originalToken, newToken)

	// New token should work.
	newClaims, err := a.ValidateToken(newToken)
	require.NoError(t, err)
	assert.Equal(t, originalClaims.TeamName, newClaims.TeamName)
	assert.Equal(t, originalClaims.Role, newClaims.Role)

	// Original token should be revoked.
	_, err = a.ValidateToken(originalToken)
	assert.ErrorIs(t, err, ErrTokenRevoked)
}

func TestRefreshAndRevokeToken_InvalidToken(t *testing.T) {
	a := newTestAuth(t)

	_, err := a.RefreshAndRevokeToken("invalid-token")
	assert.Error(t, err)
}

func TestExtendTokenExpiry(t *testing.T) {
	a, err := New(Config{
		Secret:      testSecret,
		TokenExpiry: 1 * time.Hour,
	})
	require.NoError(t, err)

	// Generate original token.
	originalToken, err := a.GenerateTeamToken("team1", RoleMember)
	require.NoError(t, err)

	originalClaims, err := a.ValidateToken(originalToken)
	require.NoError(t, err)
	assert.False(t, originalClaims.ExpiresAt.IsZero())

	// Extend by 24 hours.
	newToken, err := a.ExtendTokenExpiry(originalToken, 24*time.Hour)
	require.NoError(t, err)
	assert.NotEqual(t, originalToken, newToken)

	// Validate new token has extended expiry.
	newClaims, err := a.ValidateToken(newToken)
	require.NoError(t, err)

	// New expiry should be later than original.
	assert.True(t, newClaims.ExpiresAt.After(originalClaims.ExpiresAt))

	// The extension should be approximately 24 hours from now (not from original expiry).
	expectedExpiry := time.Now().Add(time.Until(originalClaims.ExpiresAt) + 24*time.Hour)
	assert.WithinDuration(t, expectedExpiry, newClaims.ExpiresAt, 5*time.Second)
}

func TestExtendTokenExpiry_InvalidToken(t *testing.T) {
	a := newTestAuth(t)

	_, err := a.ExtendTokenExpiry("invalid-token", 1*time.Hour)
	assert.Error(t, err)
}
