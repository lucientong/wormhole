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
