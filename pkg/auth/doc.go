// Package auth provides authentication and authorization for Wormhole.
//
// The auth package implements team-based authentication using HMAC-SHA256
// tokens and role-based access control for multi-user scenarios.
//
// # Features
//
//   - Team token generation with HMAC-SHA256 signing
//   - Token validation (signature + expiration)
//   - Role-based permissions (admin, member, viewer)
//   - Simple pre-shared token mode for quick setup
//   - In-memory team management
//
// # Token Modes
//
// Two modes are supported:
//
//   - HMAC Mode: Tokens are signed with a secret key and include team, role,
//     issued-at, expiration, and a random nonce.
//   - Simple Mode: Tokens are plain strings compared against a whitelist.
//     All matched tokens get "default" team + "member" role.
//
// # Usage
//
//	// HMAC mode
//	a, err := auth.New(auth.Config{
//	    Secret:      []byte("your-secret-key-at-least-16-bytes"),
//	    TokenExpiry: 24 * time.Hour,
//	})
//
//	// Generate team token
//	token, err := a.GenerateTeamToken("team-name", auth.RoleMember)
//
//	// Validate token
//	claims, err := a.ValidateToken(token)
//	if err != nil {
//	    return err
//	}
//
//	// Check permission
//	if !auth.HasPermission(claims, auth.PermissionWrite) {
//	    return auth.ErrForbidden
//	}
//
//	// Simple mode
//	a := auth.NewSimple([]string{"token-abc", "token-xyz"})
//	claims, err := a.ValidateToken("token-abc") // returns default/member claims.
package auth
