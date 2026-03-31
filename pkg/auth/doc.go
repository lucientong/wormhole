// Package auth provides authentication and authorization for Wormhole.
//
// The auth package implements team-based authentication using tokens and
// role-based access control for multi-user scenarios.
//
// # Features
//
//   - Team token generation and validation
//   - JWT-based session tokens
//   - Role-based permissions (admin, member, viewer)
//   - Token expiration and refresh
//
// # Token Types
//
//   - Team Token: Long-lived token for team identification
//   - Session Token: Short-lived JWT for authenticated sessions
//   - API Key: For programmatic access
//
// # Usage
//
//	auth := auth.New(auth.Config{
//	    Secret:      []byte("your-secret-key"),
//	    TokenExpiry: 24 * time.Hour,
//	})
//
//	// Generate team token
//	token, err := auth.GenerateTeamToken("team-name")
//
//	// Validate token
//	claims, err := auth.ValidateToken(token)
//	if err != nil {
//	    return err
//	}
//
//	// Check permission
//	if !auth.HasPermission(claims, auth.PermissionWrite) {
//	    return ErrForbidden
//	}
package auth
