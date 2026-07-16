// Package auth provides authentication, authorization, and audit logging
// for Wormhole.
//
// # Token Modes
//
// Three ways to authenticate a client are supported, all producing the same
// [Claims] shape so the rest of the codebase never needs to know which mode
// issued a token:
//
//   - Simple Mode ([NewSimple]): tokens are plain strings compared against a
//     whitelist. Every match gets "default" team + [RoleMember]. Meant for
//     quick local setups, not multi-team deployments.
//   - HMAC Mode ([New] with [Config.Secret]): tokens are signed with a
//     shared secret and carry team, role, issued-at, expiration, and a random
//     nonce. Supports per-team token generation, refresh, and revocation.
//   - OIDC Mode ([Auth.SetOIDCValidator] + [NewOIDCValidator]): tokens are
//     standard JWTs validated against an OIDC provider's JWKS. [Auth.ValidateToken]
//     detects a JWT-shaped token automatically and routes it to the OIDC
//     validator instead of the HMAC path, so both modes can coexist on one
//     server (e.g. pre-shared tokens for CI, OIDC for humans). Role claims
//     can map to member/viewer by default; mapping to [RoleAdmin] requires
//     [OIDCClaimMapping.AllowAdminRole] to be enabled explicitly, so a
//     provider-side claim mistake cannot silently grant tunnel-layer admin.
//
// # SSO Login (Device Code Flow)
//
// [StartDeviceFlow] / [PollDeviceFlow] implement the OAuth2 Device
// Authorization Grant (RFC 8628) used by `wormhole login`: the CLI prints a
// verification URL, the user approves in a browser, and the CLI polls the
// token endpoint until the provider issues an access token. [RefreshAccessToken]
// exchanges a refresh token for a new access token without re-prompting the
// user. Discovery of the device/token endpoints happens via the standard
// OIDC discovery document, so only the issuer URL needs to be configured.
//
// Successful logins are persisted with [SaveCredentials] /
// [SaveCredentialsFull] to a per-server-address entry in a JSON file
// ([DefaultCredentialsPath], `~/.wormhole/credentials.json`), and later
// commands transparently pick them up via [LoadCredentials]. [Credentials.IsExpired]
// and [Credentials.CanRefresh] let callers (see `pkg/client`'s
// authenticateWithRefresh) decide whether to refresh before reconnecting.
//
// # Storage Backends
//
// Team records and revoked-token entries are abstracted behind the [Store]
// interface, with three interchangeable implementations: [MemoryStore]
// (default, lost on restart), [NewSQLiteStore] (single-node durability), and
// [NewRedisStore] (shared state across an HA cluster — see the server's
// `--persistence redis`). All three expire revocations lazily/via TTL rather
// than requiring an external cron job.
//
// # Audit Logging
//
// [AuditLogger] records structured lifecycle and security events (auth
// success/failure, IP blocking, tunnel create/close, P2P fallback, token
// revocation, ...) via typed convenience methods like [AuditLogger.LogAuthFailure]
// and [AuditLogger.LogP2PEstablished]. Events are persisted through an
// [AuditStore] — [NewMemoryAuditStore] (ring buffer) or [NewSQLiteAuditStore]
// — and are queryable/exportable (CSV/JSON) via the server's Admin API.
// A disabled logger ([AuditLoggerConfig.Enabled] = false) is a safe no-op,
// so call sites never need to branch on whether auditing is on.
//
// # Rate Limiting
//
// [RateLimiter] tracks authentication failures per source IP and temporarily
// blocks IPs that exceed a threshold ([RateLimiterStats], [RateLimiter.IsBlocked]),
// protecting the auth handshake from brute-force token guessing without
// needing an external WAF.
//
// # Usage
//
//	// HMAC mode, team-based
//	a, err := auth.New(auth.Config{
//	    Secret:      []byte("your-secret-key-at-least-16-bytes"),
//	    TokenExpiry: 24 * time.Hour,
//	})
//	token, err := a.GenerateTeamToken("team-name", auth.RoleMember)
//	claims, err := a.ValidateToken(token)
//	if err != nil {
//	    return err
//	}
//	if !auth.HasPermission(claims, auth.PermissionWrite) {
//	    return auth.ErrForbidden
//	}
//
//	// OIDC mode layered on top of the same Auth instance
//	v, err := auth.NewOIDCValidator(auth.OIDCConfig{
//	    Issuer:   "https://accounts.google.com",
//	    ClientID: "your-oauth-client-id",
//	})
//	a.SetOIDCValidator(v)
//
//	// Simple mode, no teams
//	a := auth.NewSimple([]string{"token-abc", "token-xyz"})
//	claims, err := a.ValidateToken("token-abc") // returns default/member claims.
package auth
