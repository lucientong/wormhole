package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OIDCConfig holds the OIDC provider configuration.
type OIDCConfig struct {
	// Issuer is the OIDC provider URL (e.g. "https://accounts.google.com").
	// The well-known configuration will be fetched from <Issuer>/.well-known/openid-configuration.
	Issuer string

	// ClientID is the OAuth2 client ID registered with the provider.
	ClientID string

	// Audience is the expected JWT audience claim.
	// Defaults to ClientID when empty.
	Audience string

	// ClaimMapping configures how OIDC claims are mapped to Wormhole roles.
	ClaimMapping OIDCClaimMapping
}

// OIDCClaimMapping configures the mapping of OIDC claims to Wormhole identity fields.
type OIDCClaimMapping struct {
	// TeamClaim is the JWT claim used as the Wormhole team name.
	// Defaults to "email" when empty.
	TeamClaim string

	// RoleClaim is an optional JWT claim for the Wormhole role.
	// Supports values: "admin", "member", "viewer".
	// When absent or unrecognized, DefaultRole is used.
	RoleClaim string

	// DefaultRole is the role assigned when RoleClaim is absent.
	// Defaults to RoleMember.
	DefaultRole Role
}

// OIDCValidator validates JWT tokens issued by an OIDC provider.
// It fetches the JWKS from the provider's discovery endpoint and caches the
// signing keys.  The cache is refreshed every 15 minutes or on key miss.
type OIDCValidator struct {
	config  OIDCConfig
	client  *http.Client
	jwksURL string

	mu       sync.RWMutex
	keyCache map[string]crypto.PublicKey // kid → public key
	cacheExp time.Time
}

const jwksCacheTTL = 15 * time.Minute

// NewOIDCValidator creates an OIDCValidator and performs the OIDC discovery.
func NewOIDCValidator(config OIDCConfig) (*OIDCValidator, error) {
	if config.Issuer == "" {
		return nil, errors.New("OIDC issuer is required")
	}
	if config.ClientID == "" {
		return nil, errors.New("OIDC client_id is required")
	}
	if config.Audience == "" {
		config.Audience = config.ClientID
	}
	if config.ClaimMapping.TeamClaim == "" {
		config.ClaimMapping.TeamClaim = "email"
	}
	if config.ClaimMapping.DefaultRole == "" {
		config.ClaimMapping.DefaultRole = RoleMember
	}

	v := &OIDCValidator{
		config:   config,
		client:   &http.Client{Timeout: 10 * time.Second},
		keyCache: make(map[string]crypto.PublicKey),
	}

	if err := v.discover(); err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	return v, nil
}

// discover fetches the OIDC well-known configuration.
func (v *OIDCValidator) discover() error {
	url := strings.TrimRight(v.config.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build well-known request: %w", err)
	}
	resp, err := v.client.Do(req) // #nosec G107 -- URL comes from trusted config
	if err != nil {
		return fmt.Errorf("fetch well-known config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("well-known endpoint returned HTTP %d", resp.StatusCode)
	}

	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return fmt.Errorf("decode well-known response: %w", err)
	}
	if discovery.JWKSURI == "" {
		return errors.New("well-known config missing jwks_uri")
	}

	v.jwksURL = discovery.JWKSURI
	return nil
}

// refreshKeys fetches and caches the current JWKS from the provider.
func (v *OIDCValidator) refreshKeys() error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build JWKS request: %w", err)
	}
	resp, err := v.client.Do(req) // #nosec G107 -- URL comes from trusted discovery
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read JWKS: %w", err)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	newCache := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, rawKey := range jwks.Keys {
		key, kid, err := parseJWK(rawKey)
		if err != nil {
			continue // Skip unrecognized key types.
		}
		newCache[kid] = key
	}

	v.mu.Lock()
	v.keyCache = newCache
	v.cacheExp = time.Now().Add(jwksCacheTTL)
	v.mu.Unlock()

	return nil
}

// getKey returns the public key for the given key ID.
// It refreshes the JWKS cache if necessary.
func (v *OIDCValidator) getKey(kid string) (crypto.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keyCache[kid]
	expired := time.Now().After(v.cacheExp)
	v.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	// Refresh JWKS.
	if err := v.refreshKeys(); err != nil {
		return nil, err
	}

	v.mu.RLock()
	key, ok = v.keyCache[kid]
	v.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no key found for kid=%q", kid)
	}
	return key, nil
}

// ValidateToken validates an OIDC JWT and returns Wormhole Claims.
func (v *OIDCValidator) ValidateToken(tokenStr string) (*Claims, error) {
	headerJSON, payloadJSON, sigBytes, signingInput, alg, kid, err := decodeJWTParts(tokenStr)
	if err != nil {
		return nil, err
	}

	pubKey, err := v.getKey(kid)
	if err != nil {
		return nil, fmt.Errorf("JWKS lookup: %w", err)
	}

	if err := verifyJWTSignature(alg, pubKey, []byte(signingInput), sigBytes); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %w", ErrInvalidToken, err)
	}

	return v.buildClaims(headerJSON, payloadJSON)
}

// decodeJWTParts splits and base64-decodes a JWT, returning the header JSON,
// payload JSON, signature bytes, signing input, algorithm, and key ID.
func decodeJWTParts(tokenStr string) (headerJSON, payloadJSON, sigBytes []byte, signingInput, alg, kid string, err error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, nil, nil, "", "", "", ErrInvalidToken
	}

	headerJSON, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, "", "", "", fmt.Errorf("%w: invalid JWT header encoding", ErrInvalidToken)
	}
	payloadJSON, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, "", "", "", fmt.Errorf("%w: invalid JWT payload encoding", ErrInvalidToken)
	}
	sigBytes, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, "", "", "", fmt.Errorf("%w: invalid JWT signature encoding", ErrInvalidToken)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if unmarshalErr := json.Unmarshal(headerJSON, &header); unmarshalErr != nil {
		return nil, nil, nil, "", "", "", fmt.Errorf("%w: cannot parse JWT header", ErrInvalidToken)
	}

	return headerJSON, payloadJSON, sigBytes, parts[0] + "." + parts[1], header.Alg, header.Kid, nil
}

// buildClaims validates the JWT payload against the validator's config and
// converts it to a Claims struct.
func (v *OIDCValidator) buildClaims(_, payloadJSON []byte) (*Claims, error) {
	var payload struct {
		Iss   string          `json:"iss"`
		Aud   json.RawMessage `json:"aud"`
		Sub   string          `json:"sub"`
		Exp   int64           `json:"exp"`
		Iat   int64           `json:"iat"`
		Email string          `json:"email"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("%w: cannot parse JWT payload", ErrInvalidToken)
	}

	if payload.Iss != v.config.Issuer {
		return nil, fmt.Errorf("%w: issuer mismatch (got %q, want %q)", ErrInvalidToken, payload.Iss, v.config.Issuer)
	}
	if !audienceContains(payload.Aud, v.config.Audience) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}
	if payload.Exp > 0 && time.Now().Unix() > payload.Exp {
		return nil, ErrTokenExpired
	}

	var rawClaims map[string]json.RawMessage
	_ = json.Unmarshal(payloadJSON, &rawClaims)

	teamName := extractStringClaim(rawClaims, v.config.ClaimMapping.TeamClaim)
	if teamName == "" {
		teamName = payload.Email
	}
	if teamName == "" {
		teamName = payload.Sub
	}

	role := mapRole(rawClaims, v.config.ClaimMapping)

	var expiresAt time.Time
	if payload.Exp > 0 {
		expiresAt = time.Unix(payload.Exp, 0)
	}

	return &Claims{
		TokenID:   payload.Sub,
		TeamName:  teamName,
		Role:      role,
		IssuedAt:  time.Unix(payload.Iat, 0),
		ExpiresAt: expiresAt,
	}, nil
}

// mapRole derives a Role from raw JWT claims using the configured claim mapping.
func mapRole(rawClaims map[string]json.RawMessage, mapping OIDCClaimMapping) Role {
	role := mapping.DefaultRole
	if mapping.RoleClaim == "" {
		return role
	}
	if roleName := extractStringClaim(rawClaims, mapping.RoleClaim); roleName != "" {
		switch Role(roleName) {
		case RoleAdmin, RoleMember, RoleViewer:
			role = Role(roleName)
		}
	}
	return role
}

// ─── Signature verification ───────────────────────────────────────────────────

// verifyJWTSignature verifies a JWT signature using the given algorithm and key.
func verifyJWTSignature(alg string, key crypto.PublicKey, signingInput, sig []byte) error {
	switch alg {
	case "RS256":
		sum := sha256.Sum256(signingInput)
		return verifyRSA(key, crypto.SHA256, sum[:], sig)
	case "RS384":
		sum := sha512.Sum384(signingInput)
		return verifyRSA(key, crypto.SHA384, sum[:], sig)
	case "RS512":
		sum := sha512.Sum512(signingInput)
		return verifyRSA(key, crypto.SHA512, sum[:], sig)
	case "ES256":
		return verifyECDSA(key, sha256.New(), signingInput, sig)
	case "ES384":
		return verifyECDSA(key, sha512.New384(), signingInput, sig)
	case "ES512":
		return verifyECDSA(key, sha512.New(), signingInput, sig)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func verifyRSA(key crypto.PublicKey, hash crypto.Hash, digest []byte, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("expected RSA public key")
	}
	return rsa.VerifyPKCS1v15(rsaKey, hash, digest, sig)
}

func verifyECDSA(key crypto.PublicKey, h hash.Hash, input, sig []byte) error {
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("expected ECDSA public key")
	}
	h.Write(input)
	digest := h.Sum(nil)

	// Parse the DER-style or raw (r||s) ECDSA signature.
	// RFC7518 ECDSA signatures are raw: r and s as fixed-size byte arrays.
	keyLen := (ecKey.Params().BitSize + 7) / 8
	if len(sig) != 2*keyLen {
		return fmt.Errorf("invalid ECDSA signature length: got %d, want %d", len(sig), 2*keyLen)
	}
	r := new(big.Int).SetBytes(sig[:keyLen])
	s := new(big.Int).SetBytes(sig[keyLen:])
	if !ecdsa.Verify(ecKey, digest, r, s) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

// ─── JWK parsing ─────────────────────────────────────────────────────────────

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA fields
	N string `json:"n"`
	E string `json:"e"`
	// EC fields
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWK(raw json.RawMessage) (crypto.PublicKey, string, error) {
	var k jwkKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", err
	}

	switch k.Kty {
	case "RSA":
		key, err := parseRSAJWK(k)
		return key, k.Kid, err
	case "EC":
		key, err := parseECJWK(k)
		return key, k.Kid, err
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

func parseRSAJWK(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("RSA e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	eInt := new(big.Int).SetBytes(eBytes)
	if !eInt.IsInt64() {
		return nil, errors.New("RSA exponent too large")
	}

	return &rsa.PublicKey{N: n, E: int(eInt.Int64())}, nil
}

func parseECJWK(k jwkKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("EC y: %w", err)
	}

	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func audienceContains(audJSON json.RawMessage, want string) bool {
	if len(audJSON) == 0 {
		return false
	}
	// Try array form.
	var audList []string
	if json.Unmarshal(audJSON, &audList) == nil {
		for _, a := range audList {
			if a == want {
				return true
			}
		}
		return false
	}
	// Try single string form.
	var audStr string
	if json.Unmarshal(audJSON, &audStr) == nil {
		return audStr == want
	}
	return false
}

func extractStringClaim(claims map[string]json.RawMessage, name string) string {
	raw, ok := claims[name]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}
