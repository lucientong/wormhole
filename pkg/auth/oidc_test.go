package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

func testGenRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// testBuildJWT creates a signed RS256 JWT using the provided key.
func testBuildJWT(t *testing.T, key *rsa.PrivateKey, issuer, audience, subject string, extra map[string]interface{}, exp int64) string {
	t.Helper()

	hdr := map[string]string{"alg": "RS256", "kid": "key-1", "typ": "JWT"}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := map[string]interface{}{
		"iss": issuer,
		"aud": audience,
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": exp,
	}
	for k, v := range extra {
		payload[k] = v
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	sigInput := hdrB64 + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	require.NoError(t, err)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return sigInput + "." + sigB64
}

// testFakeOIDCServer starts a minimal OIDC server for the given RSA key.
func testFakeOIDCServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/.well-known/jwks.json",
		})
	})

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := &key.PublicKey
		nB64 := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{"kty": "RSA", "kid": "key-1", "alg": "RS256", "use": "sig", "n": nB64, "e": eB64},
			},
		})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestOIDCValidator_ValidToken(t *testing.T) {
	key := testGenRSAKey(t)
	srv := testFakeOIDCServer(t, key)

	v, err := NewOIDCValidator(OIDCConfig{
		Issuer:   srv.URL,
		ClientID: "my-client",
	})
	require.NoError(t, err)

	jwt := testBuildJWT(t, key, srv.URL, "my-client", "user@example.com", map[string]interface{}{
		"email": "user@example.com",
	}, time.Now().Add(1*time.Hour).Unix())

	claims, err := v.ValidateToken(jwt)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.TeamName)
	assert.Equal(t, RoleMember, claims.Role)
}

func TestOIDCValidator_ExpiredToken(t *testing.T) {
	key := testGenRSAKey(t)
	srv := testFakeOIDCServer(t, key)

	v, err := NewOIDCValidator(OIDCConfig{Issuer: srv.URL, ClientID: "my-client"})
	require.NoError(t, err)

	jwt := testBuildJWT(t, key, srv.URL, "my-client", "user@example.com", nil,
		time.Now().Add(-1*time.Hour).Unix())

	_, err = v.ValidateToken(jwt)
	require.ErrorIs(t, err, ErrTokenExpired)
}

func TestOIDCValidator_WrongIssuer(t *testing.T) {
	key := testGenRSAKey(t)
	srv := testFakeOIDCServer(t, key)

	v, err := NewOIDCValidator(OIDCConfig{Issuer: srv.URL, ClientID: "my-client"})
	require.NoError(t, err)

	jwt := testBuildJWT(t, key, "https://evil.example.com", "my-client", "user@example.com", nil,
		time.Now().Add(1*time.Hour).Unix())

	_, err = v.ValidateToken(jwt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer mismatch")
}

func TestOIDCValidator_WrongAudience(t *testing.T) {
	key := testGenRSAKey(t)
	srv := testFakeOIDCServer(t, key)

	v, err := NewOIDCValidator(OIDCConfig{Issuer: srv.URL, ClientID: "my-client"})
	require.NoError(t, err)

	jwt := testBuildJWT(t, key, srv.URL, "other-client", "user@example.com", nil,
		time.Now().Add(1*time.Hour).Unix())

	_, err = v.ValidateToken(jwt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestOIDCValidator_CustomRoleClaim(t *testing.T) {
	key := testGenRSAKey(t)
	srv := testFakeOIDCServer(t, key)

	v, err := NewOIDCValidator(OIDCConfig{
		Issuer:   srv.URL,
		ClientID: "my-client",
		ClaimMapping: OIDCClaimMapping{
			TeamClaim: "email",
			RoleClaim: "wormhole_role",
		},
	})
	require.NoError(t, err)

	jwt := testBuildJWT(t, key, srv.URL, "my-client", "admin@example.com", map[string]interface{}{
		"email":         "admin@example.com",
		"wormhole_role": "admin",
	}, time.Now().Add(1*time.Hour).Unix())

	claims, err := v.ValidateToken(jwt)
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, claims.Role)
	assert.Equal(t, "admin@example.com", claims.TeamName)
}

func TestOIDCValidator_NotAJWT(t *testing.T) {
	key := testGenRSAKey(t)
	srv := testFakeOIDCServer(t, key)

	v, err := NewOIDCValidator(OIDCConfig{Issuer: srv.URL, ClientID: "my-client"})
	require.NoError(t, err)

	_, err = v.ValidateToken("not-a-jwt")
	require.ErrorIs(t, err, ErrInvalidToken)
}

// ─── ECDSA (ES256) tests ──────────────────────────────────────────────────────

func testGenECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// testBuildES256JWT creates a signed ES256 JWT.
func testBuildES256JWT(t *testing.T, key *ecdsa.PrivateKey, kid, issuer, audience, subject string, exp int64) string {
	t.Helper()

	hdr := map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := map[string]interface{}{
		"iss":   issuer,
		"aud":   audience,
		"sub":   subject,
		"email": subject,
		"iat":   time.Now().Unix(),
		"exp":   exp,
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	sigInput := hdrB64 + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	require.NoError(t, err)

	// Encode signature as fixed-width big-endian R || S (64 bytes for P-256).
	rb := r.Bytes()
	sb := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)

	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// testFakeECOIDCServer starts a minimal OIDC discovery server serving an EC JWK.
func testFakeECOIDCServer(t *testing.T, key *ecdsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/.well-known/jwks.json",
		})
	})

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := &key.PublicKey
		xB64 := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
		yB64 := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{"kty": "EC", "kid": kid, "alg": "ES256", "use": "sig", "crv": "P-256", "x": xB64, "y": yB64},
			},
		})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOIDCValidator_ES256ValidToken(t *testing.T) {
	key := testGenECKey(t)
	kid := "ec-key-1"
	srv := testFakeECOIDCServer(t, key, kid)

	v, err := NewOIDCValidator(OIDCConfig{
		Issuer:   srv.URL,
		ClientID: "my-client",
	})
	require.NoError(t, err)

	jwt := testBuildES256JWT(t, key, kid, srv.URL, "my-client", "user@example.com",
		time.Now().Add(1*time.Hour).Unix())

	claims, err := v.ValidateToken(jwt)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.TeamName)
}

func TestOIDCValidator_ES384ValidToken(t *testing.T) {
	// Build a minimal ES384 JWT using P-384 key to cover sha512.New384 path.
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	kid := "ec384-key"

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/.well-known/jwks.json"})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := &ecKey.PublicKey
		xB64 := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
		yB64 := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{"kty": "EC", "kid": kid, "alg": "ES384", "use": "sig", "crv": "P-384", "x": xB64, "y": yB64},
			},
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Build ES384 JWT.
	hdr := map[string]string{"alg": "ES384", "kid": kid, "typ": "JWT"}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := map[string]interface{}{
		"iss": srv.URL, "aud": "cli", "sub": "u@x.com", "email": "u@x.com",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigInput := hdrB64 + "." + payloadB64

	h := sha512.New384()
	h.Write([]byte(sigInput))
	digest := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest)
	require.NoError(t, err)

	keyLen := 48 // P-384 = 48 bytes
	rb := r.Bytes()
	sb := s.Bytes()
	sig := make([]byte, 2*keyLen)
	copy(sig[keyLen-len(rb):keyLen], rb)
	copy(sig[2*keyLen-len(sb):], sb)
	jwt := sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	v, err := NewOIDCValidator(OIDCConfig{Issuer: srv.URL, ClientID: "cli"})
	require.NoError(t, err)
	claims, err := v.ValidateToken(jwt)
	require.NoError(t, err)
	assert.Equal(t, "u@x.com", claims.TeamName)
}

func TestAudienceContains_Array(t *testing.T) {
	raw := json.RawMessage(`["client1","client2"]`)
	assert.True(t, audienceContains(raw, "client1"))
	assert.True(t, audienceContains(raw, "client2"))
	assert.False(t, audienceContains(raw, "other"))
}

func TestAudienceContains_String(t *testing.T) {
	raw := json.RawMessage(`"single-client"`)
	assert.True(t, audienceContains(raw, "single-client"))
	assert.False(t, audienceContains(raw, "other"))
}

func TestAuthValidateToken_OIDCIntegration(t *testing.T) {
	key := testGenRSAKey(t)
	srv := testFakeOIDCServer(t, key)

	// Create a standard Auth with HMAC secret.
	a, err := New(Config{Secret: []byte("my-secret-key-32chars-xxxxxxxxxxxxxxxx")})
	require.NoError(t, err)

	// Attach OIDC validator.
	oidcV, err := NewOIDCValidator(OIDCConfig{Issuer: srv.URL, ClientID: "cli"})
	require.NoError(t, err)
	a.SetOIDCValidator(oidcV)

	jwt := testBuildJWT(t, key, srv.URL, "cli", "user@example.com", map[string]interface{}{
		"email": "user@example.com",
	}, time.Now().Add(1*time.Hour).Unix())

	claims, err := a.ValidateToken(jwt)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.TeamName)
}
