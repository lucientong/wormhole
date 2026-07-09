package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme/autocert"
)

// TLSManager manages TLS configuration and automatic certificate provisioning.
type TLSManager struct {
	config  Config
	manager *autocert.Manager
}

// NewTLSManager creates a new TLS manager from the server config.
func NewTLSManager(config Config) *TLSManager {
	return &TLSManager{config: config}
}

// TLSConfig returns a *tls.Config suitable for the HTTP server.
// It supports three modes:
//  1. AutoTLS with Let's Encrypt (when AutoTLS=true and Domain is set).
//  2. Manual TLS with provided cert/key files.
//  3. No TLS (returns nil).
func (m *TLSManager) TLSConfig() (*tls.Config, error) {
	if !m.config.TLSEnabled {
		return nil, nil //nolint:nilnil // nil means no TLS
	}

	// Auto TLS with Let's Encrypt.
	if m.config.AutoTLS {
		return m.autoTLSConfig()
	}

	// Manual TLS with cert/key files.
	return m.manualTLSConfig()
}

// autoTLSConfig sets up automatic certificate management via Let's Encrypt.
func (m *TLSManager) autoTLSConfig() (*tls.Config, error) {
	if m.config.Domain == "" || m.config.Domain == defaultDomain {
		return nil, fmt.Errorf("auto-TLS requires a valid domain (got %q)", m.config.Domain)
	}

	// Determine cache directory.
	cacheDir := m.certCacheDir()
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cert cache dir: %w", err)
	}

	m.manager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(
			m.config.Domain,
			"*."+m.config.Domain,
		),
		Cache: autocert.DirCache(cacheDir),
		Email: m.config.AutoTLSEmail,
	}

	tlsConfig := m.manager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12

	log.Info().
		Str("domain", m.config.Domain).
		Str("email", m.config.AutoTLSEmail).
		Str("cache_dir", cacheDir).
		Msg("Auto-TLS enabled with Let's Encrypt")

	return tlsConfig, nil
}

// manualTLSConfig loads TLS certificates from files.
func (m *TLSManager) manualTLSConfig() (*tls.Config, error) {
	if m.config.TLSCertFile == "" || m.config.TLSKeyFile == "" {
		return nil, fmt.Errorf("TLS enabled but cert/key files not provided")
	}

	cert, err := tls.LoadX509KeyPair(m.config.TLSCertFile, m.config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	log.Info().
		Str("cert", m.config.TLSCertFile).
		Str("key", m.config.TLSKeyFile).
		Msg("Manual TLS enabled")

	return tlsConfig, nil
}

// HTTPChallengeHandler returns an HTTP handler for ACME HTTP-01 challenges.
// This should be served on port 80 when using AutoTLS.
// Non-challenge requests are redirected to HTTPS.
func (m *TLSManager) HTTPChallengeHandler() http.Handler {
	if m.manager == nil {
		// No auto-TLS, just redirect to HTTPS.
		return http.HandlerFunc(redirectToHTTPS)
	}

	return m.manager.HTTPHandler(http.HandlerFunc(redirectToHTTPS))
}

// WrapListener wraps a net.Listener with TLS if configured.
func (m *TLSManager) WrapListener(ln net.Listener) net.Listener {
	tlsConfig, err := m.TLSConfig()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get TLS config, falling back to plain TCP")
		return ln
	}

	if tlsConfig == nil {
		return ln
	}

	return tls.NewListener(ln, tlsConfig)
}

// certCacheDir returns the directory for caching Let's Encrypt certificates.
func (m *TLSManager) certCacheDir() string {
	// Use /var/lib/wormhole/certs if running as root, otherwise ~/.wormhole/certs.
	if os.Getuid() == 0 {
		return "/var/lib/wormhole/certs"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ".wormhole/certs"
	}

	return filepath.Join(home, ".wormhole", "certs")
}

// validHostHeaderPattern matches a syntactically valid HTTP Host header:
// a DNS hostname or IPv4/IPv6 literal, optionally followed by ":<port>".
// It intentionally does not allow "/", "\", "@", control characters, etc.,
// which is what makes it safe to reflect into a redirect Location below.
var validHostHeaderPattern = regexp.MustCompile(`^[a-zA-Z0-9.\-\[\]:]+$`)

// redirectToHTTPS redirects HTTP requests to HTTPS on the same host.
//
// The target host always mirrors the Host the client already connected
// with, so this cannot be turned into a cross-domain open redirect: an
// attacker cannot make the server redirect somewhere other than the host
// they themselves dialed. We still validate the Host header's syntax
// before reflecting it (rather than trusting it blindly) so that
// malformed values — e.g. containing "/", "@", or control characters —
// can't be smuggled into the Location header at all.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !validHostHeaderPattern.MatchString(host) {
		http.Error(w, "invalid host header", http.StatusBadRequest)
		return
	}
	target := "https://" + host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently) // #nosec G710 -- host validated above; redirect target always mirrors the requested host, never an attacker-chosen different domain
}
