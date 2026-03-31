package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTLSManager(t *testing.T) {
	config := DefaultConfig()
	m := NewTLSManager(config)

	assert.NotNil(t, m)
	assert.Equal(t, config, m.config)
	assert.Nil(t, m.manager)
}

func TestTLSManager_TLSConfig_Disabled(t *testing.T) {
	config := DefaultConfig()
	config.TLSEnabled = false
	m := NewTLSManager(config)

	tlsConfig, err := m.TLSConfig()
	assert.NoError(t, err)
	assert.Nil(t, tlsConfig)
}

func TestTLSManager_TLSConfig_AutoTLS_InvalidDomain(t *testing.T) {
	config := DefaultConfig()
	config.TLSEnabled = true
	config.AutoTLS = true
	config.Domain = "localhost" // Invalid for Let's Encrypt.

	m := NewTLSManager(config)

	_, err := m.TLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "valid domain")
}

func TestTLSManager_TLSConfig_AutoTLS_EmptyDomain(t *testing.T) {
	config := DefaultConfig()
	config.TLSEnabled = true
	config.AutoTLS = true
	config.Domain = ""

	m := NewTLSManager(config)

	_, err := m.TLSConfig()
	assert.Error(t, err)
}

func TestTLSManager_TLSConfig_Manual_MissingCert(t *testing.T) {
	config := DefaultConfig()
	config.TLSEnabled = true
	config.AutoTLS = false
	config.TLSCertFile = ""
	config.TLSKeyFile = "/path/to/key.pem"

	m := NewTLSManager(config)

	_, err := m.TLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cert/key files not provided")
}

func TestTLSManager_TLSConfig_Manual_MissingKey(t *testing.T) {
	config := DefaultConfig()
	config.TLSEnabled = true
	config.AutoTLS = false
	config.TLSCertFile = "/path/to/cert.pem"
	config.TLSKeyFile = ""

	m := NewTLSManager(config)

	_, err := m.TLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cert/key files not provided")
}

func TestTLSManager_TLSConfig_Manual_InvalidFiles(t *testing.T) {
	config := DefaultConfig()
	config.TLSEnabled = true
	config.AutoTLS = false
	config.TLSCertFile = "/nonexistent/cert.pem"
	config.TLSKeyFile = "/nonexistent/key.pem"

	m := NewTLSManager(config)

	_, err := m.TLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load TLS cert")
}

func TestTLSManager_TLSConfig_Manual_ValidFiles(t *testing.T) {
	// Create temporary certificate files using Go's crypto packages.
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate a self-signed certificate for testing.
	generateTestCert(t, certFile, keyFile)

	config := DefaultConfig()
	config.TLSEnabled = true
	config.AutoTLS = false
	config.TLSCertFile = certFile
	config.TLSKeyFile = keyFile

	m := NewTLSManager(config)

	tlsConfig, err := m.TLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.Len(t, tlsConfig.Certificates, 1)
}

// generateTestCert generates a self-signed certificate for testing.
func generateTestCert(t *testing.T, certFile, keyFile string) {
	t.Helper()

	// Generate RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Certificate template.
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "example.com"},
	}

	// Create self-signed certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Write certificate.
	certOut, err := os.Create(certFile)
	require.NoError(t, err)
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(t, err)
	certOut.Close()

	// Write private key.
	keyOut, err := os.Create(keyFile)
	require.NoError(t, err)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	require.NoError(t, err)
	keyOut.Close()
}

func TestTLSManager_HTTPChallengeHandler_NoAutoTLS(t *testing.T) {
	config := DefaultConfig()
	config.TLSEnabled = false

	m := NewTLSManager(config)

	handler := m.HTTPChallengeHandler()
	assert.NotNil(t, handler)

	// Should redirect to HTTPS.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMovedPermanently, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "https://")
}

func TestRedirectToHTTPS(t *testing.T) {
	tests := []struct {
		url         string
		expectedLoc string
	}{
		{"http://example.com/", "https://example.com/"},
		{"http://example.com/path", "https://example.com/path"},
		{"http://example.com/path?query=1", "https://example.com/path?query=1"},
		{"http://sub.example.com:80/test", "https://sub.example.com:80/test"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			rec := httptest.NewRecorder()

			redirectToHTTPS(rec, req)

			assert.Equal(t, http.StatusMovedPermanently, rec.Code)
			assert.Equal(t, tt.expectedLoc, rec.Header().Get("Location"))
		})
	}
}

func TestTLSManager_CertCacheDir(t *testing.T) {
	config := DefaultConfig()
	m := NewTLSManager(config)

	cacheDir := m.certCacheDir()
	assert.NotEmpty(t, cacheDir)

	// Should contain "wormhole" and "certs".
	assert.Contains(t, cacheDir, "wormhole")
	assert.Contains(t, cacheDir, "certs")
}

func TestTLSManager_WrapListener_NoTLS(t *testing.T) {
	config := DefaultConfig()
	config.TLSEnabled = false

	m := NewTLSManager(config)

	// Create a real TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	wrapped := m.WrapListener(ln)

	// Should return the same listener (no TLS wrapping).
	assert.Equal(t, ln, wrapped)
}
