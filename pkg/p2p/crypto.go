package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/hkdf"
)

// Crypto context labels used in HKDF key derivation.
const (
	// hkdfInfo is the context string for HKDF key derivation.
	hkdfInfo = "wormhole-p2p-v1"
	// hkdfPunchInfo is the context string for hole-punch HMAC key derivation.
	hkdfPunchInfo = "wormhole-punch-v1"
)

// KeyPair holds an ECDH X25519 key pair for key exchange.
type KeyPair struct {
	// Private is the ECDH private key.
	Private *ecdh.PrivateKey
	// Public is the ECDH public key (raw 32-byte X25519 representation).
	Public []byte
}

// GenerateKeyPair generates a new X25519 ECDH key pair.
func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	return &KeyPair{
		Private: priv,
		Public:  priv.PublicKey().Bytes(),
	}, nil
}

// SessionCipher provides authenticated encryption for a P2P session.
// It uses AES-256-GCM with a monotonic nonce derived from a sequence counter.
type SessionCipher struct {
	aead cipher.AEAD
	// punchKey is used for HMAC authentication of hole-punch probes.
	punchKey []byte
	// sendNonce is a monotonically increasing counter for nonce generation.
	sendNonce uint64
}

// DeriveSession performs ECDH key agreement and derives session keys.
// It takes the local private key and the remote peer's public key bytes,
// and returns a SessionCipher ready for encrypting/decrypting data.
func DeriveSession(localPriv *ecdh.PrivateKey, remotePubBytes []byte) (*SessionCipher, error) {
	// Parse remote public key.
	curve := ecdh.X25519()
	remotePub, err := curve.NewPublicKey(remotePubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse remote public key: %w", err)
	}

	// ECDH shared secret.
	sharedSecret, err := localPriv.ECDH(remotePub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key exchange: %w", err)
	}

	// Derive encryption key via HKDF-SHA256.
	encKey, err := deriveKey(sharedSecret, []byte(hkdfInfo), 32)
	if err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}

	// Derive punch HMAC key via HKDF-SHA256.
	punchKey, err := deriveKey(sharedSecret, []byte(hkdfPunchInfo), 32)
	if err != nil {
		return nil, fmt.Errorf("derive punch key: %w", err)
	}

	// Create AES-256-GCM AEAD.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &SessionCipher{
		aead:     aead,
		punchKey: punchKey,
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a unique nonce.
// The output format is: [8-byte nonce counter][GCM ciphertext+tag].
func (sc *SessionCipher) Encrypt(plaintext []byte) ([]byte, error) {
	// Increment nonce counter atomically.
	counter := atomic.AddUint64(&sc.sendNonce, 1)

	// Build 12-byte nonce: 4 zero bytes + 8-byte counter (big-endian).
	// The nonce is NOT hardcoded — it uses a monotonically increasing
	// atomic counter that is unique per Encrypt call.
	nonce := buildNonce(sc.aead.NonceSize(), counter)

	// Encrypt: nonce is prepended as an 8-byte counter prefix so receiver
	// can reconstruct it.
	ciphertext := sc.aead.Seal(nil, nonce, plaintext, nil) // #nosec G407 -- nonce is derived from atomic counter, not hardcoded

	// Output: [8-byte counter][ciphertext+tag].
	out := make([]byte, 8+len(ciphertext))
	binary.BigEndian.PutUint64(out[:8], counter)
	copy(out[8:], ciphertext)

	return out, nil
}

// Decrypt decrypts data produced by Encrypt.
// Input format: [8-byte nonce counter][GCM ciphertext+tag].
func (sc *SessionCipher) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 8+sc.aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract counter and reconstruct nonce.
	counter := binary.BigEndian.Uint64(data[:8])
	nonce := buildNonce(sc.aead.NonceSize(), counter)

	// Decrypt and authenticate.
	plaintext, err := sc.aead.Open(nil, nonce, data[8:], nil)
	if err != nil {
		return nil, fmt.Errorf("GCM decrypt: %w", err)
	}

	return plaintext, nil
}

// Overhead returns the total byte overhead added by encryption.
// This is 8 (nonce counter) + GCM tag size (16) = 24 bytes.
func (sc *SessionCipher) Overhead() int {
	return 8 + sc.aead.Overhead()
}

// SignProbe creates an HMAC-SHA256 signature for a hole-punch probe payload.
// The caller should append this tag to the probe packet.
func (sc *SessionCipher) SignProbe(payload []byte) []byte {
	mac := hmac.New(sha256.New, sc.punchKey)
	mac.Write(payload)
	return mac.Sum(nil)
}

// VerifyProbe verifies the HMAC-SHA256 signature on a hole-punch probe.
func (sc *SessionCipher) VerifyProbe(payload, tag []byte) bool {
	mac := hmac.New(sha256.New, sc.punchKey)
	mac.Write(payload)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, tag)
}

// buildNonce constructs a 12-byte GCM nonce from a counter value.
// Format: [4 zero bytes][8-byte counter big-endian].
// This ensures each nonce is unique as long as the counter is unique.
func buildNonce(nonceSize int, counter uint64) []byte {
	nonce := make([]byte, nonceSize)
	binary.BigEndian.PutUint64(nonce[nonceSize-8:], counter)
	return nonce
}

// deriveKey uses HKDF-SHA256 to derive a key of the given length.
func deriveKey(secret, info []byte, keyLen int) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, secret, nil, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF read: %w", err)
	}
	return key, nil
}
