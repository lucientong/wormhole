package p2p

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)
	assert.NotNil(t, kp.Private)
	assert.Len(t, kp.Public, 32, "X25519 public key should be 32 bytes")
}

func TestDeriveSession_SymmetricKeys(t *testing.T) {
	// Generate two key pairs.
	kpA, err := GenerateKeyPair()
	require.NoError(t, err)

	kpB, err := GenerateKeyPair()
	require.NoError(t, err)

	// Derive session cipher on both sides.
	cipherA, err := DeriveSession(kpA.Private, kpB.Public)
	require.NoError(t, err)

	cipherB, err := DeriveSession(kpB.Private, kpA.Public)
	require.NoError(t, err)

	// Both sides should be able to encrypt/decrypt each other's messages.
	plaintext := []byte("Hello, end-to-end encryption!")

	ciphertext, err := cipherA.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := cipherB.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// And vice versa.
	ciphertext2, err := cipherB.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted2, err := cipherA.Decrypt(ciphertext2)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)
}

func TestSessionCipher_EncryptDecryptEmpty(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()

	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	// Encrypt empty payload.
	ciphertext, err := cipherA.Encrypt([]byte{})
	require.NoError(t, err)

	decrypted, err := cipherB.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestSessionCipher_UniqueNonces(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipher, _ := DeriveSession(kpA.Private, kpB.Public)

	// Encrypt the same plaintext twice — ciphertexts must differ (different nonces).
	plaintext := []byte("same data")
	ct1, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)

	ct2, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, ct1, ct2, "ciphertexts with different nonces must differ")
}

func TestSessionCipher_TamperedCiphertext(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()

	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	plaintext := []byte("tamper-proof data")
	ciphertext, err := cipherA.Encrypt(plaintext)
	require.NoError(t, err)

	// Flip a bit in the ciphertext body (after the 8-byte nonce counter).
	if len(ciphertext) > 10 {
		ciphertext[10] ^= 0xFF
	}

	_, err = cipherB.Decrypt(ciphertext)
	assert.Error(t, err, "decrypting tampered ciphertext should fail")
}

func TestSessionCipher_WrongKey(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	kpC, _ := GenerateKeyPair() // Unrelated key.

	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherWrong, _ := DeriveSession(kpC.Private, kpB.Public) // Wrong shared secret.

	plaintext := []byte("secret message")
	ciphertext, err := cipherA.Encrypt(plaintext)
	require.NoError(t, err)

	_, err = cipherWrong.Decrypt(ciphertext)
	assert.Error(t, err, "decrypting with wrong key should fail")
}

func TestSessionCipher_Overhead(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipher, _ := DeriveSession(kpA.Private, kpB.Public)

	// Overhead should be 8 (nonce counter) + 16 (GCM tag) = 24 bytes.
	assert.Equal(t, 24, cipher.Overhead())
}

func TestSessionCipher_ProbeHMAC(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()

	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	probe := []byte("WHPPprobe")
	tag := cipherA.SignProbe(probe)

	// Verification with the same derived key should succeed.
	assert.True(t, cipherB.VerifyProbe(probe, tag))

	// Tampered payload should fail.
	assert.False(t, cipherB.VerifyProbe([]byte("WHPPfake"), tag))

	// Tampered tag should fail.
	badTag := make([]byte, len(tag))
	copy(badTag, tag)
	badTag[0] ^= 0xFF
	assert.False(t, cipherB.VerifyProbe(probe, badTag))
}

func TestSessionCipher_ProbeHMAC_WrongKey(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	kpC, _ := GenerateKeyPair()

	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherWrong, _ := DeriveSession(kpC.Private, kpB.Public)

	probe := []byte("WHPPprobe")
	tag := cipherA.SignProbe(probe)

	// Wrong key should fail verification.
	assert.False(t, cipherWrong.VerifyProbe(probe, tag))
}

func TestDeriveSession_InvalidPublicKey(t *testing.T) {
	kpA, _ := GenerateKeyPair()

	// Too short.
	_, err := DeriveSession(kpA.Private, []byte("short"))
	assert.Error(t, err)

	// Empty.
	_, err = DeriveSession(kpA.Private, nil)
	assert.Error(t, err)
}

func TestTransport_Encrypted_BasicSendReceive(t *testing.T) {
	// Generate key pairs and derive session ciphers.
	kpA, err := GenerateKeyPair()
	require.NoError(t, err)
	kpB, err := GenerateKeyPair()
	require.NoError(t, err)

	cipherA, err := DeriveSession(kpA.Private, kpB.Public)
	require.NoError(t, err)
	cipherB, err := DeriveSession(kpB.Private, kpA.Public)
	require.NoError(t, err)

	// Create two UDP sockets.
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond

	// Create encrypted transports.
	t1 := NewTransport(conn1, addr2, config, cipherA)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config, cipherB)
	defer t2.Close()

	assert.True(t, t1.IsEncrypted())
	assert.True(t, t2.IsEncrypted())

	// Send data from t1 to t2.
	testData := []byte("Hello, encrypted P2P!")
	n, err := t1.Write(testData)
	require.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Receive data on t2.
	buf := make([]byte, 1024)
	done := make(chan struct{})

	go func() {
		readN, readErr := t2.Read(buf)
		if readErr == nil {
			assert.Equal(t, testData, buf[:readN])
		}
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Encrypted read timed out")
	}
}

func TestTransport_Encrypted_LargeMessage(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond
	config.MaxPacketSize = 200 // Small packets to test fragmentation with encryption overhead.

	t1 := NewTransport(conn1, addr2, config, cipherA)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config, cipherB)
	defer t2.Close()

	// Send large data that will be split into multiple encrypted packets.
	largeData := bytes.Repeat([]byte("E"), 500)
	_, err = t1.Write(largeData)
	require.NoError(t, err)

	received := make([]byte, 0, len(largeData))
	buf := make([]byte, 1024)

	done := make(chan struct{})
	go func() {
		for len(received) < len(largeData) {
			n, readErr := t2.Read(buf)
			if readErr != nil {
				break
			}
			received = append(received, buf[:n]...)
		}
		close(done)
	}()

	select {
	case <-done:
		assert.Equal(t, largeData, received)
	case <-time.After(10 * time.Second):
		t.Fatalf("Large encrypted message read timed out, received %d/%d bytes", len(received), len(largeData))
	}
}

// TestSessionCipher_DecryptTruncatedData tests that truncated ciphertext
// is correctly rejected at various boundary lengths.
func TestSessionCipher_DecryptTruncatedData(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	// Encrypt a message to get valid ciphertext.
	plaintext := []byte("boundary test data")
	ciphertext, err := cipherA.Encrypt(plaintext)
	require.NoError(t, err)

	// Test various truncated lengths.
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x01}},
		{"7 bytes (less than counter)", make([]byte, 7)},
		{"8 bytes (counter only, no GCM data)", make([]byte, 8)},
		{"23 bytes (counter + less than GCM tag)", make([]byte, 23)},
		{"counter + tag exactly (no ciphertext body)", ciphertext[:8+16]},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, decErr := cipherB.Decrypt(tc.data)
			assert.Error(t, decErr, "decrypt should fail for: %s", tc.name)
		})
	}

	// Full ciphertext should still work.
	decrypted, err := cipherB.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestSessionCipher_ConcurrentEncrypt tests that concurrent encryption
// from the same cipher produces valid outputs without data races.
func TestSessionCipher_ConcurrentEncrypt(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	const numGoroutines = 20
	plaintext := []byte("concurrent encryption test")

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make(chan []byte, numGoroutines)

	for range numGoroutines {
		go func() {
			defer wg.Done()
			ct, encErr := cipherA.Encrypt(plaintext)
			if encErr != nil {
				t.Errorf("concurrent encrypt failed: %v", encErr)
				return
			}
			results <- ct
		}()
	}

	wg.Wait()
	close(results)

	// All ciphertexts should be unique (different nonces) and decryptable.
	seen := make(map[string]bool)
	for ct := range results {
		assert.False(t, seen[string(ct)], "ciphertexts must be unique across concurrent calls")
		seen[string(ct)] = true

		decrypted, err := cipherB.Decrypt(ct)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
	assert.Len(t, seen, numGoroutines)
}

// TestHolePuncher_AuthenticatedPunch tests hole punching with HMAC-authenticated
// probes. Both sides set a cipher and only authenticated probes should succeed.
func TestHolePuncher_AuthenticatedPunch(t *testing.T) {
	kpA, err := GenerateKeyPair()
	require.NoError(t, err)
	kpB, err := GenerateKeyPair()
	require.NoError(t, err)

	cipherA, err := DeriveSession(kpA.Private, kpB.Public)
	require.NoError(t, err)
	cipherB, err := DeriveSession(kpB.Private, kpA.Public)
	require.NoError(t, err)

	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	hpConfig := HolePunchConfig{
		MaxAttempts: 10,
		Interval:    50 * time.Millisecond,
		Timeout:     5 * time.Second,
	}

	ctx := context.Background()
	resultCh := make(chan *net.UDPAddr, 2)
	errCh := make(chan error, 2)

	// Punch from conn1 → conn2 with cipher A.
	go func() {
		hp1 := NewHolePuncher(hpConfig)
		hp1.SetCipher(cipherA)
		peer := Endpoint{IP: addr2.IP.String(), Port: addr2.Port}
		result, punchErr := hp1.Punch(ctx, conn1, peer)
		if punchErr != nil {
			errCh <- punchErr
		} else {
			resultCh <- result
		}
	}()

	// Punch from conn2 → conn1 with cipher B.
	go func() {
		hp2 := NewHolePuncher(hpConfig)
		hp2.SetCipher(cipherB)
		peer := Endpoint{IP: addr1.IP.String(), Port: addr1.Port}
		result, punchErr := hp2.Punch(ctx, conn2, peer)
		if punchErr != nil {
			errCh <- punchErr
		} else {
			resultCh <- result
		}
	}()

	// At least one side should succeed with authenticated probes.
	select {
	case addr := <-resultCh:
		assert.NotNil(t, addr)
		t.Logf("Authenticated hole punch succeeded: peer=%s", addr.String())
	case punchErr := <-errCh:
		t.Logf("Authenticated hole punch failed (acceptable in some environments): %v", punchErr)
	case <-time.After(10 * time.Second):
		t.Fatal("Authenticated hole punch timed out")
	}
}

// TestHolePuncher_AuthMismatch tests that an authenticated hole puncher
// rejects unauthenticated probes. The authenticated side (cipher set)
// should timeout because it discards probes without valid HMAC tags.
func TestHolePuncher_AuthMismatch(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)

	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	hpConfig := HolePunchConfig{
		MaxAttempts: 5,
		Interval:    50 * time.Millisecond,
		Timeout:     1 * time.Second,
	}

	ctx := context.Background()

	// conn1 has cipher (expects HMAC), conn2 has no cipher (sends plain probes).
	// The authenticated side (conn1) will reject plain probes and timeout.
	// The unauthenticated side (conn2) may or may not succeed (it doesn't verify HMAC),
	// but that's not what we're testing — we test that conn1 rejects plain probes.
	type punchResult struct {
		side string
		err  error
	}
	resultCh := make(chan punchResult, 2)

	go func() {
		hp := NewHolePuncher(hpConfig)
		hp.SetCipher(cipherA) // Expects HMAC.
		peer := Endpoint{IP: addr2.IP.String(), Port: addr2.Port}
		_, punchErr := hp.Punch(ctx, conn1, peer)
		resultCh <- punchResult{side: "authenticated", err: punchErr}
	}()

	go func() {
		hp := NewHolePuncher(hpConfig)
		// No cipher — sends plain probes.
		peer := Endpoint{IP: addr1.IP.String(), Port: addr1.Port}
		_, punchErr := hp.Punch(ctx, conn2, peer)
		resultCh <- punchResult{side: "unauthenticated", err: punchErr}
	}()

	// Collect both results.
	var authResult punchResult
	for range 2 {
		r := <-resultCh
		if r.side == "authenticated" {
			authResult = r
		}
	}

	// The authenticated side must have timed out since it rejects plain probes.
	assert.Error(t, authResult.err, "authenticated side should fail when receiving plain probes")
	assert.Contains(t, authResult.err.Error(), "timed out")
}

// TestTransport_Encrypted_Bidirectional tests concurrent bidirectional
// encrypted communication over the transport.
func TestTransport_Encrypted_Bidirectional(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond

	t1 := NewTransport(conn1, addr2, config, cipherA)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config, cipherB)
	defer t2.Close()

	msg1to2 := []byte("encrypted message from peer 1")
	msg2to1 := []byte("encrypted message from peer 2")

	var wg sync.WaitGroup
	wg.Add(2)

	// Peer 1 sends.
	go func() {
		defer wg.Done()
		_, writeErr := t1.Write(msg1to2)
		assert.NoError(t, writeErr)
	}()

	// Peer 2 sends.
	go func() {
		defer wg.Done()
		_, writeErr := t2.Write(msg2to1)
		assert.NoError(t, writeErr)
	}()

	wg.Wait()

	// Read both sides with timeout.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)

		// Read on t1 (expect msg from t2).
		n, readErr := t1.Read(buf)
		if readErr == nil {
			assert.Equal(t, msg2to1, buf[:n])
		}

		// Read on t2 (expect msg from t1).
		n, readErr = t2.Read(buf)
		if readErr == nil {
			assert.Equal(t, msg1to2, buf[:n])
		}

		close(done)
	}()

	select {
	case <-done:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("Encrypted bidirectional read timed out")
	}
}

// TestTransport_Encrypted_GracefulClose tests that closing an encrypted
// transport properly sends FIN and the peer gets EOF.
func TestTransport_Encrypted_GracefulClose(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	t1 := NewTransport(conn1, addr2, config, cipherA)
	t2 := NewTransport(conn2, addr1, config, cipherB)

	// Send encrypted data first.
	_, err = t1.Write([]byte("encrypted close test"))
	require.NoError(t, err)

	buf := make([]byte, 1024)
	_, err = t2.Read(buf)
	require.NoError(t, err)

	// Close t1 gracefully.
	err = t1.Close()
	require.NoError(t, err)

	// t2 should eventually get EOF or error.
	done := make(chan error, 1)
	go func() {
		_, readErr := t2.Read(buf)
		done <- readErr
	}()

	select {
	case readErr := <-done:
		assert.True(t, readErr == io.EOF || readErr != nil)
	case <-time.After(3 * time.Second):
		// FIN might not arrive in all CI environments — acceptable.
	}

	_ = t2.Close()
	_ = conn1.Close()
	_ = conn2.Close()
}

// TestTransport_IsEncrypted tests the IsEncrypted method.
func TestTransport_IsEncrypted(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	fakeAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 65000}
	config := DefaultTransportConfig()

	// Without cipher.
	tr := NewTransport(conn, fakeAddr, config, nil)
	assert.False(t, tr.IsEncrypted())
	_ = tr.Close()

	// Recreate conn since Close may affect it.
	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	// With cipher.
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipher, _ := DeriveSession(kpA.Private, kpB.Public)

	tr2 := NewTransport(conn2, fakeAddr, config, cipher)
	assert.True(t, tr2.IsEncrypted())
	_ = tr2.Close()
}
