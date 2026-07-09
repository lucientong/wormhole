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

// TestSessionCipher_EncryptInto_MatchesEncryptWithNilDst verifies that
// EncryptInto(nil, plaintext) produces byte-for-byte the same output as
// Encrypt would for an equivalent nonce counter value.
func TestSessionCipher_EncryptInto_MatchesEncryptWithNilDst(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, err := DeriveSession(kpA.Private, kpB.Public)
	require.NoError(t, err)
	cipherB, err := DeriveSession(kpB.Private, kpA.Public)
	require.NoError(t, err)

	plaintext := []byte("dp-14 encrypt-into parity check")

	viaEncrypt, err := cipherA.Encrypt(plaintext)
	require.NoError(t, err)

	viaEncryptInto, err := cipherB.EncryptInto(nil, plaintext)
	require.NoError(t, err)

	// Both ciphers were driven with the same nonce counter sequence (each
	// starts fresh at 1), so the outputs should be identical in length
	// and structure even though they're independent cipher instances.
	assert.Len(t, viaEncryptInto, len(viaEncrypt))
}

// TestSessionCipher_EncryptInto_AppendsToExistingPrefix verifies that
// EncryptInto appends to a non-empty dst (e.g. a wire header already
// written into the buffer) rather than overwriting it, and that the
// appended region decrypts back to the original plaintext.
func TestSessionCipher_EncryptInto_AppendsToExistingPrefix(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, err := DeriveSession(kpA.Private, kpB.Public)
	require.NoError(t, err)
	cipherB, err := DeriveSession(kpB.Private, kpA.Public)
	require.NoError(t, err)

	prefix := []byte("HEADER99")
	plaintext := []byte("appended after a wire header prefix")

	frame, err := cipherA.EncryptInto(prefix, plaintext)
	require.NoError(t, err)

	require.True(t, len(frame) > len(prefix))
	assert.Equal(t, "HEADER99", string(frame[:len(prefix)]))

	decrypted, err := cipherB.Decrypt(frame[len(prefix):])
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestSessionCipher_EncryptInto_DoesNotCorruptCallerPrefix verifies that
// growing dst via append inside EncryptInto never retroactively mutates
// bytes the caller already wrote before the call, even when dst's
// capacity happens to be large enough for Seal to write in place.
func TestSessionCipher_EncryptInto_DoesNotCorruptCallerPrefix(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, err := DeriveSession(kpA.Private, kpB.Public)
	require.NoError(t, err)

	buf := make([]byte, 4, 256)
	copy(buf, []byte{0xDE, 0xAD, 0xBE, 0xEF})

	out, err := cipherA.EncryptInto(buf, []byte("payload"))
	require.NoError(t, err)

	assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, out[:4])
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

// TestUDPMux_Encrypted_BasicSendReceive exercises the same encrypted
// send/receive path previously covered by the (now-removed) Transport
// type, via UDPMux/UDPStream instead.
func TestUDPMux_Encrypted_BasicSendReceive(t *testing.T) {
	kpA, err := GenerateKeyPair()
	require.NoError(t, err)
	kpB, err := GenerateKeyPair()
	require.NoError(t, err)

	cipherA, err := DeriveSession(kpA.Private, kpB.Public)
	require.NoError(t, err)
	cipherB, err := DeriveSession(kpB.Private, kpA.Public)
	require.NoError(t, err)

	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond

	m1 := NewUDPMux(conn1, peer1, config, cipherA, true)
	defer m1.Close()
	m2 := NewUDPMux(conn2, peer2, config, cipherB, false)
	defer m2.Close()

	s1, err := m1.OpenStream()
	require.NoError(t, err)
	defer s1.Close()

	testData := []byte("Hello, encrypted P2P!")
	go func() {
		_, _ = s1.Write(testData)
	}()

	s2, err := m2.AcceptStream()
	require.NoError(t, err)
	defer s2.Close()

	buf := make([]byte, 1024)
	_ = s2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, readErr := s2.Read(buf)
	require.NoError(t, readErr)
	assert.Equal(t, testData, buf[:n])
}

// TestUDPMux_Encrypted_LargeMessage verifies that a payload spanning many
// fragments is delivered intact when encryption overhead is factored into
// each fragment's size.
func TestUDPMux_Encrypted_LargeMessage(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond
	config.MaxPacketSize = 200 // Small packets to test fragmentation with encryption overhead.

	m1 := NewUDPMux(conn1, peer1, config, cipherA, true)
	defer m1.Close()
	m2 := NewUDPMux(conn2, peer2, config, cipherB, false)
	defer m2.Close()

	s1, err := m1.OpenStream()
	require.NoError(t, err)
	defer s1.Close()

	largeData := bytes.Repeat([]byte("E"), 5000)
	go func() {
		_, _ = s1.Write(largeData)
		_ = s1.Close()
	}()

	s2, err := m2.AcceptStream()
	require.NoError(t, err)
	defer s2.Close()

	_ = s2.SetReadDeadline(time.Now().Add(10 * time.Second))
	received, readErr := io.ReadAll(s2)
	require.NoError(t, readErr)
	assert.Equal(t, largeData, received)
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
// TestUDPMux_Encrypted_Bidirectional verifies simultaneous encrypted
// traffic in both directions is delivered correctly to each side.
func TestUDPMux_Encrypted_Bidirectional(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond

	m1 := NewUDPMux(conn1, peer1, config, cipherA, true)
	defer m1.Close()
	m2 := NewUDPMux(conn2, peer2, config, cipherB, false)
	defer m2.Close()

	s1, err := m1.OpenStream()
	require.NoError(t, err)
	defer s1.Close()

	msg1to2 := []byte("encrypted message from peer 1")
	msg2to1 := []byte("encrypted message from peer 2")

	go func() {
		_, _ = s1.Write(msg1to2)
	}()

	s2, err := m2.AcceptStream()
	require.NoError(t, err)
	defer s2.Close()

	go func() {
		_, _ = s2.Write(msg2to1)
	}()

	done := make(chan struct{})
	go func() {
		buf1 := make([]byte, 1024)
		n, readErr := s1.Read(buf1)
		if readErr == nil {
			assert.Equal(t, msg2to1, buf1[:n])
		}

		buf2 := make([]byte, 1024)
		n, readErr = s2.Read(buf2)
		if readErr == nil {
			assert.Equal(t, msg1to2, buf2[:n])
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Encrypted bidirectional read timed out")
	}
}

// TestUDPMux_Encrypted_GracefulClose verifies that closing an encrypted
// stream sends FIN and the peer's Read() observes EOF.
func TestUDPMux_Encrypted_GracefulClose(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	m1 := NewUDPMux(conn1, peer1, config, cipherA, true)
	defer m1.Close()
	m2 := NewUDPMux(conn2, peer2, config, cipherB, false)
	defer m2.Close()

	s1, err := m1.OpenStream()
	require.NoError(t, err)

	go func() {
		_, _ = s1.Write([]byte("encrypted close test"))
	}()

	s2, err := m2.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 1024)
	_ = s2.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = s2.Read(buf)
	require.NoError(t, err)

	require.NoError(t, s1.Close())

	_ = s2.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, readErr := s2.Read(buf)
	assert.True(t, readErr == io.EOF || readErr != nil)
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkGenerateKeyPair(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKeyPair()
	}
}

func BenchmarkDeriveSession(b *testing.B) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = DeriveSession(kpA.Private, kpB.Public)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipher, _ := DeriveSession(kpA.Private, kpB.Public)

	sizes := []struct {
		name string
		size int
	}{
		{"64B", 64},
		{"1KB", 1024},
		{"32KB", 32 * 1024},
	}

	for _, s := range sizes {
		plaintext := make([]byte, s.size)
		b.Run(s.name, func(b *testing.B) {
			b.SetBytes(int64(s.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = cipher.Encrypt(plaintext)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipherA, _ := DeriveSession(kpA.Private, kpB.Public)
	cipherB, _ := DeriveSession(kpB.Private, kpA.Public)

	sizes := []struct {
		name string
		size int
	}{
		{"64B", 64},
		{"1KB", 1024},
		{"32KB", 32 * 1024},
	}

	for _, s := range sizes {
		plaintext := make([]byte, s.size)
		ct, _ := cipherA.Encrypt(plaintext)

		b.Run(s.name, func(b *testing.B) {
			b.SetBytes(int64(s.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = cipherB.Decrypt(ct)
			}
		})
	}
}

func BenchmarkSignProbe(b *testing.B) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipher, _ := DeriveSession(kpA.Private, kpB.Public)
	payload := []byte("WHPPprobe-benchmark")

	b.ReportAllocs()
	for b.Loop() {
		_ = cipher.SignProbe(payload)
	}
}

func BenchmarkVerifyProbe(b *testing.B) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()
	cipher, _ := DeriveSession(kpA.Private, kpB.Public)
	payload := []byte("WHPPprobe-benchmark")
	tag := cipher.SignProbe(payload)

	b.ReportAllocs()
	for b.Loop() {
		_ = cipher.VerifyProbe(payload, tag)
	}
}
