package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestP2PSession_InstallSession_TearsDownPreviousSession verifies that
// installing a new P2P session always tears down whatever session was
// previously active first, so its resources (signal channel, in this
// case) can never be orphaned by the replacement — this is the fix for
// NDP-01: attemptP2P used to blindly overwrite p.conn/p.udpMux/
// p.sessionCloseCh, leaking the old session's UDPMux, socket, and
// accept-loop goroutine whenever a session was replaced rather than
// explicitly closed first.
func TestP2PSession_InstallSession_TearsDownPreviousSession(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	oldPipe, _ := net.Pipe()
	oldConn := newFakePacketConn(oldPipe)
	oldCloseCh := make(chan struct{})

	c.p2p.mu.Lock()
	c.p2p.conn = oldConn
	c.p2p.sessionCloseCh = oldCloseCh
	atomic.StoreUint32(&c.p2p.mode, 1)
	oldGen := c.p2p.sessionGen
	c.p2p.mu.Unlock()

	newPipe, _ := net.Pipe()
	newConn := newFakePacketConn(newPipe)
	newCloseCh := make(chan struct{})
	newPeer := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 4242}

	gen := c.p2p.installSession(newConn, newPeer, nil, newCloseCh)

	// The old session's signal channel must be closed so any goroutine
	// still selecting on it (e.g. a lingering acceptP2PStreams) unblocks
	// instead of running forever against a session nobody references
	// anymore.
	select {
	case <-oldCloseCh:
	default:
		t.Fatal("old session's close channel was not closed by installSession")
	}

	c.p2p.mu.Lock()
	assert.Same(t, newConn, c.p2p.conn, "new connection should be installed")
	assert.Equal(t, newPeer, c.p2p.peer)
	assert.True(t, newCloseCh == c.p2p.sessionCloseCh, "new session's close channel should be installed")
	c.p2p.mu.Unlock()

	assert.True(t, c.IsP2PMode())
	assert.Greater(t, gen, oldGen, "installing a new session must advance the generation counter")
	assert.Equal(t, gen, c.p2p.sessionGen)
}

// TestP2PSession_InstallSession_NoPreviousSession verifies installSession
// works correctly as a no-op teardown when there is no prior session
// (the common case: the very first successful hole punch).
func TestP2PSession_InstallSession_NoPreviousSession(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	newPipe, _ := net.Pipe()
	newConn := newFakePacketConn(newPipe)
	newCloseCh := make(chan struct{})

	gen := c.p2p.installSession(newConn, &net.UDPAddr{}, nil, newCloseCh)

	assert.True(t, c.IsP2PMode())
	assert.Equal(t, uint64(1), gen)
}

// TestP2PSession_AttemptP2P_SkipsWhenAlreadyAttempting verifies the
// singleflight guard added for NDP-01: a second concurrent call to
// attemptP2P (which can happen when an outgoing offer response and an
// inbound notification race each other) must return immediately without
// touching any session state, rather than racing the in-flight attempt to
// install its own session.
func TestP2PSession_AttemptP2P_SkipsWhenAlreadyAttempting(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Simulate an attempt already in flight.
	c.p2p.attempting.Store(true)

	c.p2p.attemptP2P(context.Background(), c.relay, "10.0.0.1:5000", "", true)

	// The guard must be left exactly as the in-flight attempt (not this
	// call) would eventually clear it — this call's early return must not
	// have touched it either way.
	assert.True(t, c.p2p.attempting.Load())
	assert.Equal(t, uint64(0), c.p2p.sessionGen, "skipped attempt must not install any session")
	assert.False(t, c.IsP2PMode())
}

// TestP2PSession_AttemptP2P_ReleasesGuardOnCompletion verifies that a
// non-skipped attempt always releases the singleflight guard when it
// returns (success or failure), so a single failed attempt doesn't
// permanently block all future ones.
func TestP2PSession_AttemptP2P_ReleasesGuardOnCompletion(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// No NAT info discovered, so manager.AttemptP2P fails fast — this
	// exercises the "attempt ran and failed" path, not the skip path.
	c.p2p.attemptP2P(context.Background(), c.relay, "10.0.0.1:5000", "", true)

	assert.False(t, c.p2p.attempting.Load(), "guard must be released after a completed attempt")
}

// TestP2PSession_FallbackFromStaleSession_IgnoresStaleGeneration verifies
// that an accept-loop goroutine reporting an error for a session that has
// already been replaced (sessionGen has moved on) does not tear down the
// newer, currently-active session — the second half of the NDP-01 fix.
func TestP2PSession_FallbackFromStaleSession_IgnoresStaleGeneration(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Install a session and capture its generation, then install a second
	// one, simulating a fresh attempt superseding the first before its
	// accept loop noticed anything was wrong.
	pipe1, _ := net.Pipe()
	staleGen := c.p2p.installSession(newFakePacketConn(pipe1), &net.UDPAddr{}, nil, make(chan struct{}))

	pipe2, _ := net.Pipe()
	currentCloseCh := make(chan struct{})
	currentConn := newFakePacketConn(pipe2)
	currentGen := c.p2p.installSession(currentConn, &net.UDPAddr{}, nil, currentCloseCh)
	require.Greater(t, currentGen, staleGen)

	// The stale accept loop's error must be ignored: the current session
	// stays untouched.
	c.p2p.fallbackFromStaleSession(staleGen, "stale mux closed")

	c.p2p.mu.Lock()
	assert.Same(t, currentConn, c.p2p.conn, "current session must survive a stale generation's fallback")
	c.p2p.mu.Unlock()
	assert.True(t, c.IsP2PMode(), "falling back on stale generation must not flip mode off")

	select {
	case <-currentCloseCh:
		t.Fatal("current session's close channel must not be closed by a stale fallback")
	default:
	}

	// A fallback reported against the *current* generation, however,
	// really does tear it down.
	c.p2p.fallbackFromStaleSession(currentGen, "current mux closed")
	assert.False(t, c.IsP2PMode())
	select {
	case <-currentCloseCh:
	case <-time.After(time.Second):
		t.Fatal("current session's close channel should be closed once its own generation falls back")
	}
}

// TestP2PSession_Close_ResetsMode verifies Close() always resets the P2P
// mode flag to relay (0), fixing NDP-05: Close() used to tear down
// conn/udpMux/sessionCloseCh but never reset the atomic mode flag, so
// IsP2PMode() could keep reporting true after shutdown.
func TestP2PSession_Close_ResetsMode(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	pipe, _ := net.Pipe()
	_ = c.p2p.installSession(newFakePacketConn(pipe), &net.UDPAddr{}, nil, make(chan struct{}))
	require.True(t, c.IsP2PMode())

	c.p2p.Close()

	assert.False(t, c.IsP2PMode(), "Close must reset P2P mode to relay")
}
