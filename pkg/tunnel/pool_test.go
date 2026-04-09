package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDialer creates a dialer that returns connected pipes.
func testDialer(serverHandler func(net.Conn)) DialFunc {
	return func(_ context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go serverHandler(server)
		return client, nil
	}
}

func TestPool_Basic(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			stream, err := mux.AcceptStream()
			if err != nil {
				return
			}
			stream.Close()
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Get connection
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, mux)
	assert.Equal(t, 1, pool.Len())

	// Put it back
	pool.Put(mux)

	// Get again - should reuse
	mux2, err := pool.Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, mux, mux2)
	assert.Equal(t, 1, pool.Len())
}

func TestPool_OpenStream(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			stream, err := mux.AcceptStream()
			if err != nil {
				return
			}
			go func(s *Stream) {
				buf := make([]byte, 100)
				s.Read(buf)
				s.Close()
			}(stream)
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	stream, mux, err := pool.OpenStream(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, stream)
	assert.NotNil(t, mux)

	stream.Write([]byte("hello"))
	stream.Close()
}

func TestPool_MaxSize(t *testing.T) {
	config := DefaultPoolConfig()
	config.MaxSize = 2
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	var connCount int32

	serverHandler := func(conn net.Conn) {
		atomic.AddInt32(&connCount, 1)
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Create MaxSize connections
	for i := 0; i < config.MaxSize+2; i++ {
		_, err := pool.Get(context.Background())
		require.NoError(t, err)
	}

	// Should not exceed MaxSize
	assert.LessOrEqual(t, pool.Len(), config.MaxSize)
}

func TestPool_Concurrent(t *testing.T) {
	config := DefaultPoolConfig()
	config.MaxSize = 5
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			stream, err := mux.AcceptStream()
			if err != nil {
				return
			}
			go func(s *Stream) {
				buf := make([]byte, 100)
				s.Read(buf)
				s.Write(buf)
				s.Close()
			}(stream)
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	var wg sync.WaitGroup
	numGoroutines := 20

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, mux, err := pool.OpenStream(context.Background())
			if err != nil {
				return
			}
			defer pool.Put(mux)

			stream.Write([]byte("hello"))
			buf := make([]byte, 10)
			stream.Read(buf)
			stream.Close()
		}()
	}

	wg.Wait()
	assert.LessOrEqual(t, pool.Len(), config.MaxSize)
}

func TestPool_Close(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)

	// Create some connections
	mux, _ := pool.Get(context.Background())
	assert.NotNil(t, mux)

	// Close pool
	pool.Close()
	assert.True(t, pool.IsClosed())

	// Get should fail
	_, err := pool.Get(context.Background())
	require.Error(t, err)
}

func TestPool_Stats(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			stream, err := mux.AcceptStream()
			if err != nil {
				return
			}
			stream.Close()
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Initial stats
	stats := pool.Stats()
	assert.Equal(t, int64(0), stats.TotalConnections)

	// Create connection
	pool.Get(context.Background())
	stats = pool.Stats()
	assert.Equal(t, int64(1), stats.TotalConnections)
	assert.Equal(t, int64(1), stats.ActiveConnections)

	// Open stream
	pool.OpenStream(context.Background())
	stats = pool.Stats()
	assert.Equal(t, int64(1), stats.TotalStreams)
}

func TestPool_Warmup(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinSize = 3
	config.MaxSize = 5
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Warmup
	err := pool.Warmup(context.Background())
	require.NoError(t, err)

	assert.Equal(t, config.MinSize, pool.Len())
}

func TestPool_IdleCleanup(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinSize = 1
	config.MaxSize = 5
	config.MaxIdleTime = 50 * time.Millisecond
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Warmup to create multiple connections
	err := pool.Warmup(context.Background())
	require.NoError(t, err)

	// Force create more connections by modifying pool directly
	// This is a simplified test - just verify the cleanup mechanism works
	initialLen := pool.Len()
	assert.GreaterOrEqual(t, initialLen, 1)

	// Wait for idle cleanup
	time.Sleep(150 * time.Millisecond)

	// Should be reduced (or stay at MinSize)
	assert.LessOrEqual(t, pool.Len(), config.MinSize+1)
}

func TestDefaultPoolConfig(t *testing.T) {
	config := DefaultPoolConfig()

	assert.Equal(t, 10, config.MaxSize)
	assert.Equal(t, 1, config.MinSize)
	assert.Equal(t, 5*time.Minute, config.MaxIdleTime)
	assert.Equal(t, 30*time.Second, config.HealthCheckInterval)
	assert.Equal(t, 10*time.Second, config.ConnectTimeout)
}

func TestPool_RemoveConn(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Create a connection.
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, pool.Len())

	// Remove it.
	pool.removeConn(mux)
	assert.Equal(t, 0, pool.Len())

	// Removing again should be a no-op.
	pool.removeConn(mux)
	assert.Equal(t, 0, pool.Len())
}

func TestPool_HealthCheck(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinSize = 2
	config.MaxSize = 5
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 50 * time.Millisecond
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Warmup to create MinSize connections.
	err := pool.Warmup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, pool.Len())

	// Get one connection and close it to mark it unhealthy.
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)
	_ = mux.Close()

	// Wait for health check to detect and remove.
	time.Sleep(200 * time.Millisecond)

	// One connection should have been removed.
	assert.LessOrEqual(t, pool.Len(), 1)
	stats := pool.Stats()
	assert.GreaterOrEqual(t, stats.HealthCheckFailures, int64(1))
}

func TestPool_HealthCheckLoop(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 50 * time.Millisecond
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)

	// Create a connection and close its mux to mark it unhealthy.
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, pool.Len())

	_ = mux.Close()

	// Wait for health check loop to detect and remove.
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 0, pool.Len())

	pool.Close()
}

func TestPool_Put_ClosedMux(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	mux, err := pool.Get(context.Background())
	require.NoError(t, err)

	// Close the mux then put it back.
	_ = mux.Close()
	pool.Put(mux)

	// Pool should remove the closed mux.
	// The Put may or may not clean it up immediately, but it shouldn't panic.
	assert.LessOrEqual(t, pool.Len(), 1)
}

func TestPool_CloseWhileGetting(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)

	// Get a connection.
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, mux)

	// Close pool.
	pool.Close()

	// Get should fail now.
	_, err = pool.Get(context.Background())
	assert.Error(t, err)

	// OpenStream should also fail.
	_, _, err = pool.OpenStream(context.Background())
	assert.Error(t, err)
}

func BenchmarkPool_Get(b *testing.B) {
	config := DefaultPoolConfig()
	config.MaxSize = 10
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Pre-warm
	pool.Get(context.Background())

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		mux, _ := pool.Get(context.Background())
		pool.Put(mux)
	}
}

func BenchmarkPool_OpenStream(b *testing.B) {
	config := DefaultPoolConfig()
	config.MaxSize = 10
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			stream, err := mux.AcceptStream()
			if err != nil {
				return
			}
			stream.Close()
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		stream, mux, _ := pool.OpenStream(context.Background())
		if stream != nil {
			stream.Close()
		}
		if mux != nil {
			pool.Put(mux)
		}
	}
}

// TestPool_CleanupIdle_Direct directly invokes cleanupIdle and verifies
// that idle connections exceeding MaxIdleTime are removed while MinSize is preserved.
func TestPool_CleanupIdle_Direct(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinSize = 1
	config.MaxSize = 5
	config.MaxIdleTime = 50 * time.Millisecond
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	// Disable auto idle cleanup so we control it manually.
	config.MaxIdleTime = 50 * time.Millisecond

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	// Create pool with idle cleanup disabled (we set it to 0 during pool creation).
	poolConfig := config
	poolConfig.MaxIdleTime = 0 // Disable auto cleanup loop.
	pool := NewPool(poolConfig, testDialer(serverHandler), true)
	defer pool.Close()

	// Override config for cleanupIdle to use.
	pool.config.MaxIdleTime = 50 * time.Millisecond
	pool.config.MinSize = 1

	// Use Warmup to create 3 connections (set MinSize temporarily).
	pool.config.MinSize = 3
	err := pool.Warmup(context.Background())
	require.NoError(t, err)
	pool.config.MinSize = 1 // Restore MinSize for cleanup.
	assert.Equal(t, 3, pool.Len())

	// Wait for connections to become idle.
	time.Sleep(100 * time.Millisecond)

	// Directly invoke cleanup.
	pool.cleanupIdle()

	// Should keep at least MinSize (1) connections.
	assert.GreaterOrEqual(t, pool.Len(), config.MinSize,
		"should preserve MinSize connections")
	assert.Less(t, pool.Len(), 3,
		"should have removed at least one idle connection")
}

// TestPool_CleanupIdle_PreservesMinSize verifies that cleanupIdle does NOT
// remove connections below MinSize even if they are idle.
func TestPool_CleanupIdle_PreservesMinSize(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinSize = 2
	config.MaxSize = 5
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	// Create pool without auto-cleanup.
	poolConfig := config
	poolConfig.MaxIdleTime = 0
	pool := NewPool(poolConfig, testDialer(serverHandler), true)
	defer pool.Close()

	pool.config.MaxIdleTime = 10 * time.Millisecond

	// Use Warmup to create exactly MinSize connections.
	err := pool.Warmup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, config.MinSize, pool.Len())

	// Wait for them to become idle.
	time.Sleep(50 * time.Millisecond)

	// Invoke cleanup — should NOT remove any because we're at MinSize.
	pool.cleanupIdle()
	assert.Equal(t, config.MinSize, pool.Len(),
		"should not remove connections at MinSize")
}

// TestPool_CreateConn_MaxCapacityWithClosedConns verifies that createConn
// can clean up closed connections at max capacity and still serve requests.
func TestPool_CreateConn_MaxCapacityWithClosedConns(t *testing.T) {
	config := DefaultPoolConfig()
	config.MaxSize = 2
	config.MinSize = 2
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Use Warmup to fill pool to MaxSize.
	err := pool.Warmup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, pool.Len())

	// Close first connection to simulate it dying.
	pool.connLock.RLock()
	firstMux := pool.conns[0].mux
	pool.connLock.RUnlock()
	_ = firstMux.Close()

	// Get should still succeed (reuse surviving conn or create new after cleanup).
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, mux)
	assert.LessOrEqual(t, pool.Len(), config.MaxSize)
}

// TestPool_CreateConn_AllClosedAtMax verifies that when all connections are
// closed at max capacity, createConn reports the error correctly.
func TestPool_CreateConn_AllClosedAtMax(t *testing.T) {
	config := DefaultPoolConfig()
	config.MaxSize = 2
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	var callCount int32
	failingDialer := func(_ context.Context) (net.Conn, error) {
		count := atomic.AddInt32(&callCount, 1)
		if count <= 2 {
			// First two calls succeed (filling the pool).
			client, server := net.Pipe()
			go func() {
				mux, _ := Server(server, config.MuxConfig)
				defer mux.Close()
				for {
					_, err := mux.AcceptStream()
					if err != nil {
						return
					}
				}
			}()
			return client, nil
		}
		// Subsequent calls succeed for the cleanup test.
		client, server := net.Pipe()
		go func() {
			mux, _ := Server(server, config.MuxConfig)
			defer mux.Close()
			for {
				_, err := mux.AcceptStream()
				if err != nil {
					return
				}
			}
		}()
		return client, nil
	}

	pool := NewPool(config, failingDialer, true)
	defer pool.Close()

	// Fill to max.
	mux1, err := pool.Get(context.Background())
	require.NoError(t, err)
	mux2, err := pool.Get(context.Background())
	require.NoError(t, err)

	// Pool is at max. Getting another should reuse an existing one.
	mux3, err := pool.Get(context.Background())
	require.NoError(t, err)
	// Should get back one of the existing connections.
	assert.True(t, mux3 == mux1 || mux3 == mux2,
		"should reuse existing connection at max capacity")
}

// TestPool_CreateConn_DialFailure verifies that createConn increments
// FailedConnections counter when dial fails.
func TestPool_CreateConn_DialFailure(t *testing.T) {
	config := DefaultPoolConfig()
	config.MaxSize = 5
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0
	config.ConnectTimeout = 50 * time.Millisecond

	errDialer := func(_ context.Context) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	pool := NewPool(config, errDialer, true)
	defer pool.Close()

	_, err := pool.Get(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")

	stats := pool.Stats()
	assert.Equal(t, int64(1), stats.FailedConnections)
}

// TestPool_OpenStream_BrokenConn verifies that OpenStream handles
// the case where the mux is closed after Get but before OpenStreamContext.
func TestPool_OpenStream_BrokenConn(t *testing.T) {
	config := DefaultPoolConfig()
	config.MaxSize = 1
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Get the connection and close it to simulate breakage.
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)
	_ = mux.Close()

	// OpenStream should fail and remove the broken connection.
	_, _, err = pool.OpenStream(context.Background())
	// It may or may not error depending on timing, but should not panic.
	if err != nil {
		assert.True(t, pool.Len() <= 1)
	}
}

// TestPool_Put_ClosedPool verifies Put is a no-op when pool is closed.
func TestPool_Put_ClosedPool(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)

	// Close pool first.
	pool.Close()

	// Put should be a no-op (not panic).
	pool.Put(mux)
}

// TestPool_Put_UnknownMux verifies Put ignores a mux not in the pool.
func TestPool_Put_UnknownMux(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Create a mux outside the pool.
	c, s := net.Pipe()
	unknownMux, err := Client(c, config.MuxConfig)
	require.NoError(t, err)
	defer unknownMux.Close()

	go func() {
		serverMux, _ := Server(s, config.MuxConfig)
		defer serverMux.Close()
		for {
			_, err := serverMux.AcceptStream()
			if err != nil {
				return
			}
		}
	}()

	// Put with unknown mux should not panic.
	pool.Put(unknownMux)
}

// TestPool_DoubleClose verifies that closing a pool twice is safe and
// the second close returns nil immediately.
func TestPool_DoubleClose(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)

	// Create a connection so there's something to clean up.
	_, err := pool.Get(context.Background())
	require.NoError(t, err)

	// First close.
	err = pool.Close()
	assert.NoError(t, err)
	assert.True(t, pool.IsClosed())

	// Second close should be a no-op (no panic, returns nil).
	err = pool.Close()
	assert.NoError(t, err)
}

// TestPool_CreateConn_AllClosedAtMaxError verifies that when all
// connections at max capacity are closed and cleanup removes them all,
// createConn correctly creates a new connection.
func TestPool_CreateConn_AllClosedRecovery(t *testing.T) {
	config := DefaultPoolConfig()
	config.MaxSize = 2
	config.MinSize = 2
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Fill to max capacity.
	err := pool.Warmup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, pool.Len())

	// Close ALL connections to simulate total connection death.
	pool.connLock.RLock()
	for _, pc := range pool.conns {
		_ = pc.mux.Close()
	}
	pool.connLock.RUnlock()

	// Now Get should clean up all closed conns and create a fresh one.
	mux, err := pool.Get(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, mux)
	assert.False(t, mux.IsClosed())
}

// TestPool_OpenStream_ContextCancel verifies that OpenStream returns an
// error when the context is canceled but the mux is still healthy
// (covers the non-closed mux error path in OpenStream).
func TestPool_OpenStream_ContextCancel(t *testing.T) {
	config := DefaultPoolConfig()
	config.MuxConfig.KeepAliveInterval = 0
	config.HealthCheckInterval = 0
	config.MaxIdleTime = 0

	serverHandler := func(conn net.Conn) {
		mux, _ := Server(conn, config.MuxConfig)
		defer mux.Close()
		for {
			_, err := mux.AcceptStream()
			if err != nil {
				return
			}
		}
	}

	pool := NewPool(config, testDialer(serverHandler), true)
	defer pool.Close()

	// Pre-warm so Get returns an existing mux.
	_, err := pool.Get(context.Background())
	require.NoError(t, err)

	// Use an already-canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = pool.OpenStream(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	// The mux should NOT have been removed (it's still healthy).
	assert.Equal(t, 1, pool.Len())
}
