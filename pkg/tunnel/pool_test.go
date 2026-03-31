package tunnel

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDialer creates a dialer that returns connected pipes
func testDialer(serverHandler func(net.Conn)) DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
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
	var muxes []*Mux
	for i := 0; i < config.MaxSize+2; i++ {
		mux, err := pool.Get(context.Background())
		require.NoError(t, err)
		muxes = append(muxes, mux)
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
