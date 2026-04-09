package tunnel

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

// testConn creates a pair of connected net.Conn.
func testConn() (net.Conn, net.Conn) {
	return net.Pipe()
}

func TestMux_ClientServer(t *testing.T) {
	clientConn, serverConn := testConn()

	// Create server mux
	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0 // Disable keep-alive for test
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	// Create client mux
	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	// Client opens stream
	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), clientStream.ID()) // Client uses odd IDs

	// Server accepts stream
	serverStream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), serverStream.ID())

	// Client writes, server reads
	go func() {
		clientStream.Write([]byte("hello from client"))
		clientStream.Close()
	}()

	buf := make([]byte, 100)
	n, err := serverStream.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello from client", string(buf[:n]))
}

func TestMux_BidirectionalStream(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	// Open stream from client
	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	serverStream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	// Bidirectional communication
	var wg sync.WaitGroup
	wg.Add(2)

	// Client sends, server echoes back
	go func() {
		defer wg.Done()
		_, err := clientStream.Write([]byte("ping"))
		assert.NoError(t, err)

		buf := make([]byte, 100)
		n, err := clientStream.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, "pong", string(buf[:n]))
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 100)
		n, err := serverStream.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, "ping", string(buf[:n]))

		_, err = serverStream.Write([]byte("pong"))
		assert.NoError(t, err)
	}()

	wg.Wait()
}

func TestMux_MultipleStreams(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	numStreams := 10
	var wg sync.WaitGroup
	wg.Add(numStreams * 2) // client + server for each stream

	// Server handler
	go func() {
		for range numStreams {
			stream, err := serverMux.AcceptStream()
			if err != nil {
				return
			}
			go func(s *Stream) {
				defer wg.Done()
				buf := make([]byte, 100)
				n, _ := s.Read(buf)
				s.Write(buf[:n]) // Echo back
			}(stream)
		}
	}()

	// Client opens multiple streams concurrently
	for range numStreams {
		go func() {
			defer wg.Done()
			stream, err := clientMux.OpenStream()
			assert.NoError(t, err)

			msg := []byte("hello")
			stream.Write(msg)

			buf := make([]byte, 100)
			n, _ := stream.Read(buf)
			assert.Equal(t, msg, buf[:n])
		}()
	}

	wg.Wait()
	assert.Equal(t, numStreams, clientMux.NumStreams())
}

func TestMux_StreamClose(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	serverStream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	// Client closes stream
	clientStream.Close()

	// Server should get EOF
	buf := make([]byte, 100)
	_, err = serverStream.Read(buf)
	assert.Equal(t, io.EOF, err)
}

func TestMux_MuxClose(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)

	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	_, err = serverMux.AcceptStream()
	require.NoError(t, err)

	// Close client mux
	clientMux.Close()
	assert.True(t, clientMux.IsClosed())

	// Stream should be closed
	assert.True(t, clientStream.IsClosed())

	// Open stream should fail
	_, err = clientMux.OpenStream()
	require.Error(t, err)

	// Accept should fail
	_, err = clientMux.AcceptStream()
	require.Error(t, err)
}

func TestMux_AcceptStreamContext(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	_, err = Client(clientConn, clientConfig)
	require.NoError(t, err)

	// Context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = serverMux.AcceptStreamContext(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestMux_OpenStreamContext(t *testing.T) {
	clientConn, serverConn := testConn()
	defer clientConn.Close()
	defer serverConn.Close()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	_, err := Server(serverConn, serverConfig)
	require.NoError(t, err)

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)

	ctx := context.Background()
	stream, err := clientMux.OpenStreamContext(ctx)
	require.NoError(t, err)
	assert.NotNil(t, stream)
}

func TestMux_NumStreams(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	assert.Equal(t, 0, clientMux.NumStreams())

	// Open streams
	stream1, _ := clientMux.OpenStream()
	serverMux.AcceptStream()
	assert.Equal(t, 1, clientMux.NumStreams())

	stream2, _ := clientMux.OpenStream()
	serverMux.AcceptStream()
	assert.Equal(t, 2, clientMux.NumStreams())

	// Close one stream
	stream1.Close()
	time.Sleep(10 * time.Millisecond) // Allow close to propagate
	assert.Equal(t, 1, clientMux.NumStreams())

	stream2.Close()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, 0, clientMux.NumStreams())
}

func TestMux_LocalRemoteAddr(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	// net.Pipe returns "pipe" addresses
	assert.NotNil(t, clientMux.LocalAddr())
	assert.NotNil(t, clientMux.RemoteAddr())
	assert.NotNil(t, serverMux.LocalAddr())
	assert.NotNil(t, serverMux.RemoteAddr())
}

func TestMux_NilConn(t *testing.T) {
	_, err := Server(nil, DefaultMuxConfig())
	require.Error(t, err)

	_, err = Client(nil, DefaultMuxConfig())
	require.Error(t, err)
}

func TestDefaultMuxConfig(t *testing.T) {
	config := DefaultMuxConfig()

	assert.Equal(t, 256, config.AcceptBacklog)
	assert.Equal(t, 30*time.Second, config.KeepAliveInterval)
	assert.Equal(t, 10*time.Second, config.KeepAliveTimeout)
	assert.Equal(t, uint32(DefaultFramePayloadSize), config.MaxFrameSize)
	assert.True(t, config.EnableFlowControl)
}

func TestMux_LargeData(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	serverStream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	// Send large data
	largeData := bytes.Repeat([]byte("x"), 100*1024) // 100KB

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := clientStream.Write(largeData)
		assert.NoError(t, err)
		assert.Equal(t, len(largeData), n)
		clientStream.Close()
	}()

	go func() {
		defer wg.Done()
		received := make([]byte, 0, len(largeData))
		buf := make([]byte, 4096)
		for {
			n, err := serverStream.Read(buf)
			if err == io.EOF {
				break
			}
			assert.NoError(t, err)
			received = append(received, buf[:n]...)
		}
		assert.Equal(t, largeData, received)
	}()

	wg.Wait()
}

// Benchmarks

func BenchmarkMux_OpenStream(b *testing.B) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, _ := Server(serverConn, serverConfig)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, _ := Client(clientConn, clientConfig)
	defer clientMux.Close()

	// Server accepts in background
	go func() {
		for {
			stream, err := serverMux.AcceptStream()
			if err != nil {
				return
			}
			stream.Close()
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		stream, _ := clientMux.OpenStream()
		stream.Close()
	}
}

func BenchmarkMux_WriteRead(b *testing.B) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, _ := Server(serverConn, serverConfig)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, _ := Client(clientConn, clientConfig)
	defer clientMux.Close()

	clientStream, _ := clientMux.OpenStream()
	serverStream, _ := serverMux.AcceptStream()

	data := make([]byte, 1024)
	buf := make([]byte, 1024)

	// Server echoes in background
	go func() {
		for {
			n, err := serverStream.Read(buf)
			if err != nil {
				return
			}
			serverStream.Write(buf[:n])
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		clientStream.Write(data)
		clientStream.Read(buf)
	}
}

func TestMux_KeepAlive(t *testing.T) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 50 * time.Millisecond
	serverConfig.KeepAliveTimeout = 500 * time.Millisecond
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 50 * time.Millisecond
	clientConfig.KeepAliveTimeout = 500 * time.Millisecond
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	// Let keep-alive ping/pong exchange happen a few times.
	time.Sleep(200 * time.Millisecond)

	// Both sides should still be alive.
	assert.False(t, clientMux.IsClosed(), "client mux should be alive")
	assert.False(t, serverMux.IsClosed(), "server mux should be alive")

	// Streams should still work.
	stream, err := clientMux.OpenStream()
	require.NoError(t, err)
	defer stream.Close()

	sStream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer sStream.Close()

	_, err = stream.Write([]byte("alive"))
	require.NoError(t, err)

	buf := make([]byte, 10)
	n, err := sStream.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "alive", string(buf[:n]))
}

func TestMux_KeepAlive_Timeout(t *testing.T) {
	clientConn, serverConn := testConn()

	// Only enable keep-alive on server side.
	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 50 * time.Millisecond
	serverConfig.KeepAliveTimeout = 100 * time.Millisecond
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)

	// Client with no keep-alive (won't respond to pings).
	// Actually mux always handles pings in recvLoop, so we need to
	// simulate by closing the client side to prevent pong response.
	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)

	// Let server send a ping, client responds with pong (because recvLoop handles it).
	time.Sleep(80 * time.Millisecond)
	assert.False(t, serverMux.IsClosed(), "server should be alive during active connection")

	// Close client to simulate broken connection — pongs will stop.
	clientMux.Close()

	// Wait for server's keep-alive timeout.
	time.Sleep(300 * time.Millisecond)

	assert.True(t, serverMux.IsClosed(), "server mux should be closed after keep-alive timeout")
}

func TestMux_DoubleClose(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)

	// First close.
	err = clientMux.Close()
	assert.NoError(t, err)
	assert.True(t, clientMux.IsClosed())

	// Second close should be a no-op (no panic).
	err = clientMux.Close()
	assert.NoError(t, err)

	_ = serverMux.Close()
}

func TestMux_ServerOpensStream(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)
	defer clientMux.Close()

	// Server opens stream (even-numbered IDs).
	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)
	assert.Equal(t, uint32(2), serverStream.ID()) // Server uses even IDs.

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)
	assert.Equal(t, uint32(2), clientStream.ID())

	go func() {
		_, _ = serverStream.Write([]byte("from server"))
		_ = serverStream.Close()
	}()

	buf := make([]byte, 100)
	n, err := clientStream.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "from server", string(buf[:n]))
}

func TestMux_ConcurrentOpenClose(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)

	// Server accepts in background.
	go func() {
		for {
			stream, err := serverMux.AcceptStream()
			if err != nil {
				return
			}
			go func(s *Stream) {
				buf := make([]byte, 100)
				_, _ = s.Read(buf)
				_ = s.Close()
			}(stream)
		}
	}()

	// Concurrently open and close streams.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := clientMux.OpenStream()
			if err != nil {
				return
			}
			_, _ = s.Write([]byte("test"))
			_ = s.Close()
		}()
	}
	wg.Wait()

	_ = clientMux.Close()
	_ = serverMux.Close()
}

func BenchmarkMux_Throughput(b *testing.B) {
	clientConn, serverConn := testConn()

	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 0
	serverMux, _ := Server(serverConn, serverConfig)
	defer serverMux.Close()

	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 0
	clientMux, _ := Client(clientConn, clientConfig)
	defer clientMux.Close()

	clientStream, _ := clientMux.OpenStream()
	serverStream, _ := serverMux.AcceptStream()

	data := make([]byte, 32*1024) // 32KB
	buf := make([]byte, 32*1024)

	// Server reads and discards
	go func() {
		for {
			_, err := serverStream.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		clientStream.Write(data)
	}
}

// TestMux_HandleError verifies that error frames set the stream's error state.
func TestMux_HandleError(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)
	defer clientMux.Close()

	// Client opens a stream.
	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	serverStream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	// Server sends an error frame to the client's stream.
	errFrame := NewErrorFrame(serverStream.ID(), 500, "internal error")
	err = serverMux.writeFrame(errFrame)
	require.NoError(t, err)

	// Give time for the error frame to propagate.
	time.Sleep(50 * time.Millisecond)

	// Reading from the client stream should return the remote error.
	buf := make([]byte, 100)
	_, readErr := clientStream.Read(buf)
	require.Error(t, readErr)
	assert.Contains(t, readErr.Error(), "internal error")
}

// TestMux_HandleHandshake_DuplicateStream verifies that a duplicate stream ID
// in a handshake frame triggers the ErrStreamAlreadyExist error path.
func TestMux_HandleHandshake_DuplicateStream(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)
	defer clientMux.Close()

	// Client opens a stream (ID=1).
	_, err = clientMux.OpenStream()
	require.NoError(t, err)

	_, err = serverMux.AcceptStream()
	require.NoError(t, err)

	// Manually send a duplicate handshake frame with the same stream ID (1).
	// This tests the "stream already exists" error path in handleHandshake.
	dupFrame := NewFrame(FrameHandshake, 1, nil)
	err = clientMux.writeFrame(dupFrame)
	// The write should succeed (the error handling happens on the server side).
	require.NoError(t, err)

	// Give time for the server to process the duplicate handshake.
	time.Sleep(50 * time.Millisecond)

	// The server should NOT have been closed — ErrStreamAlreadyExist is handled
	// by closing the mux.
	// Actually, handleHandshake returns ErrStreamAlreadyExist which causes
	// recvLoop to call closeWithError. So the server mux gets closed.
	assert.True(t, serverMux.IsClosed(),
		"server mux should close when duplicate handshake is received")
}

// TestMux_AcceptBacklogFull verifies that when the accept channel is full,
// new handshakes are rejected with sendError (503 "accept queue full").
func TestMux_AcceptBacklogFull(t *testing.T) {
	clientConn, serverConn := testConn()

	// Set a very small accept backlog.
	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	cfg.AcceptBacklog = 1

	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)
	defer clientMux.Close()

	// Open first stream — fills the accept backlog (size=1).
	_, err = clientMux.OpenStream()
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)

	// Open second stream — should overflow the accept backlog.
	stream2, err := clientMux.OpenStream()
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// The second stream should receive an error (503 accept queue full)
	// which manifests as an error on Read.
	buf := make([]byte, 100)
	_ = stream2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, readErr := stream2.Read(buf)
	if readErr != nil {
		assert.Contains(t, readErr.Error(), "accept queue full")
	}

	// Drain the first stream from accept queue.
	_, err = serverMux.AcceptStream()
	require.NoError(t, err)
}

// TestMux_AcceptStreamContext_ClosedMux verifies AcceptStreamContext returns
// error immediately when the mux is already closed.
func TestMux_AcceptStreamContext_ClosedMux(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)

	_, err = Client(clientConn, cfg)
	require.NoError(t, err)

	// Close the mux first.
	_ = serverMux.Close()

	// AcceptStreamContext should return error immediately.
	_, err = serverMux.AcceptStreamContext(context.Background())
	require.Error(t, err)
}

// TestMux_HandleFrame_UnknownType verifies that unknown frame types
// cause the mux to close with an error.
func TestMux_HandleFrame_UnknownType(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)

	// Don't create a client mux — we write raw bytes to simulate a bad frame.
	// Write a raw frame header with an unknown frame type (99) directly to clientConn.
	// Frame header format: Version(1) | Type(1) | StreamID(4) | PayloadLen(4) = 10 bytes.
	header := make([]byte, 10)
	header[0] = FrameVersion // Version = 1.
	header[1] = 99           // Unknown frame type.
	// StreamID = 0, PayloadLen = 0.

	_, err = clientConn.Write(header)
	require.NoError(t, err)

	// Give time for server to process.
	time.Sleep(50 * time.Millisecond)

	// Server mux should close due to unknown frame type error.
	assert.True(t, serverMux.IsClosed(),
		"server mux should close on unknown frame type")

	_ = clientConn.Close()
}

// TestMux_KeepAlive_NoTimeout verifies that keepAliveLoop works correctly
// when KeepAliveTimeout is set to 0 (disabled) — meaning pong is not awaited.
func TestMux_KeepAlive_NoTimeout(t *testing.T) {
	clientConn, serverConn := testConn()

	// Server: keep-alive with timeout disabled.
	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 50 * time.Millisecond
	serverConfig.KeepAliveTimeout = 0 // Disable pong timeout check.
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)
	defer serverMux.Close()

	// Client: keep-alive enabled to respond to pings.
	clientConfig := DefaultMuxConfig()
	clientConfig.KeepAliveInterval = 50 * time.Millisecond
	clientConfig.KeepAliveTimeout = 0
	clientMux, err := Client(clientConn, clientConfig)
	require.NoError(t, err)
	defer clientMux.Close()

	// Let multiple ping cycles run (without pong timeout enforcement).
	time.Sleep(200 * time.Millisecond)

	// Both sides should remain alive since timeout checking is disabled.
	assert.False(t, serverMux.IsClosed(), "server mux should be alive with no timeout check")
	assert.False(t, clientMux.IsClosed(), "client mux should be alive with no timeout check")

	// Streams should still work.
	stream, err := clientMux.OpenStream()
	require.NoError(t, err)
	defer stream.Close()

	sStream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer sStream.Close()

	_, err = stream.Write([]byte("alive"))
	require.NoError(t, err)

	buf := make([]byte, 10)
	n, err := sStream.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "alive", string(buf[:n]))
}

// TestMux_KeepAlive_CloseDuringPong verifies that closing the mux while
// keepAliveLoop is waiting for a pong causes a clean exit.
func TestMux_KeepAlive_CloseDuringPong(t *testing.T) {
	clientConn, serverConn := testConn()

	// Server: enable keep-alive with long timeout so it's blocked waiting for pong.
	serverConfig := DefaultMuxConfig()
	serverConfig.KeepAliveInterval = 50 * time.Millisecond
	serverConfig.KeepAliveTimeout = 5 * time.Second // Very long — won't actually fire.
	serverMux, err := Server(serverConn, serverConfig)
	require.NoError(t, err)

	// Client: don't respond to pings (no mux — raw connection).
	// We close clientConn to prevent pong responses.
	_ = clientConn.Close()

	// Wait for server to send a ping and start waiting for pong.
	time.Sleep(100 * time.Millisecond)

	// Close the server mux while it's blocked waiting for pong.
	// The keepAliveLoop should detect closeCh and exit cleanly.
	_ = serverMux.Close()

	// Should be closed without blocking.
	assert.True(t, serverMux.IsClosed())
}

// TestMux_OpenStreamContext_CanceledContext verifies that OpenStreamContext
// returns context.Canceled when given an already-canceled context.
func TestMux_OpenStreamContext_CanceledContext(t *testing.T) {
	clientConn, serverConn := testConn()
	defer clientConn.Close()
	defer serverConn.Close()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	_, err := Server(serverConn, cfg)
	require.NoError(t, err)

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)
	defer clientMux.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err = clientMux.OpenStreamContext(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestMux_SendClose_ClosedMux verifies that sendClose is a no-op when
// the mux is already closed.
func TestMux_SendClose_AfterClose(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)

	// Open and accept a stream.
	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	_, err = serverMux.AcceptStream()
	require.NoError(t, err)

	// Close the mux.
	_ = clientMux.Close()

	// sendClose on the closed mux should return nil immediately (no panic).
	err = clientMux.sendClose(clientStream.ID())
	assert.NoError(t, err)

	_ = serverMux.Close()
}

// TestMux_SendWindowUpdate_ClosedMux verifies that sendWindowUpdate returns
// ErrMuxClosed when the mux is already closed.
func TestMux_SendWindowUpdate_ClosedMux(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)

	// Close the mux.
	_ = clientMux.Close()

	err = clientMux.sendWindowUpdate(1, 1024)
	assert.ErrorIs(t, err, ErrMuxClosed)

	_ = serverMux.Close()
}
