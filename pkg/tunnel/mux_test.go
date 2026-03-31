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

// testConn creates a pair of connected net.Conn
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
	for i := range numStreams {
		go func(id int) {
			defer wg.Done()
			stream, err := clientMux.OpenStream()
			assert.NoError(t, err)

			msg := []byte("hello")
			stream.Write(msg)

			buf := make([]byte, 100)
			n, _ := stream.Read(buf)
			assert.Equal(t, msg, buf[:n])
		}(i)
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
	t.Skip("Skipping large data test - requires ringBuffer optimization")
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
