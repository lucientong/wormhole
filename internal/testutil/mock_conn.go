package testutil

import (
	"io"
	"net"
	"sync"
	"time"
)

// MockConn implements net.Conn for testing purposes.
// It uses two connected pipes for bidirectional communication.
type MockConn struct {
	reader     *io.PipeReader
	writer     *io.PipeWriter
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     bool
	mu         sync.Mutex
}

// MockAddr implements net.Addr for testing.
type MockAddr struct {
	NetworkStr string
	AddrStr    string
}

func (a MockAddr) Network() string { return a.NetworkStr }
func (a MockAddr) String() string  { return a.AddrStr }

// NewMockConnPair creates a pair of connected MockConn instances.
// Data written to one connection can be read from the other.
func NewMockConnPair() (*MockConn, *MockConn) {
	// Create two pipes for bidirectional communication
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	conn1 := &MockConn{
		reader:     r1,
		writer:     w2,
		localAddr:  MockAddr{NetworkStr: "tcp", AddrStr: "127.0.0.1:1234"},
		remoteAddr: MockAddr{NetworkStr: "tcp", AddrStr: "127.0.0.1:5678"},
	}

	conn2 := &MockConn{
		reader:     r2,
		writer:     w1,
		localAddr:  MockAddr{NetworkStr: "tcp", AddrStr: "127.0.0.1:5678"},
		remoteAddr: MockAddr{NetworkStr: "tcp", AddrStr: "127.0.0.1:1234"},
	}

	return conn1, conn2
}

// Read reads data from the connection.
func (c *MockConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}
	c.mu.Unlock()
	return c.reader.Read(b)
}

// Write writes data to the connection.
func (c *MockConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()
	return c.writer.Write(b)
}

// Close closes the connection.
func (c *MockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.reader.Close()
	c.writer.Close()
	return nil
}

// LocalAddr returns the local network address.
func (c *MockConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote network address.
func (c *MockConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (c *MockConn) SetDeadline(t time.Time) error {
	return nil // Not implemented for mock
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *MockConn) SetReadDeadline(t time.Time) error {
	return nil // Not implemented for mock
}

// SetWriteDeadline sets the deadline for future Write calls.
func (c *MockConn) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented for mock
}

// IsClosed returns whether the connection is closed.
func (c *MockConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}
