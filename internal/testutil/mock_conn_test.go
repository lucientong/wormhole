package testutil

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockAddr(t *testing.T) {
	addr := MockAddr{NetworkStr: "tcp", AddrStr: "127.0.0.1:8080"}
	assert.Equal(t, "tcp", addr.Network())
	assert.Equal(t, "127.0.0.1:8080", addr.String())
}

func TestNewMockConnPair(t *testing.T) {
	c1, c2 := NewMockConnPair()
	require.NotNil(t, c1)
	require.NotNil(t, c2)

	// Verify addresses are set.
	assert.NotNil(t, c1.LocalAddr())
	assert.NotNil(t, c1.RemoteAddr())
	assert.NotNil(t, c2.LocalAddr())
	assert.NotNil(t, c2.RemoteAddr())

	// Local addr of c1 should be remote addr of c2.
	assert.Equal(t, c1.LocalAddr().String(), c2.RemoteAddr().String())
	assert.Equal(t, c1.RemoteAddr().String(), c2.LocalAddr().String())
}

func TestMockConn_ReadWrite(t *testing.T) {
	c1, c2 := NewMockConnPair()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	msg := []byte("hello world")

	// Write from c1, read from c2.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := c1.Write(msg)
		require.NoError(t, err)
		assert.Equal(t, len(msg), n)
	}()

	buf := make([]byte, 64)
	n, err := c2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, msg, buf[:n])
	wg.Wait()
}

func TestMockConn_Bidirectional(t *testing.T) {
	c1, c2 := NewMockConnPair()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	// Write from c2, read from c1.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := c2.Write([]byte("response"))
		require.NoError(t, err)
	}()

	buf := make([]byte, 64)
	n, err := c1.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "response", string(buf[:n]))
	wg.Wait()
}

func TestMockConn_Close(t *testing.T) {
	c1, c2 := NewMockConnPair()

	assert.False(t, c1.IsClosed())
	assert.False(t, c2.IsClosed())

	err := c1.Close()
	assert.NoError(t, err)
	assert.True(t, c1.IsClosed())

	// Double close should not error.
	err = c1.Close()
	assert.NoError(t, err)
}

func TestMockConn_ReadAfterClose(t *testing.T) {
	c1, _ := NewMockConnPair()
	_ = c1.Close()

	buf := make([]byte, 64)
	_, err := c1.Read(buf)
	assert.Equal(t, io.EOF, err)
}

func TestMockConn_WriteAfterClose(t *testing.T) {
	c1, _ := NewMockConnPair()
	_ = c1.Close()

	_, err := c1.Write([]byte("data"))
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestMockConn_SetDeadline(t *testing.T) {
	c1, _ := NewMockConnPair()
	defer func() { _ = c1.Close() }()

	// These should not error (no-op).
	assert.NoError(t, c1.SetDeadline(time.Now().Add(time.Second)))
	assert.NoError(t, c1.SetReadDeadline(time.Now().Add(time.Second)))
	assert.NoError(t, c1.SetWriteDeadline(time.Now().Add(time.Second)))
}
