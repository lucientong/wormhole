package testutil

import (
	"context"
	"net"
	"testing"
	"time"
)

// RequireNoError fails the test if err is not nil.
func RequireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// RequireError fails the test if err is nil.
func RequireError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// RequireEqual fails the test if expected != actual.
func RequireEqual[T comparable](t *testing.T, expected, actual T) {
	t.Helper()
	if expected != actual {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

// RequireTrue fails the test if condition is false.
func RequireTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Fatalf("condition failed: %s", msg)
	}
}

// WithTimeout returns a context that times out after the specified duration.
func WithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// GetFreePort returns an available TCP port.
func GetFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

// WaitFor waits for a condition to become true within the timeout.
func WaitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// Eventually asserts that the condition becomes true within the timeout.
func Eventually(t *testing.T, timeout time.Duration, interval time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatal("condition not met within timeout")
}

// RunInGoroutine runs the function in a goroutine and waits for completion.
// It fails the test if the function doesn't complete within the timeout.
func RunInGoroutine(t *testing.T, timeout time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(timeout):
		t.Fatal("goroutine did not complete within timeout")
	}
}
