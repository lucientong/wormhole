package testutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRequireNoError(t *testing.T) {
	// Should not fail with nil error.
	RequireNoError(t, nil)
}

func TestRequireError(t *testing.T) {
	// Should not fail with non-nil error.
	RequireError(t, assert.AnError)
}

func TestRequireEqual(t *testing.T) {
	RequireEqual(t, 42, 42)
	RequireEqual(t, "hello", "hello")
	RequireEqual(t, true, true)
}

func TestRequireTrue(t *testing.T) {
	RequireTrue(t, true, "should be true")
}

func TestWithTimeout(t *testing.T) {
	ctx := WithTimeout(t, 5*time.Second)
	assert.NotNil(t, ctx)

	// Context should not be done yet.
	select {
	case <-ctx.Done():
		t.Fatal("context should not be done")
	default:
		// OK.
	}
}

func TestGetFreePort(t *testing.T) {
	port := GetFreePort(t)
	assert.Greater(t, port, 0)
	assert.Less(t, port, 65536)

	// Two calls should return different ports.
	port2 := GetFreePort(t)
	assert.NotEqual(t, port, port2)
}

func TestWaitFor_ImmediateSuccess(t *testing.T) {
	WaitFor(t, time.Second, func() bool {
		return true
	})
}

func TestWaitFor_EventualSuccess(t *testing.T) {
	start := time.Now()
	count := 0
	WaitFor(t, time.Second, func() bool {
		count++
		return count >= 3
	})
	assert.WithinDuration(t, start, time.Now(), 500*time.Millisecond)
}

func TestEventually_ImmediateSuccess(t *testing.T) {
	Eventually(t, time.Second, 10*time.Millisecond, func() bool {
		return true
	})
}

func TestEventually_DelayedSuccess(t *testing.T) {
	deadline := time.Now().Add(50 * time.Millisecond)
	Eventually(t, time.Second, 10*time.Millisecond, func() bool {
		return time.Now().After(deadline)
	})
}

func TestRunInGoroutine_Completes(t *testing.T) {
	called := false
	RunInGoroutine(t, time.Second, func() {
		called = true
	})
	assert.True(t, called)
}
