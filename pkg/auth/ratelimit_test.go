package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_NotBlockedInitially(t *testing.T) {
	rl := NewRateLimiter(DefaultRateLimitConfig())
	defer rl.Close()

	assert.False(t, rl.IsBlocked("192.168.1.1"))
}

func TestRateLimiter_BlocksAfterMaxFailures(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     3,
		Window:          1 * time.Minute,
		BlockDuration:   5 * time.Minute,
		CleanupInterval: 1 * time.Hour, // Disable cleanup for test.
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	ip := "192.168.1.1"

	// First failure - not blocked.
	blocked := rl.RecordFailure(ip)
	assert.False(t, blocked)
	assert.False(t, rl.IsBlocked(ip))

	// Second failure - not blocked.
	blocked = rl.RecordFailure(ip)
	assert.False(t, blocked)
	assert.False(t, rl.IsBlocked(ip))

	// Third failure - now blocked.
	blocked = rl.RecordFailure(ip)
	assert.True(t, blocked)
	assert.True(t, rl.IsBlocked(ip))
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     2,
		Window:          1 * time.Minute,
		BlockDuration:   5 * time.Minute,
		CleanupInterval: 1 * time.Hour,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	// Block IP1.
	rl.RecordFailure(ip1)
	rl.RecordFailure(ip1)
	assert.True(t, rl.IsBlocked(ip1))

	// IP2 should not be affected.
	assert.False(t, rl.IsBlocked(ip2))
	rl.RecordFailure(ip2)
	assert.False(t, rl.IsBlocked(ip2))
}

func TestRateLimiter_SuccessClearsFailures(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     3,
		Window:          1 * time.Minute,
		BlockDuration:   5 * time.Minute,
		CleanupInterval: 1 * time.Hour,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	ip := "192.168.1.1"

	// Two failures.
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	assert.False(t, rl.IsBlocked(ip))

	// Successful auth clears failures.
	rl.RecordSuccess(ip)

	// Need 3 more failures to block.
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	assert.False(t, rl.IsBlocked(ip))

	rl.RecordFailure(ip)
	assert.True(t, rl.IsBlocked(ip))
}

func TestRateLimiter_Unblock(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     2,
		Window:          1 * time.Minute,
		BlockDuration:   5 * time.Minute,
		CleanupInterval: 1 * time.Hour,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	ip := "192.168.1.1"

	// Block the IP.
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	assert.True(t, rl.IsBlocked(ip))

	// Manual unblock.
	rl.Unblock(ip)
	assert.False(t, rl.IsBlocked(ip))
}

func TestRateLimiter_WindowReset(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     3,
		Window:          50 * time.Millisecond,
		BlockDuration:   5 * time.Minute,
		CleanupInterval: 1 * time.Hour,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	ip := "192.168.1.1"

	// Two failures.
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	assert.False(t, rl.IsBlocked(ip))

	// Wait for window to expire.
	time.Sleep(60 * time.Millisecond)

	// Failure count should reset.
	rl.RecordFailure(ip)
	assert.False(t, rl.IsBlocked(ip))

	rl.RecordFailure(ip)
	assert.False(t, rl.IsBlocked(ip))

	// Third failure in new window blocks.
	rl.RecordFailure(ip)
	assert.True(t, rl.IsBlocked(ip))
}

func TestRateLimiter_BlockExpiry(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     2,
		Window:          1 * time.Minute,
		BlockDuration:   50 * time.Millisecond,
		CleanupInterval: 1 * time.Hour,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	ip := "192.168.1.1"

	// Block the IP.
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	assert.True(t, rl.IsBlocked(ip))

	// Wait for block to expire.
	time.Sleep(60 * time.Millisecond)

	// Should no longer be blocked.
	assert.False(t, rl.IsBlocked(ip))
}

func TestRateLimiter_GetBlockedIPs(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     2,
		Window:          1 * time.Minute,
		BlockDuration:   5 * time.Minute,
		CleanupInterval: 1 * time.Hour,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	// Block two IPs.
	rl.RecordFailure("192.168.1.1")
	rl.RecordFailure("192.168.1.1")

	rl.RecordFailure("192.168.1.2")
	rl.RecordFailure("192.168.1.2")

	// One IP with failures but not blocked.
	rl.RecordFailure("192.168.1.3")

	blocked := rl.GetBlockedIPs()
	assert.Len(t, blocked, 2)
	assert.Contains(t, blocked, "192.168.1.1")
	assert.Contains(t, blocked, "192.168.1.2")
}

func TestRateLimiter_Stats(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     2,
		Window:          1 * time.Minute,
		BlockDuration:   5 * time.Minute,
		CleanupInterval: 1 * time.Hour,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	// Initial stats.
	stats := rl.Stats()
	assert.Equal(t, 0, stats.TrackedIPs)
	assert.Equal(t, 0, stats.BlockedIPs)

	// Add some activity.
	rl.RecordFailure("192.168.1.1")
	rl.RecordFailure("192.168.1.2")
	rl.RecordFailure("192.168.1.2")

	stats = rl.Stats()
	assert.Equal(t, 2, stats.TrackedIPs)
	assert.Equal(t, 1, stats.BlockedIPs)
}

func TestRateLimiter_Cleanup(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     2,
		Window:          50 * time.Millisecond,
		BlockDuration:   50 * time.Millisecond,
		CleanupInterval: 20 * time.Millisecond,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	// Add failures.
	rl.RecordFailure("192.168.1.1")
	rl.RecordFailure("192.168.1.2")
	rl.RecordFailure("192.168.1.2")

	stats := rl.Stats()
	require.Equal(t, 2, stats.TrackedIPs)

	// Wait for cleanup.
	time.Sleep(100 * time.Millisecond)

	// Records should be cleaned up.
	stats = rl.Stats()
	assert.Equal(t, 0, stats.TrackedIPs)
}

func TestRateLimiter_ContinuedFailuresExtendBlock(t *testing.T) {
	config := RateLimitConfig{
		MaxFailures:     2,
		Window:          1 * time.Minute,
		BlockDuration:   100 * time.Millisecond,
		CleanupInterval: 1 * time.Hour,
	}
	rl := NewRateLimiter(config)
	defer rl.Close()

	ip := "192.168.1.1"

	// Block the IP.
	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	assert.True(t, rl.IsBlocked(ip))

	// Wait 60ms (less than block duration).
	time.Sleep(60 * time.Millisecond)

	// Another failure should extend the block.
	rl.RecordFailure(ip)
	assert.True(t, rl.IsBlocked(ip))

	// Wait 60ms again - should still be blocked since we refreshed.
	time.Sleep(60 * time.Millisecond)
	assert.True(t, rl.IsBlocked(ip))

	// Wait full block duration.
	time.Sleep(110 * time.Millisecond)
	assert.False(t, rl.IsBlocked(ip))
}
