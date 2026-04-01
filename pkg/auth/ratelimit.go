package auth

import (
	"sync"
	"time"
)

// RateLimitConfig configures the rate limiter behavior.
type RateLimitConfig struct {
	// MaxFailures is the maximum number of auth failures before blocking.
	MaxFailures int

	// Window is the time window for counting failures.
	Window time.Duration

	// BlockDuration is how long to block after exceeding MaxFailures.
	BlockDuration time.Duration

	// CleanupInterval is how often to clean up expired entries.
	CleanupInterval time.Duration
}

// DefaultRateLimitConfig returns sensible defaults for rate limiting.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		MaxFailures:     5,
		Window:          5 * time.Minute,
		BlockDuration:   15 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}
}

// ipRecord tracks authentication attempts for a single IP.
type ipRecord struct {
	failures    int       // Number of failures in current window.
	windowStart time.Time // Start of the current counting window.
	blockedAt   time.Time // When the IP was blocked (zero if not blocked).
}

// RateLimiter tracks authentication failures and blocks IPs.
type RateLimiter struct {
	config RateLimitConfig

	records  map[string]*ipRecord
	mu       sync.RWMutex
	closed   chan struct{}
	stopOnce sync.Once
}

// NewRateLimiter creates a new rate limiter with the given config.
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		config:  config,
		records: make(map[string]*ipRecord),
		closed:  make(chan struct{}),
	}

	// Start background cleanup goroutine.
	go rl.cleanupLoop()

	return rl
}

// IsBlocked checks if the given IP is currently blocked.
func (rl *RateLimiter) IsBlocked(ip string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	record, ok := rl.records[ip]
	if !ok {
		return false
	}

	if record.blockedAt.IsZero() {
		return false
	}

	// Check if block has expired.
	return time.Since(record.blockedAt) < rl.config.BlockDuration
}

// RecordFailure records an authentication failure for the given IP.
// Returns true if the IP is now blocked.
func (rl *RateLimiter) RecordFailure(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	record, ok := rl.records[ip]

	if !ok {
		// First failure for this IP.
		rl.records[ip] = &ipRecord{
			failures:    1,
			windowStart: now,
		}
		return false
	}

	// If already blocked, extend the block.
	if !record.blockedAt.IsZero() {
		if time.Since(record.blockedAt) < rl.config.BlockDuration {
			// Still blocked, refresh the block time.
			record.blockedAt = now
			return true
		}
		// Block expired, reset record.
		record.failures = 1
		record.windowStart = now
		record.blockedAt = time.Time{}
		return false
	}

	// Check if we need to reset the window.
	if time.Since(record.windowStart) > rl.config.Window {
		record.failures = 1
		record.windowStart = now
		return false
	}

	// Increment failure count.
	record.failures++

	// Check if threshold exceeded.
	if record.failures >= rl.config.MaxFailures {
		record.blockedAt = now
		return true
	}

	return false
}

// RecordSuccess records a successful authentication, clearing failure count.
func (rl *RateLimiter) RecordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.records, ip)
}

// Unblock manually unblocks an IP address.
func (rl *RateLimiter) Unblock(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.records, ip)
}

// GetBlockedIPs returns a list of currently blocked IP addresses.
func (rl *RateLimiter) GetBlockedIPs() []string {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	var blocked []string
	now := time.Now()

	for ip, record := range rl.records {
		if !record.blockedAt.IsZero() && now.Sub(record.blockedAt) < rl.config.BlockDuration {
			blocked = append(blocked, ip)
		}
	}

	return blocked
}

// Stats returns rate limiter statistics.
type RateLimiterStats struct {
	TrackedIPs int `json:"tracked_ips"`
	BlockedIPs int `json:"blocked_ips"`
}

// Stats returns current rate limiter statistics.
func (rl *RateLimiter) Stats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := RateLimiterStats{
		TrackedIPs: len(rl.records),
	}

	now := time.Now()
	for _, record := range rl.records {
		if !record.blockedAt.IsZero() && now.Sub(record.blockedAt) < rl.config.BlockDuration {
			stats.BlockedIPs++
		}
	}

	return stats
}

// cleanupLoop periodically removes expired records.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.closed:
			return
		}
	}
}

// cleanup removes expired records.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	for ip, record := range rl.records {
		// Remove if block has expired.
		if !record.blockedAt.IsZero() {
			if now.Sub(record.blockedAt) > rl.config.BlockDuration {
				delete(rl.records, ip)
				continue
			}
		}

		// Remove if window has expired and not blocked.
		if record.blockedAt.IsZero() && now.Sub(record.windowStart) > rl.config.Window {
			delete(rl.records, ip)
		}
	}
}

// Close stops the rate limiter and its cleanup goroutine.
func (rl *RateLimiter) Close() {
	rl.stopOnce.Do(func() {
		close(rl.closed)
	})
}
