package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PoolConfig contains configuration for a connection pool.
type PoolConfig struct {
	// MaxSize is the maximum number of connections in the pool.
	MaxSize int

	// MinSize is the minimum number of connections to maintain.
	MinSize int

	// MaxIdleTime is the maximum time a connection can be idle before being closed.
	MaxIdleTime time.Duration

	// HealthCheckInterval is the interval between health checks.
	HealthCheckInterval time.Duration

	// ConnectTimeout is the timeout for establishing new connections.
	ConnectTimeout time.Duration

	// MuxConfig is the configuration for multiplexers.
	MuxConfig MuxConfig
}

// DefaultPoolConfig returns the default pool configuration.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxSize:             10,
		MinSize:             1,
		MaxIdleTime:         5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		ConnectTimeout:      10 * time.Second,
		MuxConfig:           DefaultMuxConfig(),
	}
}

// DialFunc is a function that creates a new connection.
type DialFunc func(ctx context.Context) (net.Conn, error)

// Pool manages a pool of multiplexed connections.
type Pool struct {
	config   PoolConfig
	dialFunc DialFunc
	isClient bool

	// Connection management
	conns    []*poolConn
	connLock sync.RWMutex

	// State
	closed   uint32
	closeCh  chan struct{}
	closeWg  sync.WaitGroup

	// Stats
	stats PoolStats
}

// poolConn wraps a Mux with pool metadata.
type poolConn struct {
	mux        *Mux
	createdAt  time.Time
	lastUsedAt time.Time
	useCount   int64
	mu         sync.Mutex
}

// PoolStats contains pool statistics.
type PoolStats struct {
	// TotalConnections is the total number of connections created.
	TotalConnections int64

	// ActiveConnections is the current number of active connections.
	ActiveConnections int64

	// IdleConnections is the current number of idle connections.
	IdleConnections int64

	// TotalStreams is the total number of streams created.
	TotalStreams int64

	// FailedConnections is the number of failed connection attempts.
	FailedConnections int64

	// HealthCheckFailures is the number of health check failures.
	HealthCheckFailures int64
}

// NewPool creates a new connection pool.
func NewPool(config PoolConfig, dialFunc DialFunc, isClient bool) *Pool {
	p := &Pool{
		config:   config,
		dialFunc: dialFunc,
		isClient: isClient,
		conns:    make([]*poolConn, 0, config.MaxSize),
		closeCh:  make(chan struct{}),
	}

	// Start health check goroutine
	if config.HealthCheckInterval > 0 {
		p.closeWg.Add(1)
		go p.healthCheckLoop()
	}

	// Start idle cleanup goroutine
	if config.MaxIdleTime > 0 {
		p.closeWg.Add(1)
		go p.idleCleanupLoop()
	}

	return p
}

// Get returns a connection from the pool or creates a new one.
func (p *Pool) Get(ctx context.Context) (*Mux, error) {
	if p.IsClosed() {
		return nil, errors.New("pool is closed")
	}

	// Try to get an existing connection
	if conn := p.getIdleConn(); conn != nil {
		return conn, nil
	}

	// Create new connection
	return p.createConn(ctx)
}

// Put returns a connection to the pool.
func (p *Pool) Put(mux *Mux) {
	if p.IsClosed() || mux.IsClosed() {
		return
	}

	p.connLock.Lock()
	defer p.connLock.Unlock()

	// Find the poolConn and update last used time
	for _, pc := range p.conns {
		if pc.mux == mux {
			pc.mu.Lock()
			pc.lastUsedAt = time.Now()
			pc.mu.Unlock()
			return
		}
	}
}

// OpenStream gets a connection and opens a stream.
func (p *Pool) OpenStream(ctx context.Context) (*Stream, *Mux, error) {
	mux, err := p.Get(ctx)
	if err != nil {
		return nil, nil, err
	}

	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		// Don't put back a broken connection
		if mux.IsClosed() {
			p.removeConn(mux)
		}
		return nil, nil, err
	}

	atomic.AddInt64(&p.stats.TotalStreams, 1)
	return stream, mux, nil
}

// Close closes the pool and all connections.
func (p *Pool) Close() error {
	if !atomic.CompareAndSwapUint32(&p.closed, 0, 1) {
		return nil
	}

	close(p.closeCh)

	p.connLock.Lock()
	for _, pc := range p.conns {
		pc.mux.Close()
	}
	p.conns = nil
	p.connLock.Unlock()

	p.closeWg.Wait()
	return nil
}

// IsClosed returns whether the pool is closed.
func (p *Pool) IsClosed() bool {
	return atomic.LoadUint32(&p.closed) == 1
}

// Stats returns the current pool statistics.
func (p *Pool) Stats() PoolStats {
	p.connLock.RLock()
	defer p.connLock.RUnlock()

	stats := p.stats
	stats.ActiveConnections = int64(len(p.conns))

	idle := int64(0)
	for _, pc := range p.conns {
		if pc.mux.NumStreams() == 0 {
			idle++
		}
	}
	stats.IdleConnections = idle

	return stats
}

// Len returns the number of connections in the pool.
func (p *Pool) Len() int {
	p.connLock.RLock()
	defer p.connLock.RUnlock()
	return len(p.conns)
}

// getIdleConn gets an idle connection from the pool.
func (p *Pool) getIdleConn() *Mux {
	p.connLock.RLock()
	defer p.connLock.RUnlock()

	// Find a connection with capacity
	for _, pc := range p.conns {
		if !pc.mux.IsClosed() {
			pc.mu.Lock()
			pc.lastUsedAt = time.Now()
			pc.useCount++
			pc.mu.Unlock()
			return pc.mux
		}
	}

	return nil
}

// createConn creates a new connection.
func (p *Pool) createConn(ctx context.Context) (*Mux, error) {
	p.connLock.Lock()
	// Check if we're at max capacity
	if len(p.conns) >= p.config.MaxSize {
		p.connLock.Unlock()
		// Return an existing connection even if it's busy
		return p.getIdleConn(), nil
	}
	p.connLock.Unlock()

	// Create connection with timeout
	dialCtx := ctx
	if p.config.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, p.config.ConnectTimeout)
		defer cancel()
	}

	conn, err := p.dialFunc(dialCtx)
	if err != nil {
		atomic.AddInt64(&p.stats.FailedConnections, 1)
		return nil, err
	}

	// Create multiplexer
	var mux *Mux
	if p.isClient {
		mux, err = Client(conn, p.config.MuxConfig)
	} else {
		mux, err = Server(conn, p.config.MuxConfig)
	}
	if err != nil {
		conn.Close()
		atomic.AddInt64(&p.stats.FailedConnections, 1)
		return nil, err
	}

	pc := &poolConn{
		mux:        mux,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		useCount:   1,
	}

	p.connLock.Lock()
	p.conns = append(p.conns, pc)
	p.connLock.Unlock()

	atomic.AddInt64(&p.stats.TotalConnections, 1)
	return mux, nil
}

// removeConn removes a connection from the pool.
func (p *Pool) removeConn(mux *Mux) {
	p.connLock.Lock()
	defer p.connLock.Unlock()

	for i, pc := range p.conns {
		if pc.mux == mux {
			pc.mux.Close()
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			return
		}
	}
}

// healthCheckLoop periodically checks connection health.
func (p *Pool) healthCheckLoop() {
	defer p.closeWg.Done()

	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.healthCheck()
		case <-p.closeCh:
			return
		}
	}
}

// healthCheck checks all connections and removes unhealthy ones.
func (p *Pool) healthCheck() {
	p.connLock.RLock()
	connsToCheck := make([]*poolConn, len(p.conns))
	copy(connsToCheck, p.conns)
	p.connLock.RUnlock()

	for _, pc := range connsToCheck {
		if pc.mux.IsClosed() {
			p.removeConn(pc.mux)
			atomic.AddInt64(&p.stats.HealthCheckFailures, 1)
		}
	}
}

// idleCleanupLoop removes idle connections.
func (p *Pool) idleCleanupLoop() {
	defer p.closeWg.Done()

	ticker := time.NewTicker(p.config.MaxIdleTime / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupIdle()
		case <-p.closeCh:
			return
		}
	}
}

// cleanupIdle removes connections that have been idle too long.
func (p *Pool) cleanupIdle() {
	p.connLock.Lock()
	defer p.connLock.Unlock()

	now := time.Now()
	threshold := p.config.MaxIdleTime

	// Keep at least MinSize connections
	toRemove := make([]*poolConn, 0)
	for _, pc := range p.conns {
		if len(p.conns)-len(toRemove) <= p.config.MinSize {
			break
		}

		pc.mu.Lock()
		idle := now.Sub(pc.lastUsedAt)
		hasNoStreams := pc.mux.NumStreams() == 0
		pc.mu.Unlock()

		if idle > threshold && hasNoStreams {
			toRemove = append(toRemove, pc)
		}
	}

	// Remove idle connections
	for _, pc := range toRemove {
		pc.mux.Close()
		for i, conn := range p.conns {
			if conn == pc {
				p.conns = append(p.conns[:i], p.conns[i+1:]...)
				break
			}
		}
	}
}

// Warmup pre-creates connections up to MinSize.
func (p *Pool) Warmup(ctx context.Context) error {
	for i := 0; i < p.config.MinSize; i++ {
		if _, err := p.createConn(ctx); err != nil {
			return err
		}
	}
	return nil
}
