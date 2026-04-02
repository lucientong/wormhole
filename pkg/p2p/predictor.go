package p2p

import (
	"math/rand/v2"
	"sync"
)

// Predictor predicts the next external port for symmetric NAT traversal.
//
// Symmetric NATs assign a new external port for each unique (dest IP, dest port)
// tuple. Some implementations increment ports sequentially, making prediction
// possible. This is a heuristic and may not work for all NAT implementations.
type Predictor struct {
	mu sync.Mutex
	// ports tracks observed external ports.
	ports []int
}

// NewPredictor creates a new port predictor.
func NewPredictor() *Predictor {
	return &Predictor{}
}

// AddSample adds an observed external port to the predictor.
func (p *Predictor) AddSample(port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ports = append(p.ports, port)
}

// Predict returns a list of candidate ports that the peer's NAT might use.
// It uses delta-based prediction and adds randomized candidates around the
// predicted range for better coverage.
func (p *Predictor) Predict(count int) []int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.ports) < 2 {
		return p.spreadPorts(p.lastPort(), count)
	}

	// Calculate average delta between consecutive samples.
	var totalDelta int
	for i := 1; i < len(p.ports); i++ {
		totalDelta += p.ports[i] - p.ports[i-1]
	}
	avgDelta := totalDelta / (len(p.ports) - 1)

	if avgDelta == 0 {
		// No consistent pattern — spread around last known port.
		return p.spreadPorts(p.lastPort(), count)
	}

	// Predict next ports based on average delta.
	candidates := make([]int, 0, count)
	lastPort := p.lastPort()

	for i := 1; i <= count/2; i++ {
		predicted := lastPort + avgDelta*i
		if predicted > 0 && predicted < 65536 {
			candidates = append(candidates, predicted)
		}
	}

	// Add spread candidates for coverage.
	remaining := count - len(candidates)
	if remaining > 0 {
		spread := p.spreadPorts(lastPort+avgDelta, remaining)
		candidates = append(candidates, spread...)
	}

	return candidates
}

// lastPort returns the last observed port, or a default.
func (p *Predictor) lastPort() int {
	if len(p.ports) == 0 {
		return 30000
	}
	return p.ports[len(p.ports)-1]
}

// spreadPorts generates candidate ports around a center port.
func (p *Predictor) spreadPorts(center, count int) []int {
	candidates := make([]int, 0, count)
	seen := make(map[int]bool)

	// Clamp center to valid range.
	if center <= 1024 {
		center = 1025
	}
	if center >= 65536 {
		center = 65535
	}

	// Add center first.
	candidates = append(candidates, center)
	seen[center] = true

	// Add nearby ports with random jitter.
	// Limit iterations to avoid infinite loop when near port boundaries.
	maxIterations := count * 20
	for i := 0; len(candidates) < count && i < maxIterations; i++ {
		offset := rand.IntN(256) - 128 // #nosec G404 -- non-security random for port prediction
		port := center + offset
		if port > 1024 && port < 65536 && !seen[port] {
			candidates = append(candidates, port)
			seen[port] = true
		}
	}

	return candidates
}
