package p2p

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPredictor_NoSamples(t *testing.T) {
	p := NewPredictor()
	candidates := p.Predict(5)
	assert.Len(t, candidates, 5)
	// All should be around default port 30000.
	for _, port := range candidates {
		assert.True(t, port > 1024 && port < 65536)
	}
}

func TestPredictor_SingleSample(t *testing.T) {
	p := NewPredictor()
	p.AddSample(40000)
	candidates := p.Predict(5)
	assert.Len(t, candidates, 5)
	// Should be around 40000.
	for _, port := range candidates {
		assert.True(t, port > 1024 && port < 65536)
	}
}

func TestPredictor_SequentialSamples(t *testing.T) {
	p := NewPredictor()
	p.AddSample(10000)
	p.AddSample(10001)
	p.AddSample(10002)

	candidates := p.Predict(10)
	assert.True(t, len(candidates) > 0)

	// First candidate should be around 10003 (delta=1).
	found := false
	for _, port := range candidates {
		if port == 10003 || port == 10004 {
			found = true
			break
		}
	}
	assert.True(t, found, "expected sequential prediction near 10003, got %v", candidates)
}

func TestPredictor_LargeDelta(t *testing.T) {
	p := NewPredictor()
	p.AddSample(10000)
	p.AddSample(10100)
	p.AddSample(10200)

	candidates := p.Predict(5)
	assert.True(t, len(candidates) > 0)

	// First candidate should be near 10300 (delta=100).
	found := false
	for _, port := range candidates {
		if port >= 10250 && port <= 10350 {
			found = true
			break
		}
	}
	assert.True(t, found, "expected prediction near 10300, got %v", candidates)
}

func TestPredictor_ZeroDelta(t *testing.T) {
	p := NewPredictor()
	p.AddSample(50000)
	p.AddSample(50000)
	p.AddSample(50000)

	candidates := p.Predict(5)
	assert.Len(t, candidates, 5)
	// With zero delta, should spread around 50000.
	for _, port := range candidates {
		assert.True(t, port > 1024 && port < 65536)
	}
}

func TestConnectionMode_String(t *testing.T) {
	assert.Equal(t, "Relay", ModeRelay.String())
	assert.Equal(t, "P2P", ModeP2P.String())
}

func TestManager_Disabled(t *testing.T) {
	config := DefaultManagerConfig()
	config.Enabled = false
	m := NewManager(config)

	assert.False(t, m.IsEnabled())
	assert.Equal(t, ModeRelay, m.Mode())
}
