package p2p

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTransportConfig_Defaults(t *testing.T) {
	config := DefaultTransportConfig()

	assert.Equal(t, 1400, config.MaxPacketSize)
	assert.Equal(t, 200*time.Millisecond, config.RetransmitTimeout)
	assert.Equal(t, 10, config.MaxRetransmits)
	assert.Equal(t, 5*time.Second, config.AckTimeout)
	assert.Equal(t, 256, config.RecvBufferSize)
}
