package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatBool(t *testing.T) {
	assert.Equal(t, "✅ Yes", formatBool(true))
	assert.Equal(t, "❌ No", formatBool(false))
}

func TestFormatEnvironmentTable(t *testing.T) {
	table := formatEnvironmentTable()
	assert.Contains(t, table, "Home broadband")
	assert.Contains(t, table, "Carrier-grade NAT")
	assert.Contains(t, table, "Cloud VPS/server")
}
