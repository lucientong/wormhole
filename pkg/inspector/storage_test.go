package inspector

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage_Add(t *testing.T) {
	s := NewStorage(5)

	// Add some records.
	for i := 0; i < 3; i++ {
		r := &Record{ID: fmt.Sprintf("r%d", i)}
		s.Add(r)
	}

	assert.Equal(t, 3, s.Count())
	assert.Equal(t, 5, s.Capacity())
}

func TestStorage_Get(t *testing.T) {
	s := NewStorage(10)

	// Add a record.
	r := &Record{ID: "test-id", Method: "GET"}
	s.Add(r)

	// Get it back.
	got := s.Get("test-id")
	require.NotNil(t, got)
	assert.Equal(t, "test-id", got.ID)
	assert.Equal(t, "GET", got.Method)

	// Get non-existent.
	assert.Nil(t, s.Get("non-existent"))
}

func TestStorage_Update(t *testing.T) {
	s := NewStorage(10)

	// Add a record.
	r := &Record{ID: "test-id", Method: "GET"}
	s.Add(r)

	// Update it.
	updated := &Record{ID: "test-id", Method: "POST"}
	s.Update(updated)

	// Verify update.
	got := s.Get("test-id")
	require.NotNil(t, got)
	assert.Equal(t, "POST", got.Method)
}

func TestStorage_List(t *testing.T) {
	s := NewStorage(10)

	// Add records.
	for i := 0; i < 5; i++ {
		r := &Record{ID: fmt.Sprintf("r%d", i)}
		s.Add(r)
	}

	// List all (newest first).
	records := s.List(10, 0)
	require.Len(t, records, 5)
	assert.Equal(t, "r4", records[0].ID) // newest
	assert.Equal(t, "r0", records[4].ID) // oldest

	// List with limit.
	records = s.List(2, 0)
	require.Len(t, records, 2)
	assert.Equal(t, "r4", records[0].ID)
	assert.Equal(t, "r3", records[1].ID)

	// List with offset.
	records = s.List(2, 2)
	require.Len(t, records, 2)
	assert.Equal(t, "r2", records[0].ID)
	assert.Equal(t, "r1", records[1].ID)
}

func TestStorage_RingBuffer(t *testing.T) {
	s := NewStorage(3)

	// Fill the buffer.
	for i := 0; i < 3; i++ {
		r := &Record{ID: fmt.Sprintf("r%d", i)}
		s.Add(r)
	}
	assert.Equal(t, 3, s.Count())

	// Add more, should overwrite oldest.
	s.Add(&Record{ID: "r3"})
	assert.Equal(t, 3, s.Count())

	// r0 should be gone.
	assert.Nil(t, s.Get("r0"))

	// r1, r2, r3 should exist.
	assert.NotNil(t, s.Get("r1"))
	assert.NotNil(t, s.Get("r2"))
	assert.NotNil(t, s.Get("r3"))

	// List order should be r3, r2, r1.
	records := s.List(10, 0)
	require.Len(t, records, 3)
	assert.Equal(t, "r3", records[0].ID)
	assert.Equal(t, "r2", records[1].ID)
	assert.Equal(t, "r1", records[2].ID)
}

func TestStorage_Clear(t *testing.T) {
	s := NewStorage(10)

	// Add some records.
	for i := 0; i < 5; i++ {
		s.Add(&Record{ID: fmt.Sprintf("r%d", i)})
	}
	assert.Equal(t, 5, s.Count())

	// Clear.
	s.Clear()
	assert.Equal(t, 0, s.Count())
	assert.Nil(t, s.Get("r0"))

	// Can add again.
	s.Add(&Record{ID: "new"})
	assert.Equal(t, 1, s.Count())
}

func TestStorage_ListSummaries(t *testing.T) {
	s := NewStorage(10)

	r := &Record{
		ID:     "test",
		Method: "GET",
		URL:    "http://example.com/path",
		Status: 200,
	}
	s.Add(r)

	summaries := s.ListSummaries(10, 0)
	require.Len(t, summaries, 1)
	assert.Equal(t, "test", summaries[0].ID)
	assert.Equal(t, "GET", summaries[0].Method)
	assert.Equal(t, 200, summaries[0].Status)
}

func TestStorage_EmptyList(t *testing.T) {
	s := NewStorage(10)

	records := s.List(10, 0)
	assert.Empty(t, records)

	records = s.List(10, 5)
	assert.Empty(t, records)
}
