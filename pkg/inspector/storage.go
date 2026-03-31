package inspector

import (
	"sync"
)

// Storage is a thread-safe ring buffer for storing records.
type Storage struct {
	mu       sync.RWMutex
	records  []*Record
	capacity int
	head     int // next write position
	count    int // current number of records
	index    map[string]int
}

// NewStorage creates a new storage with the given capacity.
func NewStorage(capacity int) *Storage {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Storage{
		records:  make([]*Record, capacity),
		capacity: capacity,
		index:    make(map[string]int),
	}
}

// Add adds a record to the storage.
func (s *Storage) Add(r *Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If we're overwriting an existing record, remove it from the index.
	if s.count == s.capacity {
		old := s.records[s.head]
		if old != nil {
			delete(s.index, old.ID)
		}
	}

	// Store the record.
	s.records[s.head] = r
	s.index[r.ID] = s.head

	// Update position.
	s.head = (s.head + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}
}

// Get retrieves a record by ID.
func (s *Storage) Get(id string) *Record {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx, ok := s.index[id]
	if !ok {
		return nil
	}
	return s.records[idx]
}

// Update updates a record in the storage.
func (s *Storage) Update(r *Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx, ok := s.index[r.ID]
	if !ok {
		return
	}
	s.records[idx] = r
}

// List returns records with pagination (newest first).
func (s *Storage) List(limit, offset int) []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.count == 0 {
		return nil
	}

	// Calculate start and end positions (reading backwards from newest).
	start := (s.head - 1 + s.capacity) % s.capacity

	// Skip offset records.
	if offset >= s.count {
		return nil
	}

	// Adjust start for offset.
	start = (start - offset + s.capacity) % s.capacity

	// Calculate how many records to return.
	remaining := s.count - offset
	if limit <= 0 || limit > remaining {
		limit = remaining
	}

	result := make([]*Record, 0, limit)
	pos := start
	for i := 0; i < limit; i++ {
		if s.records[pos] != nil {
			result = append(result, s.records[pos])
		}
		pos = (pos - 1 + s.capacity) % s.capacity
	}

	return result
}

// ListSummaries returns record summaries with pagination (newest first).
func (s *Storage) ListSummaries(limit, offset int) []*RecordSummary {
	records := s.List(limit, offset)
	summaries := make([]*RecordSummary, len(records))
	for i, r := range records {
		summaries[i] = r.Summary()
	}
	return summaries
}

// Clear removes all records from the storage.
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = make([]*Record, s.capacity)
	s.index = make(map[string]int)
	s.head = 0
	s.count = 0
}

// Count returns the number of records in storage.
func (s *Storage) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// Capacity returns the storage capacity.
func (s *Storage) Capacity() int {
	return s.capacity
}
