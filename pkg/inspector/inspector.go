package inspector

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"
)

// Config holds the inspector configuration.
type Config struct {
	MaxRecords    int   // Maximum number of records to keep.
	MaxBodySize   int64 // Maximum body size to capture (per request/response).
	EnableCapture bool  // Whether to capture traffic.
}

// DefaultConfig returns the default inspector configuration.
func DefaultConfig() Config {
	return Config{
		MaxRecords:    1000,
		MaxBodySize:   1024 * 1024, // 1MB
		EnableCapture: true,
	}
}

// Inspector captures and stores HTTP traffic.
type Inspector struct {
	config      Config
	storage     *Storage
	subscribers []chan *Record
	mu          sync.RWMutex
	closed      bool
}

// New creates a new inspector with the given configuration.
func New(config Config) *Inspector {
	if config.MaxRecords <= 0 {
		config.MaxRecords = 1000
	}
	if config.MaxBodySize <= 0 {
		config.MaxBodySize = 1024 * 1024
	}

	return &Inspector{
		config:  config,
		storage: NewStorage(config.MaxRecords),
	}
}

// Capture records a request/response pair.
func (i *Inspector) Capture(req *http.Request, reqBody []byte, resp *http.Response, respBody []byte, duration time.Duration, err error) *Record {
	if !i.IsEnabled() {
		return nil
	}

	record := NewRecord(generateID(), req)
	record.SetRequestBody(reqBody, i.config.MaxBodySize)

	if resp != nil {
		record.SetResponse(resp, respBody, i.config.MaxBodySize)
	}

	if err != nil {
		record.SetError(err)
	}

	record.Complete(duration)

	i.storage.Add(record)
	i.notify(record)

	return record
}

// Subscribe returns a channel that receives new records.
func (i *Inspector) Subscribe() <-chan *Record {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		ch := make(chan *Record)
		close(ch)
		return ch
	}

	ch := make(chan *Record, 100)
	i.subscribers = append(i.subscribers, ch)
	return ch
}

// Unsubscribe removes a subscriber channel.
func (i *Inspector) Unsubscribe(ch <-chan *Record) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for idx, sub := range i.subscribers {
		if sub == ch {
			close(sub)
			i.subscribers = append(i.subscribers[:idx], i.subscribers[idx+1:]...)
			return
		}
	}
}

// notify sends a record to all subscribers.
func (i *Inspector) notify(r *Record) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	for _, ch := range i.subscribers {
		select {
		case ch <- r:
		default:
			// Channel full, skip.
		}
	}
}

// Records returns paginated records.
func (i *Inspector) Records(limit, offset int) []*Record {
	return i.storage.List(limit, offset)
}

// RecordSummaries returns paginated record summaries.
func (i *Inspector) RecordSummaries(limit, offset int) []*RecordSummary {
	return i.storage.ListSummaries(limit, offset)
}

// Get retrieves a single record by ID.
func (i *Inspector) Get(id string) *Record {
	return i.storage.Get(id)
}

// Clear removes all records.
func (i *Inspector) Clear() {
	i.storage.Clear()
}

// Count returns the number of stored records.
func (i *Inspector) Count() int {
	return i.storage.Count()
}

// SetEnabled enables or disables traffic capture.
func (i *Inspector) SetEnabled(enabled bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.config.EnableCapture = enabled
}

// IsEnabled returns whether traffic capture is enabled.
func (i *Inspector) IsEnabled() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.config.EnableCapture
}

// Close closes the inspector and all subscriber channels.
func (i *Inspector) Close() {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return
	}
	i.closed = true

	for _, ch := range i.subscribers {
		close(ch)
	}
	i.subscribers = nil
}

// Wrap wraps an HTTP handler to capture traffic.
func (i *Inspector) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !i.IsEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// Capture request body.
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(io.LimitReader(r.Body, i.config.MaxBodySize+1))
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		// Wrap response writer to capture response.
		rw := &responseCapture{
			ResponseWriter: w,
			maxBodySize:    i.config.MaxBodySize,
		}

		// Serve the request.
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		// Create a fake response for recording.
		resp := &http.Response{
			StatusCode: rw.statusCode,
			Status:     http.StatusText(rw.statusCode),
			Header:     rw.Header(),
		}

		// Capture the record.
		i.Capture(r, reqBody, resp, rw.body.Bytes(), duration, nil)
	})
}

// responseCapture captures response data.
type responseCapture struct {
	http.ResponseWriter
	statusCode  int
	body        bytes.Buffer
	wroteHeader bool
	maxBodySize int64
}

func (rc *responseCapture) WriteHeader(statusCode int) {
	if !rc.wroteHeader {
		rc.statusCode = statusCode
		rc.wroteHeader = true
	}
	rc.ResponseWriter.WriteHeader(statusCode)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	if !rc.wroteHeader {
		rc.statusCode = http.StatusOK
		rc.wroteHeader = true
	}

	// Capture body up to max size.
	if int64(rc.body.Len()) < rc.maxBodySize {
		remaining := rc.maxBodySize - int64(rc.body.Len())
		if int64(len(b)) <= remaining {
			rc.body.Write(b)
		} else {
			rc.body.Write(b[:remaining])
		}
	}

	return rc.ResponseWriter.Write(b)
}

// generateID generates a unique ID for a record.
func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
