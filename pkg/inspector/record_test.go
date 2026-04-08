package inspector

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRecord(t *testing.T) {
	req := httptest.NewRequest("POST", "http://example.com/api/users?page=1", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token123")

	record := NewRecord("test-123", req)

	assert.Equal(t, "test-123", record.ID)
	assert.Equal(t, "POST", record.Method)
	assert.Contains(t, record.URL, "/api/users")
	assert.Equal(t, "example.com", record.Host)
	assert.Equal(t, "/api/users", record.Path)
	assert.NotZero(t, record.Timestamp)
	assert.Equal(t, "application/json", record.Headers["Content-Type"])
	assert.Equal(t, "Bearer token123", record.Headers["Authorization"])
}

func TestNewRecord_NoHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	record := NewRecord("test-456", req)

	assert.Equal(t, "GET", record.Method)
	assert.NotNil(t, record.Headers)
}

func TestRecord_SetRequestBody(t *testing.T) {
	record := &Record{ID: "test"}

	body := []byte(`{"name":"test","value":123}`)
	record.SetRequestBody(body, 1024)

	assert.Equal(t, string(body), record.Body)
	assert.Equal(t, int64(len(body)), record.BodySize)
}

func TestRecord_SetRequestBody_Truncated(t *testing.T) {
	record := &Record{ID: "test"}

	body := []byte("0123456789ABCDEF")
	record.SetRequestBody(body, 10)

	assert.Equal(t, "0123456789", record.Body) // Truncated.
	assert.Equal(t, int64(16), record.BodySize) // Original size.
}

func TestRecord_SetRequestBody_Empty(t *testing.T) {
	record := &Record{ID: "test"}
	record.SetRequestBody(nil, 1024)

	assert.Empty(t, record.Body)
	assert.Equal(t, int64(0), record.BodySize)
}

func TestRecord_SetResponse(t *testing.T) {
	record := &Record{ID: "test"}

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	body := []byte(`{"status":"ok"}`)

	record.SetResponse(resp, body, 1024)

	require.NotNil(t, record.Response)
	assert.Equal(t, 200, record.Response.Status)
	assert.Equal(t, "200 OK", record.Response.StatusText)
	assert.Equal(t, "application/json", record.Response.Headers["Content-Type"])
	assert.Equal(t, string(body), record.Response.Body)
	assert.Equal(t, int64(len(body)), record.Response.BodySize)
	assert.Equal(t, 200, record.Status)
}

func TestRecord_SetResponse_Truncated(t *testing.T) {
	record := &Record{ID: "test"}

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
	}
	body := []byte("0123456789ABCDEF")

	record.SetResponse(resp, body, 10)

	require.NotNil(t, record.Response)
	assert.Equal(t, "0123456789", record.Response.Body)
	assert.Equal(t, int64(16), record.Response.BodySize)
}

func TestRecord_SetError(t *testing.T) {
	record := &Record{ID: "test"}

	record.SetError(errors.New("connection refused"))
	assert.Equal(t, "connection refused", record.Error)
}

func TestRecord_SetError_Nil(t *testing.T) {
	record := &Record{ID: "test"}

	record.SetError(nil)
	assert.Empty(t, record.Error)
}

func TestRecord_Complete(t *testing.T) {
	record := &Record{ID: "test"}

	record.Complete(250 * time.Millisecond)
	assert.Equal(t, 250*time.Millisecond, record.Duration)
}

func TestRecord_Summary_NoResponse(t *testing.T) {
	record := &Record{
		ID:       "test-id",
		Method:   "DELETE",
		URL:      "http://example.com/resource/1",
		Host:     "example.com",
		Path:     "/resource/1",
		Status:   204,
		Duration: 50 * time.Millisecond,
		BodySize: 0,
		Error:    "some error",
	}

	summary := record.Summary()
	assert.Equal(t, "test-id", summary.ID)
	assert.Equal(t, "DELETE", summary.Method)
	assert.Equal(t, 204, summary.Status) // From record directly.
	assert.Equal(t, int64(0), summary.BodySize)
	assert.Equal(t, int64(0), summary.RespSize)
	assert.Equal(t, "some error", summary.Error)
}

func TestGenerateID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID()
		assert.Len(t, id, 16) // 8 bytes hex-encoded.
		assert.False(t, ids[id], "duplicate ID: %s", id)
		ids[id] = true
	}
}

func TestDefaultConfig_Inspector(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 1000, cfg.MaxRecords)
	assert.Equal(t, int64(1024*1024), cfg.MaxBodySize)
	assert.True(t, cfg.EnableCapture)
}

func TestInspector_New_InvalidConfig(t *testing.T) {
	// Negative MaxRecords should be corrected.
	cfg := Config{MaxRecords: -1, MaxBodySize: -1, EnableCapture: true}
	i := New(cfg)
	require.NotNil(t, i)

	// Should still work.
	assert.True(t, i.IsEnabled())
}

func TestInspector_SubscribeAfterClose(t *testing.T) {
	i := New(DefaultConfig())
	i.Close()

	// Subscribing after close should return a closed channel.
	ch := i.Subscribe()
	_, ok := <-ch
	assert.False(t, ok)
}

func TestInspector_DoubleClose(t *testing.T) {
	i := New(DefaultConfig())

	i.Close()
	// Second close should be a no-op.
	i.Close()
}

func TestInspector_UnsubscribeNonExistent(t *testing.T) {
	i := New(DefaultConfig())
	defer i.Close()

	// Unsubscribing a channel that was never subscribed should not panic.
	fakeCh := make(chan *Record)
	i.Unsubscribe(fakeCh)
}

func TestInspector_CaptureWithError(t *testing.T) {
	i := New(DefaultConfig())

	req := httptest.NewRequest("GET", "http://example.com/fail", nil)
	captureErr := errors.New("connection timeout")

	record := i.Capture(req, nil, nil, nil, 500*time.Millisecond, captureErr)

	require.NotNil(t, record)
	assert.Equal(t, "connection timeout", record.Error)
	assert.Equal(t, 500*time.Millisecond, record.Duration)
}

func TestInspector_RecordSummaries(t *testing.T) {
	i := New(DefaultConfig())

	for j := 0; j < 5; j++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(req, nil, nil, nil, 0, nil)
	}

	summaries := i.RecordSummaries(3, 0)
	assert.Len(t, summaries, 3)

	summaries = i.RecordSummaries(10, 0)
	assert.Len(t, summaries, 5)
}

func TestResponseCapture_WriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	rc := &responseCapture{
		ResponseWriter: rr,
		maxBodySize:    1024,
	}

	rc.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, rc.statusCode)
	assert.True(t, rc.wroteHeader)

	// Double WriteHeader should be no-op.
	rc.WriteHeader(http.StatusBadRequest)
	assert.Equal(t, http.StatusCreated, rc.statusCode) // Unchanged.
}

func TestResponseCapture_Write(t *testing.T) {
	rr := httptest.NewRecorder()
	rc := &responseCapture{
		ResponseWriter: rr,
		maxBodySize:    1024,
	}

	n, err := rc.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", rc.body.String())
	assert.True(t, rc.wroteHeader)
	assert.Equal(t, http.StatusOK, rc.statusCode) // Default on first Write.
}

func TestResponseCapture_Write_MaxBodySize(t *testing.T) {
	rr := httptest.NewRecorder()
	rc := &responseCapture{
		ResponseWriter: rr,
		maxBodySize:    5,
	}

	// Write more than maxBodySize.
	_, _ = rc.Write([]byte("0123456789"))

	// Body should be capped at 5 bytes.
	assert.Equal(t, "01234", rc.body.String())
}

func TestResponseCapture_Write_MultipleWrites(t *testing.T) {
	rr := httptest.NewRecorder()
	rc := &responseCapture{
		ResponseWriter: rr,
		maxBodySize:    10,
	}

	_, _ = rc.Write([]byte("hello"))
	_, _ = rc.Write([]byte("world!"))

	// Body should capture up to maxBodySize.
	assert.Equal(t, "helloworld", rc.body.String()) // 10 bytes cap.
}
