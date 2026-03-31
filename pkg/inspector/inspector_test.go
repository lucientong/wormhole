package inspector

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspector_New(t *testing.T) {
	i := New(DefaultConfig())
	require.NotNil(t, i)
	assert.Equal(t, 0, i.Count())
	assert.True(t, i.IsEnabled())
}

func TestInspector_Capture(t *testing.T) {
	i := New(DefaultConfig())

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Test", "value")

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	record := i.Capture(req, []byte(`{"request":"body"}`), resp, []byte(`{"response":"body"}`), 100*time.Millisecond, nil)

	require.NotNil(t, record)
	assert.Equal(t, "GET", record.Method)
	assert.Equal(t, "http://example.com/test", record.URL)
	assert.Equal(t, 200, record.Status)
	assert.Equal(t, 100*time.Millisecond, record.Duration)
	assert.Equal(t, `{"request":"body"}`, record.Body)
	assert.Equal(t, `{"response":"body"}`, record.Response.Body)

	assert.Equal(t, 1, i.Count())
}

func TestInspector_CaptureDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableCapture = false
	i := New(cfg)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	record := i.Capture(req, nil, nil, nil, 0, nil)

	assert.Nil(t, record)
	assert.Equal(t, 0, i.Count())
}

func TestInspector_Subscribe(t *testing.T) {
	i := New(DefaultConfig())

	// Subscribe.
	ch := i.Subscribe()
	require.NotNil(t, ch)

	// Capture should notify subscribers.
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	go i.Capture(req, nil, nil, nil, 0, nil)

	select {
	case record := <-ch:
		assert.Equal(t, "GET", record.Method)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for notification")
	}

	// Unsubscribe.
	i.Unsubscribe(ch)
}

func TestInspector_Records(t *testing.T) {
	i := New(DefaultConfig())

	// Add some records.
	for j := 0; j < 5; j++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(req, nil, nil, nil, 0, nil)
	}

	records := i.Records(10, 0)
	assert.Len(t, records, 5)

	records = i.Records(2, 0)
	assert.Len(t, records, 2)
}

func TestInspector_Get(t *testing.T) {
	i := New(DefaultConfig())

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	record := i.Capture(req, nil, nil, nil, 0, nil)

	got := i.Get(record.ID)
	require.NotNil(t, got)
	assert.Equal(t, record.ID, got.ID)

	assert.Nil(t, i.Get("non-existent"))
}

func TestInspector_Clear(t *testing.T) {
	i := New(DefaultConfig())

	// Add some records.
	for j := 0; j < 5; j++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(req, nil, nil, nil, 0, nil)
	}
	assert.Equal(t, 5, i.Count())

	i.Clear()
	assert.Equal(t, 0, i.Count())
}

func TestInspector_SetEnabled(t *testing.T) {
	i := New(DefaultConfig())
	assert.True(t, i.IsEnabled())

	i.SetEnabled(false)
	assert.False(t, i.IsEnabled())

	i.SetEnabled(true)
	assert.True(t, i.IsEnabled())
}

func TestInspector_Close(t *testing.T) {
	i := New(DefaultConfig())

	ch := i.Subscribe()
	i.Close()

	// Channel should be closed.
	_, ok := <-ch
	assert.False(t, ok)
}

func TestInspector_Wrap(t *testing.T) {
	i := New(DefaultConfig())

	// Create a test handler.
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Wrap it.
	wrapped := i.Wrap(handler)

	// Make a request.
	req := httptest.NewRequest("POST", "http://example.com/api", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	// Verify response.
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, `{"status":"ok"}`, rr.Body.String())

	// Verify capture.
	assert.Equal(t, 1, i.Count())
	records := i.Records(1, 0)
	require.Len(t, records, 1)
	assert.Equal(t, "POST", records[0].Method)
	assert.Equal(t, 200, records[0].Status)
}

func TestRecord_Summary(t *testing.T) {
	r := &Record{
		ID:       "test-id",
		Method:   "GET",
		URL:      "http://example.com/path",
		Host:     "example.com",
		Path:     "/path",
		Status:   200,
		Duration: 100 * time.Millisecond,
		BodySize: 1024,
		Response: &ResponseData{
			Status:   200,
			BodySize: 2048,
		},
	}

	summary := r.Summary()
	assert.Equal(t, "test-id", summary.ID)
	assert.Equal(t, "GET", summary.Method)
	assert.Equal(t, 200, summary.Status)
	assert.Equal(t, int64(1024), summary.BodySize)
	assert.Equal(t, int64(2048), summary.RespSize)
}

func TestInspector_BodySizeLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBodySize = 10
	i := New(cfg)

	// Create a request with a large body.
	largeBody := []byte("0123456789ABCDEF")
	req := httptest.NewRequest("POST", "http://example.com/test", nil)

	record := i.Capture(req, largeBody, nil, nil, 0, nil)

	// Body should be truncated.
	assert.Equal(t, int64(16), record.BodySize) // Original size recorded.
	assert.Equal(t, 10, len(record.Body))       // Stored body truncated.
	assert.Equal(t, "0123456789", record.Body)  // First 10 bytes.
}
