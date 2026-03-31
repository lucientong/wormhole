package inspector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_HandleRecords(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Add some records.
	for j := 0; j < 5; j++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(req, nil, nil, nil, 0, nil)
	}

	// Get records.
	req := httptest.NewRequest("GET", "/api/inspector/records", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var summaries []*RecordSummary
	err := json.Unmarshal(rr.Body.Bytes(), &summaries)
	require.NoError(t, err)
	assert.Len(t, summaries, 5)
}

func TestHandler_HandleRecords_WithLimit(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Add some records.
	for j := 0; j < 10; j++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(req, nil, nil, nil, 0, nil)
	}

	// Get records with limit.
	req := httptest.NewRequest("GET", "/api/inspector/records?limit=3", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var summaries []*RecordSummary
	err := json.Unmarshal(rr.Body.Bytes(), &summaries)
	require.NoError(t, err)
	assert.Len(t, summaries, 3)
}

func TestHandler_HandleRecordDetail(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Add a record.
	req := httptest.NewRequest("POST", "http://example.com/api/users", nil)
	record := i.Capture(req, []byte(`{"name":"test"}`), nil, nil, 100*time.Millisecond, nil)

	// Get record detail.
	detailReq := httptest.NewRequest("GET", "/api/inspector/records/"+record.ID, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, detailReq)

	assert.Equal(t, http.StatusOK, rr.Code)

	var got Record
	err := json.Unmarshal(rr.Body.Bytes(), &got)
	require.NoError(t, err)
	assert.Equal(t, record.ID, got.ID)
	assert.Equal(t, "POST", got.Method)
}

func TestHandler_HandleRecordDetail_NotFound(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	req := httptest.NewRequest("GET", "/api/inspector/records/non-existent", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandler_HandleStats(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Add some records.
	for j := 0; j < 3; j++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(req, nil, nil, nil, 0, nil)
	}

	req := httptest.NewRequest("GET", "/api/inspector/stats", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var stats struct {
		Count     int  `json:"count"`
		Capacity  int  `json:"capacity"`
		Enabled   bool `json:"enabled"`
		WSClients int  `json:"wsClients"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &stats)
	require.NoError(t, err)
	assert.Equal(t, 3, stats.Count)
	assert.Equal(t, 1000, stats.Capacity)
	assert.True(t, stats.Enabled)
}

func TestHandler_HandleClear(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Add some records.
	for j := 0; j < 5; j++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(req, nil, nil, nil, 0, nil)
	}
	assert.Equal(t, 5, i.Count())

	// Clear.
	req := httptest.NewRequest("POST", "/api/inspector/clear", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, 0, i.Count())
}

func TestHandler_HandleToggle(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	assert.True(t, i.IsEnabled())

	// Toggle off.
	req := httptest.NewRequest("POST", "/api/inspector/toggle", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.False(t, i.IsEnabled())

	// Toggle on.
	req = httptest.NewRequest("POST", "/api/inspector/toggle", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, i.IsEnabled())
}

func TestHandler_CORS(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// OPTIONS request.
	req := httptest.NewRequest("OPTIONS", "/api/inspector/records", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// POST to records endpoint (should be GET).
	req := httptest.NewRequest("POST", "/api/inspector/records", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}
