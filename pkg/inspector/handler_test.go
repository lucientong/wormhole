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

// TestHandler_RegisterRoutes verifies that RegisterRoutes correctly binds
// all API endpoints to a ServeMux and that they respond.
func TestHandler_RegisterRoutes(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test each registered route.
	tests := []struct {
		method string
		path   string
		expect int
	}{
		{"GET", "/api/inspector/records", http.StatusOK},
		{"GET", "/api/inspector/records/nonexistent", http.StatusNotFound},
		{"GET", "/api/inspector/stats", http.StatusOK},
		{"POST", "/api/inspector/clear", http.StatusOK},
		{"POST", "/api/inspector/toggle", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, server.URL+tt.path, nil)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tt.expect, resp.StatusCode)
		})
	}
}

// TestHandler_HandleRecordDetail_MethodNotAllowed verifies POST to /records/{id} returns 405.
func TestHandler_HandleRecordDetail_MethodNotAllowed(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	req := httptest.NewRequest("POST", "/api/inspector/records/some-id", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestHandler_HandleRecordDetail_EmptyID verifies that empty ID returns 400.
func TestHandler_HandleRecordDetail_EmptyID(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Path is exactly "/api/inspector/records/" — ID is empty after trim.
	// However, ServeHTTP switch routes this to handleRecords, not handleRecordDetail.
	// To test handleRecordDetail directly with empty ID, we need to call it directly.
	req := httptest.NewRequest("GET", "/api/inspector/records/", nil)
	rr := httptest.NewRecorder()
	h.handleRecordDetail(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Record ID required")
}

// TestHandler_HandleStats_MethodNotAllowed verifies POST to /stats returns 405.
func TestHandler_HandleStats_MethodNotAllowed(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	req := httptest.NewRequest("POST", "/api/inspector/stats", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestHandler_HandleClear_MethodNotAllowed verifies GET to /clear returns 405.
func TestHandler_HandleClear_MethodNotAllowed(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	req := httptest.NewRequest("GET", "/api/inspector/clear", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestHandler_HandleToggle_MethodNotAllowed verifies GET to /toggle returns 405.
func TestHandler_HandleToggle_MethodNotAllowed(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	req := httptest.NewRequest("GET", "/api/inspector/toggle", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestHandler_HandleRecords_WithDetail verifies handleRecords with detail=true
// returns full Record objects instead of RecordSummary.
func TestHandler_HandleRecords_WithDetail(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Add a record.
	captureReq := httptest.NewRequest("POST", "http://example.com/api/data", nil)
	captureReq.Header.Set("Content-Type", "application/json")
	i.Capture(captureReq, []byte(`{"key":"value"}`), nil, nil, 50*time.Millisecond, nil)

	// GET with detail=true.
	req := httptest.NewRequest("GET", "/api/inspector/records?detail=true", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Should return full Record objects (with Method, Headers, Body fields).
	var records []*Record
	err := json.Unmarshal(rr.Body.Bytes(), &records)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "POST", records[0].Method)
	assert.Contains(t, records[0].Headers, "Content-Type")
}

// TestHandler_HandleRecords_WithOffset verifies offset pagination in handleRecords.
func TestHandler_HandleRecords_WithOffset(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Add 5 records.
	for j := 0; j < 5; j++ {
		captureReq := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(captureReq, nil, nil, nil, 0, nil)
	}

	// GET with offset=3 and limit=10.
	req := httptest.NewRequest("GET", "/api/inspector/records?offset=3&limit=10", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var summaries []*RecordSummary
	err := json.Unmarshal(rr.Body.Bytes(), &summaries)
	require.NoError(t, err)
	assert.Len(t, summaries, 2, "should return 2 records (5 total - offset 3)")
}

// TestHandler_ServeHTTP_UnknownPath verifies that unknown paths return 404.
func TestHandler_ServeHTTP_UnknownPath(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	req := httptest.NewRequest("GET", "/api/inspector/unknown", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestHandler_HandleClear_VerifyBroadcast verifies that handleClear sends
// a clear broadcast (we verify via the HTTP response).
func TestHandler_HandleClear_VerifyEmpty(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	// Add records.
	for j := 0; j < 3; j++ {
		captureReq := httptest.NewRequest("GET", "http://example.com/test", nil)
		i.Capture(captureReq, nil, nil, nil, 0, nil)
	}
	assert.Equal(t, 3, i.Count())

	// Clear via handler.
	req := httptest.NewRequest("POST", "/api/inspector/clear", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, 0, i.Count())

	// Verify response body.
	var result map[string]bool
	err := json.Unmarshal(rr.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.True(t, result["success"])
}

// TestHandler_HandleToggle_ResponseBody verifies toggle returns current state.
func TestHandler_HandleToggle_ResponseBody(t *testing.T) {
	i := New(DefaultConfig())
	h := NewHandler(i)
	defer h.Close()

	assert.True(t, i.IsEnabled())

	// Toggle off.
	req := httptest.NewRequest("POST", "/api/inspector/toggle", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var result map[string]bool
	err := json.Unmarshal(rr.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.False(t, result["enabled"])
}

// TestParseIntParam verifies parseIntParam with various inputs.
func TestParseIntParam(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		param      string
		defaultVal int
		expected   int
	}{
		{"default value", "", "limit", 100, 100},
		{"valid number", "limit=50", "limit", 100, 50},
		{"invalid number", "limit=abc", "limit", 100, 100},
		{"zero", "offset=0", "offset", 10, 0},
		{"negative", "limit=-5", "limit", 100, -5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test?"+tt.query, nil)
			result := parseIntParam(req, tt.param, tt.defaultVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}
