// Package inspector provides HTTP traffic inspection and recording capabilities.
package inspector

import (
	"net/http"
	"strings"
	"time"
)

// sensitiveHeaders lists header names (case-insensitive) whose values are
// replaced with a fixed redaction marker before being stored in a Record
// (S14). The inspector's stated purpose is debugging request/response
// shape and routing, not exfiltrating credentials — so bearer tokens,
// session cookies, and API keys captured incidentally while inspecting
// traffic must never be persisted or shown in the local dashboard/API in
// the clear.
var sensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"x-csrf-token":        {},
}

// redactedHeaderValue replaces the value of any sensitive header.
const redactedHeaderValue = "[redacted]"

// captureHeaders copies HTTP headers into a flat map, redacting sensitive
// ones (S14) instead of storing them verbatim.
func captureHeaders(h http.Header) map[string]string {
	headers := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) == 0 {
			continue
		}
		if _, sensitive := sensitiveHeaders[strings.ToLower(k)]; sensitive {
			headers[k] = redactedHeaderValue
			continue
		}
		headers[k] = v[0]
	}
	return headers
}

// Record represents a captured HTTP request/response pair.
type Record struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
	BodySize  int64             `json:"bodySize"`
	Status    int               `json:"status"`
	Duration  time.Duration     `json:"duration"`
	Response  *ResponseData     `json:"response,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// ResponseData contains the response information.
type ResponseData struct {
	Status     int               `json:"status"`
	StatusText string            `json:"statusText"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	BodySize   int64             `json:"bodySize"`
}

// RecordSummary is a lightweight version of Record for list views.
type RecordSummary struct {
	ID        string        `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	Method    string        `json:"method"`
	URL       string        `json:"url"`
	Host      string        `json:"host"`
	Path      string        `json:"path"`
	Status    int           `json:"status"`
	Duration  time.Duration `json:"duration"`
	BodySize  int64         `json:"bodySize"`
	RespSize  int64         `json:"respSize"`
	Error     string        `json:"error,omitempty"`
}

// Summary returns a lightweight summary of the record.
func (r *Record) Summary() *RecordSummary {
	summary := &RecordSummary{
		ID:        r.ID,
		Timestamp: r.Timestamp,
		Method:    r.Method,
		URL:       r.URL,
		Host:      r.Host,
		Path:      r.Path,
		Status:    r.Status,
		Duration:  r.Duration,
		BodySize:  r.BodySize,
		Error:     r.Error,
	}
	if r.Response != nil {
		summary.RespSize = r.Response.BodySize
		summary.Status = r.Response.Status
	}
	return summary
}

// NewRecord creates a new record from an HTTP request.
func NewRecord(id string, req *http.Request) *Record {
	headers := captureHeaders(req.Header)

	return &Record{
		ID:        id,
		Timestamp: time.Now(),
		Method:    req.Method,
		URL:       req.URL.String(),
		Host:      req.Host,
		Path:      req.URL.Path,
		Headers:   headers,
	}
}

// SetRequestBody sets the request body on the record.
func (r *Record) SetRequestBody(body []byte, maxSize int64) {
	if int64(len(body)) > maxSize {
		r.Body = string(body[:maxSize])
	} else {
		r.Body = string(body)
	}
	r.BodySize = int64(len(body))
}

// SetResponse sets the response data on the record.
func (r *Record) SetResponse(resp *http.Response, body []byte, maxSize int64) {
	headers := captureHeaders(resp.Header)

	var respBody string
	if int64(len(body)) > maxSize {
		respBody = string(body[:maxSize])
	} else {
		respBody = string(body)
	}

	r.Response = &ResponseData{
		Status:     resp.StatusCode,
		StatusText: resp.Status,
		Headers:    headers,
		Body:       respBody,
		BodySize:   int64(len(body)),
	}
	r.Status = resp.StatusCode
}

// SetError sets an error on the record.
func (r *Record) SetError(err error) {
	if err != nil {
		r.Error = err.Error()
	}
}

// Complete marks the record as complete with the given duration.
func (r *Record) Complete(duration time.Duration) {
	r.Duration = duration
}
