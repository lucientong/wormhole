// Package inspector provides HTTP traffic inspection and recording capabilities.
//
// The inspector package captures HTTP requests and responses passing through
// the tunnel, stores them in a ring buffer, and provides real-time updates
// via WebSocket to connected clients (the Inspector Web UI).
//
// # Features
//
//   - Request/response capture with headers and body
//   - Ring buffer storage with configurable capacity
//   - Real-time WebSocket push to UI clients
//   - HTTP handler wrapping middleware
//
// # Usage
//
//	insp := inspector.New(inspector.Config{
//	    MaxRecords:    1000,
//	    MaxBodySize:   1024 * 1024, // 1MB
//	    EnableCapture: true,
//	})
//
//	// Wrap your handler to capture traffic
//	handler := insp.Wrap(yourHandler)
//
//	// Subscribe to real-time updates
//	ch := insp.Subscribe()
//	for record := range ch {
//	    // Handle new record
//	}
package inspector
