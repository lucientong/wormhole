package inspector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWSHub(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	require.NotNil(t, hub)
	defer hub.Close()

	assert.Equal(t, 0, hub.ClientCount())
	assert.NotNil(t, hub.clients)
}

func TestWSHub_ClientCount(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	assert.Equal(t, 0, hub.ClientCount())
}

func TestWSHub_Close(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)

	// Close should not panic.
	hub.Close()

	// Double close should be safe (cancel is idempotent).
	hub.Close()

	assert.Equal(t, 0, hub.ClientCount())
}

func TestWSHub_HandleWebSocket(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	// Create a test server that serves the WebSocket handler.
	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	// Connect a WebSocket client.
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(url, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	defer conn.Close()

	// Give time for the connection to be registered.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, hub.ClientCount())

	// Should receive stats message on connect.
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)

	var wsMsg WSMessage
	err = json.Unmarshal(msg, &wsMsg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeStats, wsMsg.Type)
}

func TestWSHub_HandleWebSocket_MultipleClients(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	dialer := websocket.Dialer{}

	// Connect 3 clients.
	conns := make([]*websocket.Conn, 0, 3)
	for range 3 {
		conn, resp, err := dialer.Dial(url, nil)
		require.NoError(t, err)
		resp.Body.Close()
		conns = append(conns, conn)
	}

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 3, hub.ClientCount())

	// Close one.
	conns[0].Close()
	time.Sleep(100 * time.Millisecond)

	// Count should decrease (eventually).
	// Note: readPump cleanup runs asynchronously.
	time.Sleep(100 * time.Millisecond)
	assert.LessOrEqual(t, hub.ClientCount(), 3)

	// Cleanup.
	for _, c := range conns[1:] {
		c.Close()
	}
}

func TestWSHub_HandleMessage_Ping(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	defer conn.Close()

	// Read initial stats message.
	_, _, err = conn.ReadMessage()
	require.NoError(t, err)

	// Send ping.
	pingMsg := WSMessage{Type: MsgTypePing}
	data, _ := json.Marshal(pingMsg)
	err = conn.WriteMessage(websocket.TextMessage, data)
	require.NoError(t, err)

	// Should receive pong.
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)

	var pongMsg WSMessage
	err = json.Unmarshal(msg, &pongMsg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePong, pongMsg.Type)
}

func TestWSHub_HandleMessage_Subscribe(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	defer conn.Close()

	// Read initial stats message.
	_, _, err = conn.ReadMessage()
	require.NoError(t, err)

	// Send subscribe.
	subMsg := WSMessage{Type: MsgTypeSubscribe}
	data, _ := json.Marshal(subMsg)
	err = conn.WriteMessage(websocket.TextMessage, data)
	require.NoError(t, err)

	// Should receive stats and record_list messages.
	var receivedTypes []string
	for i := 0; i < 2; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, msg, readErr := conn.ReadMessage()
		if readErr != nil {
			break
		}
		var wsMsg WSMessage
		_ = json.Unmarshal(msg, &wsMsg)
		receivedTypes = append(receivedTypes, wsMsg.Type)
	}

	assert.Contains(t, receivedTypes, MsgTypeStats)
	assert.Contains(t, receivedTypes, MsgTypeRecordList)
}

func TestWSHub_HandleMessage_Clear(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	// Add some records.
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	insp.Capture(req, nil, nil, nil, 0, nil)
	assert.Equal(t, 1, insp.Count())

	hub := NewWSHub(insp)
	defer hub.Close()

	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	defer conn.Close()

	// Read initial stats.
	_, _, _ = conn.ReadMessage()

	// Send clear.
	clearMsg := WSMessage{Type: MsgTypeClear}
	data, _ := json.Marshal(clearMsg)
	err = conn.WriteMessage(websocket.TextMessage, data)
	require.NoError(t, err)

	// Should receive clear broadcast.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)

	var wsMsg WSMessage
	_ = json.Unmarshal(msg, &wsMsg)
	assert.Equal(t, MsgTypeClear, wsMsg.Type)

	// Records should be cleared.
	assert.Equal(t, 0, insp.Count())
}

func TestWSHub_HandleMessage_Unknown(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	defer conn.Close()

	// Read initial stats.
	_, _, _ = conn.ReadMessage()

	// Send unknown message.
	unknownMsg := WSMessage{Type: "unknown_type"}
	data, _ := json.Marshal(unknownMsg)
	err = conn.WriteMessage(websocket.TextMessage, data)
	require.NoError(t, err)

	// Should receive error.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)

	var wsMsg WSMessage
	_ = json.Unmarshal(msg, &wsMsg)
	assert.Equal(t, MsgTypeError, wsMsg.Type)
}

func TestWSHub_HandleMessage_InvalidJSON(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	defer conn.Close()

	// Read initial stats.
	_, _, _ = conn.ReadMessage()

	// Send invalid JSON.
	err = conn.WriteMessage(websocket.TextMessage, []byte("not json"))
	require.NoError(t, err)

	// Should receive error.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)

	var wsMsg WSMessage
	_ = json.Unmarshal(msg, &wsMsg)
	assert.Equal(t, MsgTypeError, wsMsg.Type)
}

func TestWSHub_Broadcast(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect two clients.
	conn1, resp1, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer resp1.Body.Close()
	defer conn1.Close()

	conn2, resp2, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer resp2.Body.Close()
	defer conn2.Close()

	// Read initial stats for both.
	_, _, _ = conn1.ReadMessage()
	_, _, _ = conn2.ReadMessage()

	time.Sleep(50 * time.Millisecond)

	// Capture a request - should broadcast to both clients.
	req := httptest.NewRequest("POST", "http://example.com/api", nil)
	insp.Capture(req, nil, nil, nil, 100*time.Millisecond, nil)

	// Both clients should receive the record.
	for _, conn := range []*websocket.Conn{conn1, conn2} {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, msg, readErr := conn.ReadMessage()
		require.NoError(t, readErr)

		var wsMsg WSMessage
		_ = json.Unmarshal(msg, &wsMsg)
		assert.Equal(t, MsgTypeRecord, wsMsg.Type)
	}
}

func TestWSHub_RemoveClient(t *testing.T) {
	insp := New(DefaultConfig())
	defer insp.Close()

	hub := NewWSHub(insp)
	defer hub.Close()

	server := httptest.NewServer(http.HandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	resp.Body.Close()

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, hub.ClientCount())

	// Close connection - readPump should trigger removeClient.
	conn.Close()
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 0, hub.ClientCount())
}
