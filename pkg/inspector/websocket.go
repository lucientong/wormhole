package inspector

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// WebSocket message types.
const (
	MsgTypeRecord      = "record"
	MsgTypeRecordList  = "record_list"
	MsgTypeClear       = "clear"
	MsgTypeStats       = "stats"
	MsgTypePing        = "ping"
	MsgTypePong        = "pong"
	MsgTypeError       = "error"
	MsgTypeSubscribe   = "subscribe"
	MsgTypeUnsubscribe = "unsubscribe"
)

// WSMessage represents a WebSocket message.
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
}

// WSHub manages WebSocket connections.
type WSHub struct {
	inspector *Inspector
	upgrader  websocket.Upgrader
	clients   map[*WSClient]struct{}
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// WSClient represents a connected WebSocket client.
type WSClient struct {
	hub  *WSHub
	conn *websocket.Conn
	send chan []byte
	done chan struct{}
}

// NewWSHub creates a new WebSocket hub.
func NewWSHub(inspector *Inspector) *WSHub {
	ctx, cancel := context.WithCancel(context.Background())
	hub := &WSHub{
		inspector: inspector,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(_ *http.Request) bool {
				return true // Allow all origins for local development.
			},
		},
		clients: make(map[*WSClient]struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}

	go hub.run()
	return hub
}

// run listens for new records and broadcasts to clients.
func (h *WSHub) run() {
	ch := h.inspector.Subscribe()
	defer h.inspector.Unsubscribe(ch)

	for {
		select {
		case record, ok := <-ch:
			if !ok {
				return
			}
			h.broadcast(WSMessage{
				Type:    MsgTypeRecord,
				Payload: record.Summary(),
			})
		case <-h.ctx.Done():
			return
		}
	}
}

// broadcast sends a message to all connected clients.
func (h *WSHub) broadcast(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal WebSocket message")
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		select {
		case client.send <- data:
		default:
			// Client buffer full, skip.
		}
	}
}

// HandleWebSocket handles WebSocket upgrade requests.
func (h *WSHub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}

	client := &WSClient{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
		done: make(chan struct{}),
	}

	h.mu.Lock()
	h.clients[client] = struct{}{}
	h.mu.Unlock()

	log.Debug().Str("addr", conn.RemoteAddr().String()).Msg("WebSocket client connected")

	// Send current stats.
	client.sendStats()

	go client.writePump()
	go client.readPump()
}

// removeClient removes a client from the hub.
func (h *WSHub) removeClient(client *WSClient) {
	h.mu.Lock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		close(client.send)
	}
	h.mu.Unlock()
}

// ClientCount returns the number of connected clients.
func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Close closes the hub and all connections.
func (h *WSHub) Close() {
	h.cancel()

	h.mu.Lock()
	clients := h.clients
	h.clients = make(map[*WSClient]struct{})
	h.mu.Unlock()

	// Close all clients after clearing the map, so removeClient won't double-close.
	for client := range clients {
		close(client.send)
		_ = client.conn.Close()
	}
}

// readPump reads messages from the WebSocket connection.
func (c *WSClient) readPump() {
	defer func() {
		c.hub.removeClient(c)
		c.conn.Close()
		close(c.done)
	}()

	c.conn.SetReadLimit(4096)
	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Debug().Err(err).Msg("WebSocket read error")
			}
			return
		}

		c.handleMessage(message)
	}
}

// writePump writes messages to the WebSocket connection.
func (c *WSClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-c.done:
			return
		}
	}
}

// handleMessage handles incoming WebSocket messages.
func (c *WSClient) handleMessage(data []byte) {
	var msg WSMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		c.sendError("invalid message format")
		return
	}

	switch msg.Type {
	case MsgTypePing:
		c.sendMessage(WSMessage{Type: MsgTypePong})

	case MsgTypeSubscribe:
		c.sendStats()
		c.sendRecordList()

	case MsgTypeClear:
		c.hub.inspector.Clear()
		c.hub.broadcast(WSMessage{Type: MsgTypeClear})

	default:
		c.sendError("unknown message type: " + msg.Type)
	}
}

// sendMessage sends a message to this client.
func (c *WSClient) sendMessage(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	select {
	case c.send <- data:
	default:
	}
}

// sendError sends an error message to this client.
func (c *WSClient) sendError(errMsg string) {
	c.sendMessage(WSMessage{
		Type:    MsgTypeError,
		Payload: errMsg,
	})
}

// sendStats sends current stats to this client.
func (c *WSClient) sendStats() {
	stats := struct {
		Count    int  `json:"count"`
		Capacity int  `json:"capacity"`
		Enabled  bool `json:"enabled"`
	}{
		Count:    c.hub.inspector.Count(),
		Capacity: c.hub.inspector.storage.Capacity(),
		Enabled:  c.hub.inspector.IsEnabled(),
	}
	c.sendMessage(WSMessage{
		Type:    MsgTypeStats,
		Payload: stats,
	})
}

// sendRecordList sends the current record list to this client.
func (c *WSClient) sendRecordList() {
	summaries := c.hub.inspector.RecordSummaries(100, 0)
	c.sendMessage(WSMessage{
		Type:    MsgTypeRecordList,
		Payload: summaries,
	})
}
