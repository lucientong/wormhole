# Wormhole Architecture Guide

> This document describes the system architecture, network protocol design, and data flow of Wormhole in detail.

**[中文版](architecture_zh.md)**

## Table of Contents

- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
- [Tunnel Multiplexing Protocol](#tunnel-multiplexing-protocol)
- [Frame Protocol](#frame-protocol)
- [Control Protocol](#control-protocol)
- [Authentication & Authorization](#authentication--authorization)
- [HTTP Proxy Flow](#http-proxy-flow)
- [TCP Tunnel Flow](#tcp-tunnel-flow)
- [Inspector Traffic Capture](#inspector-traffic-capture)
- [P2P Direct Connection (Phase 4)](#p2p-direct-connection-phase-4)
- [Connection Management](#connection-management)
- [Security Model](#security-model)

---

## System Overview

Wormhole is a Client-Server architecture tunneling tool. The core idea is:

1. **Client** runs on the developer's local machine and connects to a **Server** on a public VPS
2. Server assigns a publicly accessible URL (subdomain or port) to the Client
3. External traffic is relayed through Server to Client, which forwards it to the local service
4. Optional **P2P direct connection** mode: Clients communicate directly, bypassing the Server relay

```
                        Internet
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
         ┌─────────┐  ┌─────────┐  ┌─────────┐
         │ Browser  │  │  curl   │  │  gRPC   │
         │  User    │  │  Client │  │  Client │
         └────┬─────┘  └────┬────┘  └────┬────┘
              │             │            │
              └──────┬──────┘────────────┘
                     │ HTTP/TCP/WebSocket
                     ▼
         ┌───────────────────────┐
         │   Wormhole Server     │
         │  (VPS with public IP) │
         │                       │
         │  ┌─────────────────┐  │
         │  │  HTTP Router    │  │   ← Host/Path routing
         │  │  TLS Terminator │  │   ← Let's Encrypt
         │  │  Admin API      │  │   ← /health, /stats
         │  │  TCP Allocator  │  │   ← Port allocation
         │  └─────────────────┘  │
         │           │           │
         │     Mux Tunnel        │   ← Multiplexed tunnel
         └───────────┬───────────┘
                     │
           ┌─────────┴─────────┐
           │  Single TCP Conn  │
           │  carrying Streams │
           └─────────┬─────────┘
                     │
         ┌───────────┴───────────┐
         │   Wormhole Client     │
         │   (Developer Local)   │
         │                       │
         │  ┌─────────────────┐  │
         │  │  Stream Handler │  │   ← Receive & forward
         │  │  Inspector      │  │   ← Traffic capture
         │  │  Inspector UI   │  │   ← Web dashboard
         │  └─────────────────┘  │
         │           │           │
         └───────────┴───────────┘
                     │
              ┌──────┴──────┐
              │ Local Service│
              │ :8080        │
              └──────────────┘
```

## Component Architecture

### Server-Side Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| `Server` | `cmd/server/server.go` | Core controller; manages client sessions, coordinates components |
| `HTTPHandler` | `cmd/server/handler.go` | HTTP reverse proxy; forwards requests through tunnel to Client |
| `Router` | `cmd/server/router.go` | Host/Path routing table; supports subdomain, custom domains, path prefixes |
| `TLSManager` | `cmd/server/tls.go` | TLS termination; Let's Encrypt auto-certs and manual certificates |
| `AdminAPI` | `cmd/server/admin.go` | RESTful admin API |
| `TCPPortAllocator` | `cmd/server/handler.go` | Allocates ports for TCP tunnels |

### Client-Side Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| `Client` | `cmd/client/client.go` | Core controller; manages connection, forwarding, reconnection |
| `Inspector` | `pkg/inspector/inspector.go` | HTTP traffic capture and recording |
| `Handler` | `pkg/inspector/handler.go` | Inspector HTTP API + WebSocket push |
| `Storage` | `pkg/inspector/storage.go` | Request record ring-buffer storage |
| `WebSocket Hub` | `pkg/inspector/websocket.go` | Real-time push of new requests to browser |
| `Web Server` | `pkg/web/handler.go` | Embedded static file server (Inspector UI) |

### Core Libraries

| Package | Location | Responsibility |
|---------|----------|----------------|
| `tunnel` | `pkg/tunnel/` | Multiplexer, frame codec, stream management, connection pool |
| `proto` | `pkg/proto/` | Control protocol message definitions (JSON encoding) |
| `auth` | `pkg/auth/` | Authentication & authorization (HMAC tokens, roles, permissions) |
| `p2p` | `pkg/p2p/` | STUN client, NAT discovery, UDP hole punching, port prediction |
| `version` | `pkg/version/` | Build version information |

---

## Tunnel Multiplexing Protocol

### Design Goals

Run multiple logical Streams over a **single TCP connection**, avoiding new connections for each request.

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Single TCP Connection               │
│                                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ Stream 1 │ │ Stream 2 │ │ Stream 3 │   ...   │
│  │ (Control)│ │ (HTTP #1)│ │ (HTTP #2)│         │
│  └──────────┘ └──────────┘ └──────────┘         │
│       │             │             │               │
│       ▼             ▼             ▼               │
│  ┌───────────────────────────────────────────┐   │
│  │             Mux (Multiplexer)              │   │
│  │                                           │   │
│  │  • Stream create/destroy                  │   │
│  │  • Frame dispatch (by StreamID)           │   │
│  │  • Flow control (WINDOW_UPDATE)           │   │
│  │  • Heartbeat detection (PING/PONG)        │   │
│  └───────────────────────────────────────────┘   │
│       │                                           │
│       ▼                                           │
│  ┌───────────────────────────────────────────┐   │
│  │           Frame Codec (Encoder/Decoder)    │   │
│  │                                           │   │
│  │  [Version][Type][StreamID][Length][Payload]│   │
│  └───────────────────────────────────────────┘   │
│       │                                           │
│       ▼                                           │
│  ┌───────────────────────────────────────────┐   │
│  │               net.Conn (TCP)               │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### Stream Lifecycle

```
  Client                                Server
    │                                      │
    │  ── OpenStream() ──►                 │
    │     (send HANDSHAKE frame)           │
    │                                      │  ◄── AcceptStream()
    │                                      │
    │  ◄── DATA frame (StreamID=N) ──      │
    │  ── DATA frame (StreamID=N) ──►      │
    │  ── WINDOW_UPDATE (StreamID=N) ──►   │
    │                                      │
    │  ── CLOSE frame (StreamID=N) ──►     │
    │     (stream closed)                  │
```

### Roles

- **Server Mux**: `tunnel.Server(conn, config)` — passively accepts new Streams
- **Client Mux**: `tunnel.Client(conn, config)` — actively opens Streams (control, heartbeat), also passively accepts Server-pushed Streams (HTTP request forwarding)

> ⚠️ Note: In Wormhole, the **Server opens Streams to the Client** (when external HTTP requests arrive), and the Client also opens Streams for control messages (registration, heartbeat). This is bidirectional.

---

## Frame Protocol

### Frame Format

All Stream data is encapsulated into frames for transmission over the TCP connection:

```
+----------+----------+------------+----------+------------------+
| Version  |   Type   |  StreamID  |  Length  |     Payload      |
|  1 byte  |  1 byte  |  4 bytes   |  4 bytes |    N bytes       |
+----------+----------+------------+----------+------------------+

Fixed header size: 10 bytes (HeaderSize)
```

### Frame Types

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| `DATA` | 0x01 | Bidirectional | Carries user data (HTTP request/response bodies, etc.) |
| `WINDOW_UPDATE` | 0x02 | Bidirectional | Flow control — notify peer it can send more data |
| `PING` | 0x03 | Client→Server | Heartbeat detection |
| `CLOSE` | 0x04 | Bidirectional | Close a specific Stream |
| `HANDSHAKE` | 0x05 | Opener→Receiver | Create a new Stream |
| `ERROR` | 0x06 | Bidirectional | Error notification (with error code and message) |

### Flow Control

- Each Stream has a receive window (default 256KB)
- Sender must not send more data than the peer's window allows
- After consuming data, receiver notifies sender via `WINDOW_UPDATE` frames
- Prevents fast senders from overwhelming slow receivers

### Encoding

- Uses `sync.Pool` for buffer reuse to reduce GC pressure
- Big-endian byte order (`binary.BigEndian`)
- Maximum payload size limited to 16MB

---

## Control Protocol

Control messages use JSON encoding, transmitted over Mux Streams (each message uses an independent Stream).

### Message Types

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| `AuthRequest` | 1 | C→S | Authentication (Token + version) |
| `AuthResponse` | 2 | S→C | Auth result |
| `RegisterRequest` | 3 | C→S | Register a tunnel |
| `RegisterResponse` | 4 | S→C | Assigned URL/port |
| `PingRequest` | 5 | C→S | Heartbeat |
| `PingResponse` | 6 | S→C | Heartbeat reply |
| `StreamRequest` | 7 | S→C | Notify Client of incoming request |
| `StreamResponse` | 8 | C→S | Client accepts/rejects |
| `StatsRequest` | 9 | C→S | Request statistics |
| `StatsResponse` | 10 | S→C | Statistics response |
| `CloseRequest` | 11 | C→S | Close a tunnel |
| `CloseResponse` | 12 | S→C | Close confirmation |
| `P2POfferRequest` | 13 | C→S | Initiate P2P connection |
| `P2POfferResponse` | 14 | S→C | P2P offer response |
| `P2PCandidates` | 15 | Bidirectional | Additional P2P candidates |
| `P2PResult` | 16 | C→S | P2P connection outcome |

### Message Envelope Format

```json
{
  "type": 3,
  "sequence": 1,
  "register_request": {
    "local_port": 8080,
    "protocol": 1,
    "subdomain": "myapp"
  }
}
```

All messages are wrapped in a `ControlMessage` envelope, distinguished by the `type` field, with `sequence` for request/response pairing.

### Connection Establishment Flow

```
  Client                                  Server
    │                                        │
    │ ──── TCP Connect ──────────────────►   │
    │                                        │
    │ ◄──── Mux Handshake ──────────────►   │  (tunnel layer handshake)
    │                                        │
    │ ── [Stream 1] AuthRequest ──────────► │  (if auth enabled)
    │     { token: "xxx",                   │
    │       version: "1.0",                 │
    │       subdomain: "myapp" }            │
    │                                        │  → Validate Token
    │                                        │  → Check connect permission
    │ ◄── [Stream 1] AuthResponse ──────── │
    │     { success: true,                  │
    │       subdomain: "myapp",             │
    │       session_id: "abc123" }          │
    │                                        │
    │ ── [Stream 2] RegisterRequest ──────► │
    │     { local_port: 8080,               │
    │       protocol: "HTTP",               │
    │       subdomain: "myapp" }            │
    │                                        │  → Assign subdomain
    │                                        │  → Register route
    │ ◄── [Stream 2] RegisterResponse ──── │
    │     { success: true,                  │
    │       tunnel_id: "abc123",            │
    │       public_url: "http://myapp.ex.." }│
    │                                        │
    │ ── [Stream 3] PingRequest ──────────► │  (periodic heartbeat)
    │ ◄── [Stream 3] PingResponse ──────── │
    │                                        │
```

---

## HTTP Proxy Flow

This is the most critical data flow — how external HTTP requests reach the local service through the tunnel.

### End-to-End Flow

```
  Browser              Server                 Client           Local Service
    │                     │                     │                    │
    │ ── HTTP Request ──► │                     │                    │
    │    GET /api/users   │                     │                    │
    │    Host: myapp.ex.. │                     │                    │
    │                     │                     │                    │
    │                     │ 1. Route(Host)      │                    │
    │                     │    → find Client    │                    │
    │                     │                     │                    │
    │                     │ 2. OpenStream()     │                    │
    │                     │ ──────────────────► │                    │
    │                     │                     │                    │
    │                     │ 3. StreamRequest    │                    │
    │                     │ ──────────────────► │                    │
    │                     │ { request_id: "x",  │                    │
    │                     │   protocol: HTTP,   │                    │
    │                     │   http_metadata: {  │                    │
    │                     │     method: "GET",  │                    │
    │                     │     uri: "/api/..", │                    │
    │                     │     host: "myapp.." │                    │
    │                     │   }}                │                    │
    │                     │                     │                    │
    │                     │ 4. r.Write(stream)  │                    │
    │                     │ ──────────────────► │ 5. ReadRequest()  │
    │                     │  (raw HTTP request) │    parse HTTP      │
    │                     │                     │                    │
    │                     │                     │ 6. RoundTrip()    │
    │                     │                     │ ──────────────────►│
    │                     │                     │                    │
    │                     │                     │ ◄── HTTP Response ─│
    │                     │                     │                    │
    │                     │                     │ 7. Capture()       │
    │                     │                     │    (Inspector log) │
    │                     │                     │                    │
    │                     │ ◄── resp.Write() ── │ 8. Write to stream │
    │                     │   (raw HTTP response)│                   │
    │                     │                     │                    │
    │                     │ 9. ReadResponse()   │                    │
    │                     │    copy Headers     │                    │
    │                     │    write Body       │                    │
    │                     │                     │                    │
    │ ◄── HTTP Response ──│                     │                    │
    │    200 OK           │                     │                    │
    │    + X-Wormhole-*   │                     │                    │
```

### Key Details

1. **Server side** (`handler.go: forwardHTTP`):
   - Serializes the complete raw HTTP request (headers + body) to the Stream via `r.Write(stream)`
   - Reads the raw HTTP response from the Stream: `http.ReadResponse(bufio.NewReader(stream), r)`
   - Adds `X-Wormhole-Tunnel` and `X-Wormhole-Duration` response headers

2. **Client side** (`client.go: forwardHTTPWithInspect`):
   - When Inspector is enabled and protocol is HTTP, uses the HTTP-aware path
   - Parses the request with `http.ReadRequest(bufio.NewReader(stream))`
   - Forwards to local service via `http.Transport.RoundTrip()`
   - Writes the response back via `resp.Write(stream)`
   - Calls `inspector.Capture()` to record the request/response pair

3. **Fallback paths**:
   - Inspector disabled → uses `forwardRawTCP` (`io.Copy` blind passthrough)
   - HTTP parse fails → falls back to `forwardRawTCP` (with buffer reassembly)
   - Local service unreachable → returns 502 Bad Gateway

### WebSocket Proxy

WebSocket upgrade requests are handled specially (`handler.go: handleWebSocket`):

1. Server hijacks the underlying connection via `http.Hijacker`
2. The raw upgrade request is written to the Stream
3. Then enters bidirectional `io.Copy` passthrough mode
4. Does not go through Inspector (WebSocket is a long-lived connection)

---

## TCP Tunnel Flow

TCP tunnels are used for non-HTTP protocols (gRPC, database connections, etc.):

```
  TCP Client             Server                 Client           Local Service
    │                     │                     │                    │
    │ ── TCP Connect ───► │                     │                    │
    │    → port 10001     │                     │                    │
    │                     │                     │                    │
    │                     │ 1. OpenStream()     │                    │
    │                     │ ──────────────────► │                    │
    │                     │                     │                    │
    │                     │ 2. StreamRequest    │                    │
    │                     │ ──────────────────► │                    │
    │                     │ { protocol: TCP }   │                    │
    │                     │                     │                    │
    │                     │                     │ 3. Connect to local│
    │                     │                     │ ──────────────────►│
    │                     │                     │                    │
    │ ── data ──────────► │ ── stream ────────► │ ── data ─────────►│
    │ ◄── data ────────── │ ◄── stream ──────── │ ◄── data ──────── │
    │                     │                     │                    │
    │   (bidirectional io.Copy until either side closes)             │
```

TCP tunnels do not go through the Inspector since there is no HTTP semantics to parse.

---

## Inspector Traffic Capture

### Architecture

```
                    ┌──────────────────────────┐
                    │    Inspector (Core)       │
                    │                          │
  forwardHTTP ────► │  Capture(req, resp, ...)  │
  WithInspect       │         │                │
                    │         ▼                │
                    │  ┌────────────────┐      │
                    │  │  Storage       │      │
                    │  │  (Ring Buffer) │      │
                    │  │  max 1000 recs │      │
                    │  └───────┬────────┘      │
                    │          │               │
                    │          ▼               │
                    │  ┌────────────────┐      │
                    │  │  WebSocket Hub │      │  ──► Browser (real-time push)
                    │  │  (Broadcast)   │      │
                    │  └────────────────┘      │
                    │                          │
                    │  HTTP API:               │
                    │  GET /api/requests       │ ◄── History query
                    │  GET /api/requests/:id   │ ◄── Details
                    │  WS  /api/ws             │ ◄── Live stream
                    │  DELETE /api/requests     │ ◄── Clear all
                    └──────────────────────────┘
```

### Record Structure

Each captured record contains:

```go
type Record struct {
    ID              string        // Unique identifier
    Timestamp       time.Time     // Request time
    Method          string        // HTTP method
    URL             string        // Full URL
    RequestHeaders  map[string]string
    RequestBody     []byte        // Truncated to MaxBodySize
    StatusCode      int
    ResponseHeaders map[string]string
    ResponseBody    []byte        // Truncated to MaxBodySize
    Duration        time.Duration // Request latency
    Size            int64         // Response size
    Error           string        // Error message (if any)
}
```

### Capture Flow

1. `forwardHTTPWithInspect` calls `inspector.Capture()` after completing the HTTP round-trip
2. `Capture` constructs a `Record` object (truncates body, extracts headers)
3. Stores into `Storage` (ring buffer, FIFO eviction)
4. Broadcasts to all WebSocket subscribers

---

## P2P Direct Connection (Phase 4)

### Goal

When two Clients need to communicate (or a single Client exposes a service), attempt a direct UDP connection to bypass Server relay, reducing latency.

### NAT Traversal Strategy

```
                    STUN Server
                    (Public)
                       │
          ┌────────────┤────────────┐
          │            │            │
          ▼            ▼            ▼
     ┌─────────┐ ┌──────────┐ ┌─────────┐
     │ Client A│ │  Server  │ │ Client B│
     │(Behind  │ │(Signaling│ │(Behind  │
     │  NAT)   │ │  Relay)  │ │  NAT)   │
     └────┬────┘ └────┬─────┘ └────┬────┘
          │           │            │
          │ 1. STUN Discover       │
          │──────────►│            │
          │◄──────────│            │
          │ (NAT type + public     │
          │  IP:Port)              │
          │           │            │
          │           │ 1. STUN    │
          │           │◄───────────│
          │           │───────────►│
          │           │            │
          │ 2. Exchange candidates │
          │───────────►───────────►│
          │◄───────────◄───────────│
          │           │            │
          │ 3. UDP Hole Punching   │
          │ ◄─────────────────────►│
          │  (simultaneous UDP)    │
          │                        │
          │ 4. P2P Connection      │
          │ ◄═══════════════════► │
          │  (reliable transport)  │
```

### Current Implementation

Phase 4 provides the foundational P2P primitives:

| Component | File | Status |
|-----------|------|--------|
| **NAT Types** | `pkg/p2p/nat.go` | ✅ Complete — Full Cone, Restricted, Port Restricted, Symmetric |
| **STUN Client** | `pkg/p2p/stun.go` | ✅ Complete — RFC 5389 binding, dual-server NAT classification |
| **Hole Puncher** | `pkg/p2p/hole_punch.go` | ✅ Complete — UDP probe/ack with WHPP magic prefix |
| **Port Predictor** | `pkg/p2p/predictor.go` | ✅ Complete — Delta-based prediction for symmetric NAT |
| **P2P Manager** | `pkg/p2p/manager.go` | ✅ Complete — Coordinates STUN + hole punch + relay fallback |
| **Signaling Messages** | `pkg/proto/messages.go` | ✅ Complete — P2POfferRequest/Response, Candidates, Result |
| **Client Integration** | `cmd/client/client.go` | ✅ Partial — NAT discovery at startup, sends P2P offer |
| **Server Signaling** | `cmd/server/server.go` | ✅ Partial — Receives P2P offer, stores NAT info |

### NAT Type Classification

| NAT Type | Traversal Difficulty | Strategy |
|----------|---------------------|----------|
| Full Cone | ★☆☆☆ | Direct connection, almost always succeeds |
| Restricted Cone | ★★☆☆ | Requires outbound probe first |
| Port Restricted Cone | ★★★☆ | Requires port-matched probe |
| Symmetric | ★★★★ | Port prediction + multi-attempt, lower success rate |

### Degradation Strategy

```
Attempt P2P Connection
    │
    ├── Success → Use P2P channel for data transfer
    │
    └── Failure → Automatic fallback to Server relay (existing architecture)
```

---

## Connection Management

### Reconnection Strategy

Client uses exponential backoff reconnection:

```
Initial interval: 1s
Backoff multiplier: 2.0
Maximum interval: 60s
Maximum attempts: Unlimited (default)

Sequence: 1s → 2s → 4s → 8s → 16s → 32s → 60s → 60s → ...
```

### Heartbeat Detection

```
Client ──── PingRequest (every 30s) ──────► Server
       ◄─── PingResponse ──────────────────

Timeout: 10s
On timeout: Mark connection abnormal, trigger reconnection
```

### Connection Pool

`pkg/tunnel/pool.go` provides connection pool management:

- Reuses existing Mux connections
- Health checks (periodic Ping)
- Automatic cleanup of expired connections
- Pre-establishes connections to reduce first-request latency

---

## Authentication & Authorization

### Overview

Wormhole supports optional authentication to protect the server from unauthorized client connections. The auth module is located in `pkg/auth/`.

### Authentication Modes

| Mode | Use Case | Configuration |
|------|----------|---------------|
| **HMAC Signed Token** | Multi-team collaboration, fine-grained access control | `--auth-secret` |
| **Simple Pre-shared Token** | Quick deployment, single team | `--auth-tokens` |
| **Hybrid Mode** | Support both token types simultaneously | `--auth-secret` + `--auth-tokens` |

### HMAC Token Format

```
<base64url(payload)>.<base64url(hmac-sha256(payload))>

payload = {
  "team":  "team-name",
  "role":  "member",
  "iat":   1711900800,
  "exp":   1711987200,
  "nonce": "random-base64"
}
```

### Roles and Permissions

| Role | connect | write | read | admin |
|------|---------|-------|------|-------|
| `admin` | ✅ | ✅ | ✅ | ✅ |
| `member` | ✅ | ✅ | ✅ | ❌ |
| `viewer` | ❌ | ❌ | ✅ | ❌ |

### Authentication Handshake Flow

```
  Client                                Server
    │                                      │
    │  ── Mux.OpenStream() ──►            │
    │                                      │  ◄── Mux.AcceptStream()
    │                                      │      (with timeout, default 10s)
    │                                      │
    │  ── AuthRequest ──────────────────► │
    │     { token: "xxx",                 │
    │       version: "1.0.0",             │
    │       subdomain: "myapp" }          │
    │                                      │  1. ValidateToken(token)
    │                                      │     → Try simple match first
    │                                      │     → Then try HMAC verification
    │                                      │  2. HasPermission(claims, "connect")
    │                                      │
    │  ◄── AuthResponse ────────────────  │
    │     { success: true,                │
    │       subdomain: "myapp",           │
    │       session_id: "abc123" }        │
    │                                      │
    │  (continue with RegisterRequest)    │
```

### Admin API Authentication

- `/health` endpoint is always public
- `/stats`, `/clients`, `/tunnels` are protected by `--admin-token`
- Uses `Authorization: Bearer <token>` header
- Token comparison uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks

---

## Security Model

### Transport Encryption

- Server supports TLS termination (Let's Encrypt auto-certs or manual certificates)
- Client-Server tunnel connection optionally TLS encrypted

### Authentication

- Dual-mode token authentication: HMAC-SHA256 signed tokens (team management) + simple pre-shared tokens (quick deployment)
- HMAC-SHA256 based token generation/verification with nonce for replay prevention
- Role-based access control (RBAC): admin, member, viewer roles
- Mandatory authentication on connection handshake (`--require-auth`), viewer role cannot establish tunnel connections
- Admin API protected by separate token, using constant-time comparison to prevent timing attacks

### Input Validation

- HTML escaping on Host header routing (XSS prevention)
- Subdomain restricted to single-level labels (no dots)
- Path prefix normalization (leading/trailing `/`)

### Rate Limiting

- `MaxClients` limits concurrent online clients
- TCP port allocation range restriction (default 10000-20000)

---

## Data Flow Summary

### Complete HTTP Request Path

```
Browser → DNS → Server:80/443
  → TLS termination
  → Router.Route(Host, Path) → find ClientSession
  → Mux.OpenStream() → new Stream
  → sendStreamRequest(metadata)
  → r.Write(stream) [raw HTTP request]
  ─── Mux frame encoding → TCP connection → reaches Client ───
  → handleStream() → read StreamRequest metadata
  → forwardToLocal()
    → (Inspector enabled?) forwardHTTPWithInspect()
      → http.ReadRequest() parse
      → http.Transport.RoundTrip(localService)
      → inspector.Capture() record
      → resp.Write(stream) write back
    → (Inspector disabled?) forwardRawTCP()
      → io.Copy bidirectional passthrough
  ─── Response via Mux frame encoding → TCP connection → reaches Server ───
  → http.ReadResponse()
  → copyHeaders() + X-Wormhole-* headers
  → w.WriteHeader() + io.Copy(w, resp.Body)
  → Browser receives response
```
