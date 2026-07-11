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
- [P2P Direct Connection (Phase 4 & 4.5)](#p2p-direct-connection-phase-4--45)
- [Connection Management](#connection-management)
- [Security Model](#security-model)
- [Multi-Tunnel Configuration & Hot-Reload](#multi-tunnel-configuration--hot-reload)
- [HA / Multi-Node Control Plane](#ha--multi-node-control-plane)
- [Robustness & Protocol Hardening (P3-6 Batch A)](#robustness--protocol-hardening-p3-6-batch-a)
- [Data Flow Summary](#data-flow-summary)

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
| `Server` | `pkg/server/server.go` | Core controller; manages client sessions, coordinates all components |
| `HTTPHandler` | `pkg/server/handler.go` | HTTP reverse proxy; forwards requests through tunnel; cross-node proxy fallback |
| `Router` | `pkg/server/router.go` | Host/Path routing table; subdomain, custom domains, path prefixes |
| `TLSManager` | `pkg/server/tls.go` | TLS termination; Let's Encrypt auto-certs and manual certificates |
| `AdminAPI` | `pkg/server/admin.go` | RESTful admin API including `/audit` and `/audit/export` |
| `TCPPortAllocator` | `pkg/server/handler.go` | Allocates ports for TCP tunnels |
| `StateStore` | `pkg/server/state*.go` | Cluster shared state (subdomain/hostname/path routes + nodes); Memory or Redis backend |
| Cluster heartbeat | `pkg/server/cluster.go` | Periodic heartbeat + route TTL refresh, dead-node eviction, cross-node HTTP proxying, shared-secret verification |

### Client-Side Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| `Client` | `pkg/client/client.go` | Core controller; connection, multi-tunnel, hot-reload, reconnection |
| `FileConfig` | `pkg/client/config_file.go` | YAML config file loader + validator |
| Control API | `pkg/client/control.go` | Local HTTP server (`/tunnels`) for `wormhole tunnels list` |
| `Inspector` | `pkg/inspector/inspector.go` | HTTP traffic capture and recording |
| `Handler` | `pkg/inspector/handler.go` | Inspector HTTP API + WebSocket push |
| `Storage` | `pkg/inspector/storage.go` | Request record ring-buffer storage |
| `WebSocket Hub` | `pkg/inspector/websocket.go` | Real-time push of new requests to browser |
| `Web Server` | `pkg/web/handler.go` | Embedded static file server (Inspector UI) |

### Core Libraries

| Package | Location | Responsibility |
|---------|----------|----------------|
| `tunnel` | `pkg/tunnel/` | Multiplexer, frame codec, stream management |
| `proto` | `pkg/proto/` | Control protocol (Protobuf encoding + JSON fallback) |
| `auth` | `pkg/auth/` | HMAC tokens, OIDC/JWT, OAuth Device Flow, credentials, RBAC, rate limiting, audit logging + store |
| `p2p` | `pkg/p2p/` | STUN (IPv4/IPv6), NAT discovery, UDP hole punching, port prediction, reliable UDP (UDPMux + UDPStream + ARQ), E2E encryption (X25519 + AES-256-GCM) |
| `version` | `pkg/version/` | Build version information |

---

## Tunnel Multiplexing Protocol

### Design Goals

Run multiple logical Streams over a **single TCP connection**, avoiding new connections for each request.

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Single TCP Connection              │
│                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ Stream 1 │ │ Stream 2 │ │ Stream 3 │   ...   │
│  │ (Control)│ │ (HTTP #1)│ │ (HTTP #2)│         │
│  └──────────┘ └──────────┘ └──────────┘         │
│       │             │             │             │
│       ▼             ▼             ▼             │
│  ┌───────────────────────────────────────────┐  │
│  │             Mux (Multiplexer)             │  │
│  │                                           │  │
│  │  • Stream create/destroy                  │  │
│  │  • Frame dispatch (by StreamID)           │  │
│  │  • Flow control (WINDOW_UPDATE)           │  │
│  │  • Heartbeat detection (PING/PONG)        │  │
│  └───────────────────────────────────────────┘  │
│       │                                         │
│       ▼                                         │
│  ┌────────────────────────────────────────────┐ │
│  │           Frame Codec (Encoder/Decoder)    │ │
│  │                                            │ │
│  │  [Version][Type][StreamID][Length][Payload]│ │
│  └────────────────────────────────────────────┘ │
│       │                                         │
│       ▼                                         │
│  ┌───────────────────────────────────────────┐  │
│  │               net.Conn (TCP)              │  │
│  └───────────────────────────────────────────┘  │
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

Control messages are Protobuf-encoded by default (`pkg/proto/messages.go`), with a JSON fallback path retained in `DecodeControlMessage` for compatibility. Each message is transmitted over a Mux Stream.

### Wire Framing

Two framing conventions coexist, depending on whether a Stream carries exactly one message or a sequence of messages:

- **Single message per Stream** (Auth/Register/Ping/Stats/Close request-response pairs): the encoded message is written directly with no length prefix — the stream boundary itself delimits the message.
- **Multiple messages per Stream** (P2P signaling — see below): each message is wrapped with a 4-byte big-endian length prefix via `proto.WriteControlMessage` / read back with `proto.ReadControlMessage`, so a reader can loop-read several framed messages off a single Stream without ambiguity.

P2P signaling needs the length-prefixed form because a single notification Stream carries a variable-length list of `P2PCandidates` (Symmetric-NAT port predictions) **followed by** a terminal `P2POfferResponse` — both the server (`handleP2POffer`, `notifyPeerOfP2P`) and the client (`handleStream`, `sendP2POffer`) loop-read framed messages, collecting `P2PCandidates` until the terminal response arrives.

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
    │ ◄──── Mux Handshake ──────────────►    │  (tunnel layer handshake)
    │                                        │
    │ ── [Stream 1] AuthRequest ──────────►  │  (if auth enabled)
    │     { token: "xxx",                    │
    │       version: "1.0",                  │
    │       subdomain: "myapp" }             │
    │                                        │  → Validate Token
    │                                        │  → Check connect permission
    │ ◄── [Stream 1] AuthResponse ────────   │
    │     { success: true,                   │
    │       subdomain: "myapp",              │
    │       session_id: "abc123" }           │
    │                                        │
    │ ── [Stream 2] RegisterRequest ──────►  │
    │     { local_port: 8080,                │
    │       protocol: "HTTP",                │
    │       subdomain: "myapp" }             │
    │                                        │  → Assign subdomain
    │                                        │  → Register route
    │ ◄── [Stream 2] RegisterResponse ────   │
    │     { success: true,                   │
    │       tunnel_id: "abc123",             │
    │       public_url: "http://myapp.ex.." }│
    │                                        │
    │ ── [Stream 3] PingRequest ──────────►  │  (periodic heartbeat)
    │ ◄── [Stream 3] PingResponse ────────   │
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
    │                     │ ──────────────────► │ 5. ReadRequest()   │
    │                     │  (raw HTTP request) │    parse HTTP      │
    │                     │                     │                    │
    │                     │                     │ 6. RoundTrip()     │
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

4. **Multi-tunnel dispatch** (`handler.go: resolveTunnelID` / `client.go: resolveLocalAddr`):
   - Step 1 (`Route(Host)`) only resolves the request down to a `ClientSession` — a single client connection may have **multiple** registered tunnels (multi-tunnel YAML config), each with its own local backend.
   - The server's `resolveTunnelID(client, host, path)` disambiguates which of the client's tunnels the request is actually for, matching in priority order: custom hostname → per-tunnel subdomain → longest path-prefix. The result populates `StreamRequest.TunnelID`.
   - The client's `resolveLocalAddr(tunnelID)` looks up that `TunnelID` in its `activeTunnels` map to find the tunnel-specific `LocalHost`/`LocalPort`, falling back to the top-level client config only when `TunnelID` is empty or unrecognized (single-tunnel backward compatibility).
   - This ensures that in multi-tunnel mode, traffic for each subdomain/hostname/path is forwarded to its own configured local port instead of all traffic collapsing onto the first-registered tunnel.

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

The `StreamRequest` for a TCP connection carries the originating `TunnelID` (set by `serveTCPTunnel`/`handleTCPConnection`, one dedicated listener per registered TCP tunnel), so the client's `resolveLocalAddr` dispatches to the correct local backend in multi-tunnel mode — the same mechanism used for HTTP (see "Multi-tunnel dispatch" above).

### Port Allocation Failure Handling

`TCPPortAllocator` draws from a bounded port range (default `10000-20000`, see `--tcp-port-range`). If registration requests a TCP tunnel and the allocator has no free port left, `handleRegister` **rejects the registration** with `RegisterResponse{Success: false}` and a descriptive error — it does not silently "succeed" with `TCPPort: 0` (which would previously report a working tunnel that could never actually accept a TCP connection). Any per-tunnel subdomain that was tentatively registered for the failed tunnel is rolled back to avoid leaking a claimed-but-unusable route.

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
                    │  GET  /api/inspector/records    │ ◄── History query
                    │  GET  /api/inspector/records/:id│ ◄── Details
                    │  GET  /api/inspector/stats      │ ◄── Statistics
                    │  POST /api/inspector/clear      │ ◄── Clear all
                    │  POST /api/inspector/toggle     │ ◄── Toggle capture
                    │  WS   /api/inspector/ws         │ ◄── Live stream
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

## P2P Direct Connection (Phase 4 & 4.5)

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

### Implementation

Phase 4 provides the foundational P2P primitives, and Phase 4.5 completes end-to-end integration:

| Component | File | Status |
|-----------|------|--------|
| **NAT Types** | `pkg/p2p/nat.go` | ✅ Complete — Full Cone, Restricted, Port Restricted, Symmetric |
| **STUN Client** | `pkg/p2p/stun.go` | ✅ Complete — RFC 5389 binding, dual-server NAT classification |
| **Hole Puncher** | `pkg/p2p/hole_punch.go` | ✅ Complete — UDP probe/ack with WHPP magic prefix |
| **Port Predictor** | `pkg/p2p/predictor.go` | ✅ Complete — Delta-based prediction for symmetric NAT |
| **P2P Manager** | `pkg/p2p/manager.go` | ✅ Complete — Coordinates STUN + hole punch + relay fallback |
| **Reliable UDP Transport** | `pkg/p2p/mux.go`, `pkg/p2p/stream.go` | ✅ Complete — `UDPMux`/`UDPStream`: multiplexed ARQ with adaptive RTO (RFC 6298), sliding window, reliable SYN handshake |
| **Signaling Messages** | `pkg/proto/messages.go` | ✅ Complete — P2POfferRequest/Response (targeted by subdomain), Candidates, Result |
| **Client Integration** | `pkg/client/client.go`, `cmd/wormhole/cmd/connect.go` | ✅ Complete — NAT discovery, P2P offer, `wormhole connect` direct data plane |
| **Server Signaling** | `pkg/server/server.go` | ✅ Complete — Subdomain-targeted peer matching, NAT compatibility check |
| **Integration Tests** | `pkg/p2p/integration_test.go` | ✅ Complete — 15+ test cases |

> **Note on scope (P3-3 / DP-23):** P2P only ever carries traffic between two `wormhole` processes that can both run the hole-punch protocol — i.e. `wormhole client` ↔ `wormhole connect`. A public visitor hitting your tunnel's hostname (a browser, curl, mobile app, etc.) is not running Wormhole's P2P protocol and physically cannot be hole-punched, so that traffic always goes through the Server relay; P2P for that path is not a roadmap gap, it's a hard physical constraint. Earlier versions of this document described a "hot switch" from relay to P2P for arbitrary tunnel traffic, which did not correspond to anything actually wired up end-to-end (the mux was established but no code path ever routed real HTTP/TCP tunnel bytes through it). `wormhole connect` (below) is what makes P2P carry real traffic in the one scenario where it's physically possible.

### Reliable UDP Transport Layer

Production P2P data transfer is carried by `UDPMux` + `UDPStream` (`pkg/p2p/mux.go`, `pkg/p2p/stream.go`) — a custom ARQ-based reliable, ordered, multiplexed stream layer over a single UDP socket pair. The older single-stream `pkg/p2p/transport.go` implementation it superseded has been removed (P3-3 / DP-16); anything it covered is now exercised against `UDPMux`/`UDPStream` instead.

**Adaptive retransmission (RFC 6298, P3-3 / DP-13):** instead of a fixed 200ms retransmit timeout, `UDPStream` maintains per-stream SRTT/RTTVAR estimates (`updateRTO`, gains α=1/8, β=1/4, `RTO = SRTT + 4×RTTVAR`, clamped to `[100ms, 10s]`) sampled from ACKs of segments that were **not** retransmitted (Karn's algorithm — a retransmitted segment's ACK is ambiguous about which transmission it's acking, so it's excluded from the sample to avoid skewing the estimate). Each in-flight segment additionally backs off its *own* retransmit timer exponentially (doubling per attempt, capped at 32× the base RTO) rather than sharing one global timer, so a single lossy segment doesn't inflate the timeout applied to every other segment on the stream. This lets the stream retransmit aggressively on a clean low-latency link and back off gracefully on a lossy/high-RTT one, instead of picking one fixed value that's wrong for most conditions.

**Reduced copies (P3-3 / DP-14):** the send path's `SessionCipher.EncryptInto` encrypts directly into the pre-sized outbound frame buffer instead of encrypting into a scratch buffer and then copying into the frame; the receive path (`handleData`/`deliverLocked`) no longer re-copies a payload that `decryptPayload` already returned as an independently-owned buffer. Combined, this cuts the encrypted send path from 8 allocations / 5200 B per packet to 6 allocations / 2640 B (`BenchmarkMux_SendPacket`), with no throughput regression under simulated WAN conditions (`BenchmarkUDPMux_Throughput_SimulatedWAN`, 50ms RTT / 1% loss).

```
┌─────────────────────────────────────────────────────────┐
│                    UDPMux (1 per P2P peer connection)     │
│                                                          │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    │
│  │  Sequence  │    │  ACK       │    │  Retrans   │    │
│  │  Numbering │    │  Handling  │    │  Timer     │    │
│  └────────────┘    └────────────┘    └────────────┘    │
│                                                          │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    │
│  │  Send      │    │  Out-of-   │    │  FIN/RST   │    │
│  │  Window    │    │  Order Buf │    │  Close     │    │
│  │  (64 seg)  │    │  (per stream) │  │            │    │
│  └────────────┘    └────────────┘    └────────────┘    │
│                                                          │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
                    UDP Connection
```

Each `UDPStream` multiplexed on the mux has an independent receive buffer (`recvCh`, capacity 256 segments) and sliding send window (64 in-flight segments). The mux's single `readLoop` goroutine dispatches every incoming packet to the target stream's `handleData`.

**Backpressure on a slow consumer** (`deliverLocked`): when the local application isn't draining `Read()` fast enough and `recvCh` is full, `deliverLocked` blocks for a short bounded timeout (200ms) rather than dropping the segment. If the timeout elapses, the segment's ACK is **withheld** — the sender's own retransmit timer then resends it, which naturally throttles the sender (implicit window-shrink) until the consumer catches up. If the consumer stays stuck long enough that `deliverLocked` times out `maxConsecutiveDeliverFailures` times in a row (25, ≈5s), the stream sends an RST and force-closes rather than retrying forever. This guarantees no segment is ever both dropped and ACKed — the old behavior that could silently desynchronize `recvSeq` from what was actually delivered to the application.

**Reliable stream handshake (SYN/SYN-ACK):** `OpenStream()` registers the outbound SYN under reserved sequence `0` in the same send buffer used for data segments (real data always starts at seq `1`), so `retransmitLoop` retries the SYN exactly like any other segment until it's acknowledged or `MaxRetransmits` is exhausted. The accepting side replies with an ordinary ACK for seq `0` once the stream is admitted, and re-ACKs on a duplicate SYN (covering the case where its first SYN-ACK was itself lost). Without this, a single dropped SYN packet would leave the peer unaware of the stream forever — every subsequent data segment would be silently discarded by `dispatch()` as "unknown stream", and the accepting side would block in `AcceptStream()`/`Read()` indefinitely instead of surfacing a connection failure. When any segment (including the SYN) exhausts `MaxRetransmits`, the sender now also sends an RST before force-closing locally, so the peer learns the stream died instead of hanging.

### `wormhole connect`: Client-to-Client Direct Data Plane (P3-3 / DP-23)

`wormhole connect <target-subdomain> --local <port>` is the scenario where P2P actually carries real application traffic end-to-end. One process runs `wormhole client` and exposes a service as usual (registering a tunnel + subdomain with the Server); a second process runs `wormhole connect <that-subdomain>` instead of `wormhole client` — it does **not** register a tunnel of its own, it only asks the Server to match it against the peer that owns the given subdomain.

```
┌──────────────────────────────────────────────────────────┐
│              wormhole connect data flow                   │
│                                                           │
│  1. Peer A: `wormhole client --local 8080 --subdomain a`  │
│     registers tunnel "a" with the Server (signaling only) │
│                                                           │
│  2. Peer B: `wormhole connect a --local 9090`              │
│     sends P2POfferRequest{target_subdomain: "a"}           │
│     Server looks up "a" via Router.LookupSubdomain(),      │
│     returns P2POfferResponse{peer_tunnel_id: <A's tunnel>} │
│                                                           │
│  3. Both sides STUN + hole-punch (same primitives as       │
│     Phase 4/4.5); on success both have a UDPMux over a     │
│     single UDP socket pair                                │
│                                                           │
│  4. Peer B listens on 127.0.0.1:9090; for every accepted   │
│     local connection it opens a UDPStream on the mux,      │
│     sends a StreamRequest addressed to A's peer_tunnel_id, │
│     and proxies bytes bidirectionally — the Server never   │
│     sees a single byte of this traffic, only the initial   │
│     signaling messages                                     │
│                                                           │
│  5. No relay fallback: if the hole punch fails or the      │
│     UDPMux later dies, `wormhole connect` closes its local │
│     listener rather than silently degrading — there is no  │
│     tunnel registered on the Server for this session to    │
│     relay through                                          │
└──────────────────────────────────────────────────────────┘
```

Server-side, `Server.findPeerBySubdomain` (in `pkg/server/server.go`) resolves `target_subdomain` to both the owning `ClientSession` and the specific `TunnelInfo.ID` serving it (a peer may expose more than one tunnel), distinguishing "no target requested" (a normal `wormhole client` registering its own P2P reachability, silently ignored), "target not found", "target is self", and "target has no usable P2P/NAT info" as distinct `P2POfferResponse.Error` reasons.

This is deliberately **not** how the normal public-visitor tunnel path works — see the scope note above.

### NAT Type Classification

| NAT Type | Traversal Difficulty | Strategy |
|----------|---------------------|----------|
| None (Open Internet) | ★☆☆☆ | Direct connection, always succeeds |
| Full Cone | ★☆☆☆ | Direct connection, almost always succeeds |
| Restricted Cone | ★★☆☆ | Requires outbound probe first |
| Port Restricted Cone | ★★★☆ | Requires port-matched probe |
| Symmetric | ★★★★ | Port prediction + multi-attempt, lower success rate |

### Degradation Strategy

```
Attempt P2P Connection
    │
    ├── Success → acceptP2PStreams() / startConnectListener()
    │              proxy data over the UDPMux
    │
    └── Failure → `wormhole client`: automatic fallback to Server relay
                  (fallbackToRelay() resets P2P state)
                  `wormhole connect`: no relay to fall back to — the
                  command fails outright (see above)
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
On 3 consecutive failures: force-close the mux, which triggers reconnection
```

### Connection-Loss Detection (`Mux.CloseNotify()`)

Reconnection is only useful if connection loss is actually detected. `tunnel.Mux` exposes a `CloseNotify() <-chan struct{}` channel that is closed exactly once, either when `Close()` is called explicitly or when the underlying TCP connection dies (read/write error in the mux's internal loops).

`Client.handleConnection()` blocks on a `select` across `mux.CloseNotify()`, `ctx.Done()`, and the client's own shutdown channel — **not just `ctx.Done()`** — so a dead mux unblocks the handler immediately instead of leaving a "half-alive" connection that looks `connected` but can no longer carry traffic. Once unblocked by `CloseNotify()`, the client clears its `connected` flag and returns control to `connectWithRetry()`, which re-enters the exponential-backoff loop above and re-registers every previously active tunnel (including all tunnels in multi-tunnel mode).

`heartbeatLoop()` also selects on `mux.CloseNotify()` so it exits promptly rather than only checking mux health when its ticker fires. After **3 consecutive** ping failures, it proactively calls `mux.Close()` — this is what turns a silently-stalled connection (TCP still "open" but no longer responsive) into a detected connection loss, closing the loop with the mechanism above.

---

## Authentication & Authorization

### Overview

Wormhole supports optional authentication to protect the server from unauthorized client connections. The auth module is located in `pkg/auth/`.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Auth Module (pkg/auth/)                  │
│                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐ │
│  │   Token    │  │   Rate     │  │   Audit                │ │
│  │  Manager   │  │  Limiter   │  │   Logger               │ │
│  │            │  │            │  │                        │ │
│  │ - Generate │  │ - IsBlocked│  │ - LogAuthSuccess       │ │
│  │ - Validate │  │ - RecordFail│ │ - LogAuthFailure       │ │
│  │ - Revoke   │  │ - Unblock  │  │ - LogIPBlocked         │ │
│  └─────┬──────┘  └─────┬──────┘  └──────────┬─────────────┘ │
│        │               │                     │               │
│        └───────────────┼─────────────────────┘               │
│                        │                                     │
│                        ▼                                     │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                  Storage Backend                        │ │
│  │                                                         │ │
│  │   ┌──────────────┐         ┌──────────────┐            │ │
│  │   │   Memory     │   OR    │   SQLite     │            │ │
│  │   │  (default)   │         │ (persistent) │            │ │
│  │   └──────────────┘         └──────────────┘            │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

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

### Rate Limiting

The rate limiter (`ratelimit.go`) protects against brute-force attacks:

```
┌─────────────────────────────────────────┐
│          Rate Limit Flow                 │
│                                          │
│  Auth Request                            │
│       │                                  │
│       ▼                                  │
│  ┌─────────────┐                         │
│  │ IsBlocked?  │──Yes──► 429 Too Many    │
│  └──────┬──────┘         Requests        │
│         │ No                             │
│         ▼                                │
│  ┌─────────────┐                         │
│  │  Validate   │                         │
│  │   Token     │                         │
│  └──────┬──────┘                         │
│         │                                │
│    ┌────┴────┐                           │
│    │         │                           │
│  Success   Failure                       │
│    │         │                           │
│    ▼         ▼                           │
│ RecordSuccess  RecordFailure             │
│ (clear count)  (increment count)         │
│                    │                     │
│              ┌─────┴─────┐               │
│              │ >= 5 fails?│              │
│              └─────┬─────┘               │
│                    │ Yes                 │
│                    ▼                     │
│              Block IP for                │
│              15 minutes                  │
└─────────────────────────────────────────┘

Default Configuration:
- MaxFailures: 5
- Window: 5 minutes
- BlockDuration: 15 minutes
```

### Audit Logging

The audit logger (`audit.go`) records security and lifecycle events for compliance and debugging.

#### Event Types

| Event Type | Description |
|------------|-------------|
| `auth_success` | Successful authentication |
| `auth_failure` | Failed authentication attempt |
| `ip_blocked` | IP blocked due to rate limit |
| `ip_unblocked` | IP manually unblocked |
| `token_generated` | New token created |
| `token_revoked` | Token explicitly revoked |
| `team_tokens_revoked` | All tokens for a team revoked |
| `client_connected` | Client established tunnel |
| `client_disconnected` | Client disconnected |
| `tunnel_created` | Tunnel registered by client |
| `tunnel_closed` | Tunnel closed gracefully |
| `p2p_established` | P2P direct connection established |
| `p2p_fallback` | P2P failed, using relay |

#### AuditStore Backends

```
AuditLogger
    └── AuditStore (interface)
          ├── MemoryAuditStore  — ring buffer (default; configurable capacity)
          └── SQLiteAuditStore  — persistent SQLite database
```

The `AuditStore` interface provides `Store(event)` and `Query(AuditQuery)`. `AuditQuery` supports filtering by event type, session ID, IP, time range, and pagination (`Offset`, `Limit`).

#### Admin Query API

```
GET  /audit?type=auth_failure&from=<RFC3339>&to=<RFC3339>&limit=50  → JSON array
GET  /audit/export?format=csv|json                                   → file download
```

### Persistent Storage

Storage backends (`store.go`, `store_sqlite.go`):

| Backend | Use Case | Configuration |
|---------|----------|---------------|
| **Memory** | Development, stateless deployments | Default |
| **SQLite** | Production, persistent team data | `--persistence sqlite` |

SQLite stores:
- Team information (name, creation time, revoked version)
- Revoked token blacklist
- Token metadata (expiry, revocation status, version)

### Authentication Handshake Flow

```
  Client                                Server
    │                                      │
    │  ── Mux.OpenStream() ──►            │
    │                                      │  ◄── Mux.AcceptStream()
    │                                      │      (with timeout, default 10s)
    │                                      │
    │                                      │  1. rateLimiter.IsBlocked(ip)?
    │                                      │     → Yes: close connection
    │                                      │
    │  ── AuthRequest ──────────────────► │
    │     { token: "xxx",                 │
    │       version: "1.0.0",             │
    │       subdomain: "myapp" }          │
    │                                      │  2. ValidateToken(token)
    │                                      │     → Try simple match first
    │                                      │     → Then try HMAC verification
    │                                      │  3. HasPermission(claims, "connect")
    │                                      │  4. rateLimiter.RecordSuccess/Failure
    │                                      │  5. auditLogger.LogAuthSuccess/Failure
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
- `/stats`, `/clients`, `/tunnels`, `/teams` are protected by `--admin-token`
- Uses `Authorization: Bearer <token>` header
- Token comparison uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks
- When `--admin-token` is not set, only loopback address requests (`127.0.0.1` / `::1`) are allowed; non-loopback requests return 403 Forbidden
- Admin API binds to `127.0.0.1` by default (override with `--admin-host` flag)

### Team Management API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/teams` | GET | List all teams |
| `/teams` | POST | Create a new team |
| `/teams/{name}` | GET | Get team details |
| `/tokens/generate` | POST | Generate token for a team |
| `/tokens/revoke` | POST | Revoke a token |

### Client Token Persistence

The client stores authentication tokens locally (`~/.wormhole/config.yaml`):

```yaml
server_addr: "tunnel.example.com:7000"
token: "eyJ0ZWFtIjoiYWxwaGEiLCJyb2xlIjoibWVtYmVyIi4uLn0.xxx"
subdomain: "myapp"
tls_enabled: true
tls_insecure: false
p2p_enabled: true
```

- Tokens are saved with restrictive permissions (0600)
- Command-line flags override persistent config
- `--save-token` flag persists token after successful auth

---

## Security Model

### Transport Encryption

- Server supports TLS termination (Let's Encrypt auto-certs or manual certificates)
- Client-Server tunnel connection supports TLS encryption (client `--tls` / `--tls-insecure` / `--tls-ca` flags)
- Server tunnel listener can independently enable TLS via `--tunnel-tls` flag

### P2P End-to-End Encryption

P2P direct connections use end-to-end encryption to protect data confidentiality and integrity, even when the signaling server is untrusted:

```
  Client A                    Server (Signaling)                Client B
    │                              │                              │
    │  1. Generate X25519 keypair  │                              │
    │     (privA, pubA)            │                              │
    │                              │  2. Generate X25519 keypair  │
    │                              │     (privB, pubB)            │
    │                              │                              │
    │  ── P2POfferRequest ──────►  │  ── P2POfferResponse ──────► │
    │     { public_key: pubA }     │     { peer_public_key: pubA }│
    │                              │                              │
    │  ◄── P2POfferResponse ─────  │  ◄── P2POfferRequest ─────   │
    │     { peer_public_key: pubB }│     { public_key: pubB }     │
    │                              │                              │
    │  3. ECDH(privA, pubB)        │                              │
    │     → shared secret          │  3. ECDH(privB, pubA)        │
    │     → HKDF derive:           │     → same shared secret     │
    │       - AES-256 enc key      │     → HKDF derive:           │
    │       - HMAC punch key       │       - AES-256 enc key      │
    │                              │       - HMAC punch key       │
    │                              │                              │
    │  4. HMAC-authenticated hole punch ◄════════════════════►    │
    │                              │                              │
    │  5. AES-256-GCM encrypted data ◄═══════════════════════►    │
```

Key components:

| Component | Description |
|-----------|-------------|
| **Key Exchange** | X25519 ECDH — each peer generates an ephemeral keypair per session |
| **Key Derivation** | HKDF-SHA256 with separate info labels: `"wormhole-p2p-encryption"` for AES key, `"wormhole-p2p-punch-hmac"` for probe HMAC key |
| **Data Encryption** | AES-256-GCM with monotonic nonce counter (8-byte counter + 4 zero bytes) |
| **Probe Authentication** | HMAC-SHA256 on hole-punch probe payloads, preventing injection of spoofed probes |
| **Forward Secrecy** | Ephemeral keys per session — compromising one session does not affect others |
| **Server Blindness** | Server relays only public keys; it cannot derive the shared secret or decrypt data |

### Authentication

- **Multi-mode token authentication**:
  1. Simple pre-shared tokens (quick deployment)
  2. HMAC-SHA256 signed team tokens (with expiry + revocation)
  3. OIDC JWT tokens — `ValidateToken` tries OIDC if an `OIDCValidator` is configured and the token is JWT-shaped
- Role-based access control (RBAC): admin, member, viewer roles
- Mandatory authentication on connection handshake (`--require-auth`); viewer role cannot establish tunnels — enforced server-side at the point of use (`handleRegister`/`handleClose` call `requireWritePermission`), not just hidden from a client-side menu
- Admin API protected by separate token using `crypto/subtle.ConstantTimeCompare`
- Token revocation support with persistent blacklist (SQLite backend)

#### OIDC / SSO Integration

```
Auth.ValidateToken(token)
  ├── 1. Simple pre-shared token match
  ├── 2. isJWT? + OIDCValidator configured?
  │       └── OIDCValidator.ValidateToken(jwt)
  │               ├── OIDC Discovery (issuer/.well-known/openid-configuration)
  │               ├── JWKS key fetch + cache (TTL 1h)
  │               ├── JWT signature verification (RS256 / ES256)
  │               ├── Claims: iss, aud, exp validation
  │               └── OIDCClaimMapping → Claims{TeamName, Role}
  └── 3. HMAC-SHA256 signed token verification
```

The `OIDCValidator` caches JWKS keys with a 1-hour TTL and auto-refreshes on unknown `kid`. Supported algorithms: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`.

#### OAuth2 Device Code Flow (`wormhole login`)

```
wormhole login --issuer <url> --client-id <id>
  │
  ├── 1. OIDC Discovery → device_authorization_endpoint, token_endpoint
  ├── 2. POST /device/auth → { device_code, user_code, verification_uri, interval }
  ├── 3. Print: "Open <url> and enter code: XXXX-YYYY"
  ├── 4. Poll token endpoint every <interval> seconds (request body includes
  │       client_id per RFC 8628 §3.4, required by strict IdPs like Keycloak)
  └── 5. On success: SaveCredentialsFull(~/.wormhole/credentials.json, {
            token, expires_at (parsed from the JWT's own `exp` claim,
            falling back to expires_in), refresh_token, oidc_issuer,
            client_id, token_endpoint })
```

**End-to-end usage (no manual token handling required):** `wormhole client` (via `resolveClientCredentials` in `cmd/wormhole/cmd/client.go`) automatically loads the saved credentials for `--server` when `--token` isn't explicitly given. If the saved token is expired but the credentials carry enough material to refresh (`Credentials.CanRefresh()`: `refresh_token` + `client_id` + `token_endpoint`), it's silently renewed via the OAuth2 `refresh_token` grant (`auth.RefreshAccessToken`) and the renewed credentials are persisted back to disk — no re-running `wormhole login`. The same refresh path is also wired as `Config.OnAuthFailure`, so a token that expires *mid-session* (e.g. across a reconnect triggered by `Mux.CloseNotify()`) is refreshed and retried automatically by `authenticateWithRefresh()` instead of failing the connection.

### Rate Limiting

- Authentication failure tracking per IP address
- Configurable thresholds: 5 failures within 5 minutes → 15 minute block
- Automatic expiration and cleanup of rate limit records
- Manual unblock capability via Admin API
- Blocked IPs cannot attempt authentication

### Audit Logging

- Structured JSON logging of security and lifecycle events
- Events: auth success/failure, IP blocked/unblocked, token generated/revoked, tunnel created/closed, P2P established/fallback, client connect/disconnect
- Pluggable `AuditStore`: in-memory ring buffer (default) or SQLite (persistent)
- Admin API: `GET /audit` with filters + `GET /audit/export` for CSV/JSON bulk export

### Input Validation

- HTML escaping on Host header routing (XSS prevention)
- Subdomain restricted to single-level labels (no dots)
- Path prefix normalization (leading/trailing `/`)

### Security Hardening (P3-4)

A dedicated review pass (`docs/personal/review-v0.6.md`) audited every security-relevant code path in v0.6.0 and closed the gaps below. Each item is independently unit-tested.

| Area | Before | After |
|------|--------|-------|
| **RBAC enforcement point** | Only the CLI hid write actions from viewers; the server accepted any authenticated client's `RegisterRequest`/`CloseRequest` | `handleRegister`/`handleClose` call `requireWritePermission(client)` first; a `viewer` token is rejected with an explicit error and an audit event, regardless of what client sent the request |
| **Tunnel control-channel TLS** | The tunnel listener was wrapped with the *same* `TLSConfig()` used for the HTTP listener, which short-circuits to "no TLS" whenever `Config.TLSEnabled` is false — so `TunnelTLSEnabled=true` alone was a silent no-op | `TLSManager.TunnelTLSConfig()`/`WrapTunnelListenerStrict()` are fully independent of the HTTP TLS config; `--require-auth` + a real domain now defaults `TunnelTLSEnabled` to `true`, and a TLS *config* error (not just "no cert configured") fails server startup outright when auth is required, instead of falling back to plaintext |
| **Subdomain reservation** | `RegisterRoute` on both the in-memory router and the Redis-backed cluster store was last-writer-wins: two clients (or two nodes) racing for the same subdomain would silently overwrite each other, and the loser would keep believing it owned the route | Atomic reservation with four defined outcomes: free → reserved; same client re-registering → idempotent TTL refresh; a *live* different owner → `ErrSubdomainConflict` (connection rejected); a *stale* owner (its route entry already expired) → reclaimed. The Redis implementation uses `SetArgs{Mode: "NX"}` (the non-deprecated replacement for `SetNX`) |
| **Token expiry mutation** | `ExtendTokenExpiry` temporarily overwrote the shared `Auth.config.TokenExpiry` field to reuse the token-generation code path, then restored it — a data race under concurrent requests | `generateTeamToken(teamName, role, expiry)` takes the expiry as an explicit parameter; nothing ever mutates shared config |
| **Revoked-token cleanup** | `Auth.CleanupRevokedTokens()` existed and worked, but nothing ever called it — the revocation blacklist (and its SQLite table, if persistence is enabled) grew without bound | `Server.Start()` schedules `runRevokedTokenCleanup()`, a goroutine that sweeps expired blacklist entries every 10 minutes |
| **OIDC `alg: none`** | An `alg: none`/empty-`alg` JWT fell through to the generic "unsupported algorithm" branch — functionally rejected, but not by an explicit, tested guard against the classic signature-bypass attack | `verifyJWTSignature` has a dedicated `case "none", ""` that rejects immediately, with a regression test |
| **OIDC issuer/`nbf`** | Issuer comparison was a raw string match (trailing-slash mismatches between a provider's discovery document and its issued tokens could cause spurious rejections); `nbf` was never checked | `normalizeIssuer()` strips trailing slashes before comparing; `nbf` is validated with the same 60s `clockSkewLeeway` already used for `exp` |
| **Inspector captures** | `Authorization`/`Cookie`/etc. headers were stored verbatim in captured records (visible via the inspector UI/API); default body-capture cap was 1MB | `captureHeaders()` redacts a fixed set of sensitive header names (case-insensitively) to a constant placeholder on both request and response capture; default `MaxBodySize` lowered to 256KB |
| **`/metrics`** | Exposed with no authentication, unlike every other Admin API route | Wrapped with the same `requireAdminAuth` middleware as `/stats`, `/audit`, etc. |
| **Audit gaps** | Only failures were logged (`LogAuthFailure`); successful auth, IP blocks, token generation, and IP unblocks left no audit trail; `RefreshAndRevokeToken` silently swallowed a failed revocation | `LogAuthSuccess`/`LogIPBlocked`/`LogTokenGenerated`/`LogIPUnblocked` added at their respective call sites; `RefreshAndRevokeToken` now returns the new token *and* a wrapped error on partial failure, surfaced to the caller as a `Warning` field instead of silently discarded |
| **Audit retention** | No way to bound audit log growth over the life of a long-running server | `AuditStore.DeleteOlderThan(cutoff)` (implemented by both the memory and SQLite stores) + `--audit-retention-days` (default 90) + a periodic `runAuditRetention()` sweep |
| **Audit store write failures** | `AuditLogger.Log()` discarded `l.store.Store(event)` errors (`_ = ...`) — a failing persistence backend (e.g. a full disk or locked SQLite file) dropped events with zero observable signal | An `atomic.Uint64` `storeErrors` counter increments on every failed `Store()` call; `AuditLogger.StoreErrors()` exposes it, and `GET /stats` surfaces it as `audit_store_errors` (omitted when audit logging is disabled) so the failure mode is monitorable/alertable instead of silent |
| **Subdomain registration failure at connect time** | A local or cluster-wide subdomain conflict was only logged; the connection proceeded and the client was told (via `AuthResponse`) that it owned the subdomain, while traffic actually kept routing to whichever session held the entry | `registerClientRoute()` rejects and closes the connection on either a local or cluster conflict, so the client's own reconnect logic retries instead of running in a silently broken state |
| **Inter-node proxy trust (S1, P3-5)** | `proxyToNode` forwarded requests between cluster nodes with no authentication — any host that could reach a node's HTTP port could forge `X-Wormhole-*` proxy headers and impersonate a peer node | `--cluster-secret` shared secret; `proxyToNode` attaches it as `X-Wormhole-Cluster-Secret`, `verifyClusterSecret` validates and strips it before the request reaches routing logic, rejecting mismatched/missing secrets when one is configured |
| **Cross-node token revocation (H5, P3-5)** | With `--persistence sqlite` or the in-memory default, a token revoked on node A stayed valid on node B until that node's own store happened to converge (it never did, for two independent SQLite files) | `--persistence redis` (`auth.RedisStore`) puts teams and revoked-token state in the same shared Redis the cluster already uses for routing; a revocation is visible cluster-wide as soon as the write completes, with TTL-based auto-expiry instead of a cleanup sweep |

---

## Multi-Tunnel Configuration & Hot-Reload

### Config File (`pkg/client/config_file.go`)

YAML-based client configuration enables declaring multiple tunnels declaratively:

```yaml
server: tunnel.example.com:7000
tls: true
token: my-team-token

tunnels:
  - name: web
    local_port: 3000
    protocol: http
  - name: api
    local_port: 8080
    subdomain: myapi
  - name: db
    local_port: 5432
    protocol: tcp
```

### Multi-Tunnel Startup Flow

```
Client.connect()
  └── config.Tunnels non-empty?
        ├── Yes → registerAllTunnels()
        │           └── for each TunnelDef → registerOneTunnel() → activeTunnels[name]
        └── No  → registerTunnel() (legacy single-tunnel mode)
```

### SIGHUP Hot-Reload

```
SIGHUP received
  └── LoadFileConfig(path) → new FileConfig
        └── c.ReloadTunnels(newDefs)
              ├── diff: find removed tunnels → CloseTunnel() each
              └── diff: find added tunnels   → registerOneTunnel() each
```

No restart needed; the tunnel connection remains open.

### Local Control API (`pkg/client/control.go`)

```
GET http://localhost:<ctrl-port>/tunnels
→ JSON array of TunnelInfo { Name, LocalPort, Protocol, PublicURL, CreatedAt }
```

Used by `wormhole tunnels list` to display active tunnels.

---

## HA / Multi-Node Control Plane

### StateStore Interface (`pkg/server/state.go`)

```go
type StateStore interface {
    RegisterRoute(entry RouteEntry) error
    UnregisterRoute(clientID string) error
    UnregisterRouteEntry(routeID string) error
    LookupBySubdomain(subdomain string) (*RouteEntry, error)
    LookupByHostname(hostname string) (*RouteEntry, error)
    LookupByPathPrefix(path string) (*RouteEntry, error)
    ListRoutes() ([]RouteEntry, error)
    NodeHeartbeat(info NodeInfo) error
    GetNodes() ([]NodeInfo, error)
    EvictDeadNodes(olderThan time.Duration) error
    Close() error
}
```

`RouteEntry` carries `{RouteID, ClientID, Subdomain, Hostname, PathPrefix, NodeID, NodeAddr, RegisteredAt}` — a single client can hold several `RouteEntry`s at once (one tunnel's subdomain, another's custom hostname, a third's path prefix), each independently addressable by `RouteID` for targeted unregistration (H3). `NodeInfo` carries `{NodeID, NodeAddr, LastHeartbeat}`.

`RegisterRoute` must atomically reserve the entry's routing key (subdomain, hostname, or path — whichever is set) (S3/H6): free → reserve; same `ClientID` re-registering → idempotent TTL refresh; held by a different, still-live client → return `ErrSubdomainConflict`; held by a stale (expired) entry → reclaim. `RedisStateStore` implements this with `SetArgs{Mode: "NX"}` on the relevant `wormhole:sub:*`/`wormhole:host:*`/`wormhole:path:*` key, falling back to a liveness check against `wormhole:route:<routeID>` on conflict; `MemoryStateStore` implements the same four-way semantics under its own lock via a shared `conflictsWith` helper.

### Backends

| Backend | Class | Use Case |
|---------|-------|----------|
| `nil` (default) | — | Single-node; no distributed state |
| `MemoryStateStore` | `state_memory.go` | Single-node; validates cluster logic without Redis |
| `RedisStateStore` | `state_redis.go` | Multi-node; production clustering |

Redis key schema:

| Key | TTL | Content |
|-----|-----|---------|
| `wormhole:route:<routeID>` | 5 min | `RouteEntry` JSON |
| `wormhole:sub:<subdomain>` | 5 min | `routeID` pointer |
| `wormhole:host:<hostname>` | 5 min | `routeID` pointer |
| `wormhole:path:<prefix>` | 5 min | `routeID` pointer |
| `wormhole:clientroutes:<clientID>` | 5 min | SET of `routeID`s owned by this client, for bulk cleanup on disconnect |
| `wormhole:node:<nodeID>` | 90 s | `NodeInfo` JSON |

`ListRoutes`/`GetNodes` (and the auth store's `ListTeams`/`CountRevokedTokens`) use `SCAN` cursors rather than `KEYS`, so large key spaces don't block the shared Redis instance (H7).

### Route TTL Refresh (H1)

A route registered once and never touched again would silently expire out of Redis after 5 minutes even though the client is still connected — the single most damaging HA gap found in the v0.6 review. `ClientSession.clusterRoutes` tracks every `RouteEntry` a session has registered cluster-wide (its primary subdomain, plus any extra subdomains/hostnames/path prefixes from `registerTunnelRoutes`), and `startClusterHeartbeat`'s 30s tick calls `refreshClusterRoutes` to re-run `RegisterRoute` for all of them — a `pipeline`-friendly batch that's functionally an `EXPIRE`/TTL-refresh rather than a fresh reservation, since the entry already belongs to this client.

### Cluster Heartbeat (`pkg/server/cluster.go`)

```
startClusterHeartbeat(ctx)
  ├── tick every 30s → NodeHeartbeat(NodeInfo{NodeID, NodeAddr})
  │                     sendHeartbeat tracks StateStore reachability → Server.stateStoreHealthy (H9)
  ├── tick every 30s → refreshClusterRoutes(client) for every connected session (H1)
  └── tick every 60s → EvictDeadNodes(90s threshold)
                           └── MemoryStateStore: scan + delete dead nodes + owned routes
                               RedisStateStore: no-op — Redis TTL is the single source of truth for eviction (H8)
```

### Cross-Node HTTP Routing

```
HTTPHandler.ServeHTTP(r)
  ├── verifyClusterSecret(r) → reject if --cluster-secret set and header missing/mismatched (S1)
  ├── router.Route(host, path) → local ClientSession?
  │     └── Yes → forwardHTTP / handleWebSocket (normal path)
  └── No → server.lookupRemoteRoute(host, path, subdomain)   [hostname → longest path-prefix → subdomain]
              └── found remote RouteEntry?
                    ├── isLocalNode? → continue to 404 (stale entry)
                    └── No  → proxyToNode(route.NodeAddr, w, r)
                                  └── attach X-Wormhole-Cluster-Secret header (S1)
                                  └── httputil.ReverseProxy → target node
```

Hostname and path-prefix routes are indexed into Redis exactly like subdomains (H3), so a tunnel registered with `--hostname`/`--path` on node A is reachable through node B, not just its own subdomain.

**Node identity (H4)**: `applyClusterNodeIDDefault` defaults `Config.ClusterNodeID` to `os.Hostname()` whenever a cluster backend is configured but no explicit ID was given, so two nodes never accidentally share an empty NodeID.

**Stale ownership reclaim (H10)**: `router.go`'s `RegisterSubdomain`/`RegisterHostname`/`RegisterPath` check `isStaleOwner` (the existing owner's `Mux.IsClosed()`) before returning a conflict; `registerClientRoute` mirrors this on the cluster side, proactively unregistering the dead session's `StateStore` entries. A client that reconnects after a network blip gets its subdomain/hostname/path back immediately instead of a transient conflict error.

**Health surfacing (H9)**: `GET /health` includes `cluster: {node_id, state_store_healthy}`; if the state store becomes unreachable, overall `status` flips from `"ok"` to `"degraded"` so monitoring picks it up without needing a separate Redis probe.

### Inter-Node Authentication (S1)

`--cluster-secret` is a shared secret across all nodes in a cluster. `proxyToNode` attaches it as `X-Wormhole-Cluster-Secret` on every proxied request; `verifyClusterSecret` (called first in `HTTPHandler.ServeHTTP`) rejects requests where the header is missing or doesn't match, and strips the header before continuing so it's never forwarded to the local tunnel client. Without a configured secret, no check is performed (backward-compatible with pre-S1 single-node/unsecured deployments) — operators running a real cluster should always set it, since without it a network peer could forge `X-Wormhole-*` proxy headers.

### Shared Auth/Revocation State (H5)

`--persistence redis` (`pkg/auth/store_redis.go`, `auth.RedisStore`) stores teams under `wormhole:auth:team:<name>` and revoked tokens under `wormhole:auth:revoked:<tokenID>` with a Redis TTL matching the token's remaining lifetime — a token revoked on node A is invisible on node B the moment the write completes, with no propagation delay and no periodic sweep needed (`CleanupExpiredRevocations` is a no-op on this backend, since TTL already deletes the key). `--auth-redis-addr/-password/-db` fall back to `--cluster-redis-*` when unset, so a single Redis instance can back both cluster routing state and auth/revocation state with one flag.

### TCP Tunnels Under HA (H2)

TCP tunnels are **node-local only**: a TCP tunnel's listener lives on whichever node the client happens to be connected to, and there is no cross-node TCP proxy (unlike the HTTP/WebSocket path, `StateStore` doesn't track TCP port ownership across nodes). Operators who need HA for TCP tunnels must put a TCP-aware load balancer (e.g. HAProxy in `mode tcp`, or an L4 DNS/anycast scheme) in front of the individual node addresses/ports themselves; Wormhole does not attempt to abstract this away. A full edge-port-proxy solution is tracked separately (see roadmap P3-6+) rather than bundled into this phase.

### Connection Limits

- `MaxClients` limits concurrent online clients
- TCP port allocation range restriction (default 10000-20000)
- Per-IP connection tracking for rate limiting

---

## Robustness & Protocol Hardening (P3-6 Batch A)

The first sub-batch of the P3-6 architecture-refactoring phase closed out a set of correctness gaps found in the `review-v0.6.md` audit and removed dead code, without touching the hot-path allocation/context work reserved for batches B/C or the god-object decomposition reserved for batch D.

### Graceful Shutdown (DP-26)

`Server` now holds the `*http.Server` values it constructs for the HTTP and admin listeners (previously they were only passed to `ListenAndServe`/`ListenAndServeTLS` and discarded). `Server.Shutdown()` calls `http.Server.Shutdown(ctx)` on each with a bounded timeout (`ShutdownTimeout`, default 10s) before closing the tunnel listener, so in-flight HTTP/admin requests get a chance to finish instead of having their connections yanked out from under them on `SIGTERM`.

### Bidirectional Proxy Half-Close (DP-04)

Both the WebSocket and TCP tunnel proxy paths pump two directions concurrently (client→local and local→client) with `io.Copy`. Previously, if one direction hit EOF/error first, the *other* direction only unblocked once its own read timed out or the peer independently closed — for a mostly-one-way conversation (e.g. a long-poll or an idle keep-alive) this could stall a stream's teardown for the full read timeout. Now the first direction to finish explicitly triggers a close/`CloseWrite` on the other side's connection, so both directions unwind immediately regardless of which one errors first.

### Concurrent Stream Limits (DP-03 / DP-27)

Two new server flags cap how many data-plane streams (HTTP/WebSocket/TCP proxy streams, not control-channel streams) can be open at once:

- `--max-concurrent-streams` (default 10000): a global, process-wide counter. When the limit is hit, new stream requests are rejected outright (not queued) so a spike in traffic degrades predictably (fast rejections) instead of unboundedly growing goroutines/memory.
- `--max-streams-per-client` (default 500): the same idea scoped to a single client connection, so one misbehaving or unusually busy tenant can't starve every other client's share of the global limit.

Both are implemented as `atomic.Int64` counters incremented before a stream is dispatched and decremented when it completes; acquiring is non-blocking (`CompareAndSwap`-style check-then-increment), matching the "reject fast" philosophy rather than adding a blocking semaphore that could itself become a queuing hazard.

### Control-Frame Validation (DP-17)

`DecodeControlMessage` previously accepted any bytes that protobuf could unmarshal without error — including all-zero or garbage input that happens to decode to `MessageType_MESSAGE_TYPE_UNKNOWN` with every oneof field unset. That's now explicitly rejected (`errUnknownEmptyMessage`) since it can only be malformed/corrupted input, never a legitimate message. The check is narrow by design: a message with `Type == UNKNOWN` that *does* carry a recognized payload (session or P2P) is still accepted, preserving forward compatibility for future message types a newer client might send to an older server.

### Protocol Version Gating & Real Capability Advertisement (DP-30 / DP-33)

- **Version gating**: `pkg/version` gained a minimal semver parser/comparator (`ParseSemver`, `Compare`) — deliberately not a full semver library, since Wormhole only needs `MAJOR.MINOR.PATCH` comparison, not pre-release/build-metadata ordering. The server's new `--min-client-version` flag rejects `AuthRequest`s from clients reporting an older version, with a clear auth-failure reason. Clients built from a non-tagged source (e.g. `dev`, empty string) fail semver parsing and are deliberately *never* rejected — version gating is an opt-in operator control, not a hard requirement for running unreleased builds.
- **Real capabilities**: `AuthResponse.Capabilities` previously didn't exist / was always empty. The server now populates it from `Server.capabilities()`, which derives the list (`p2p`, `multi-tunnel`, `cluster`, `audit`, ...) from the server's actual runtime configuration rather than a hardcoded aspirational list. The client stores the server's advertised capabilities and gates optional behavior on them — e.g. `sendP2POffer` is now skipped entirely if the server didn't advertise `"p2p"`, instead of always attempting an offer and relying on the server to silently ignore it. An absent/empty capability list (e.g. from an older server that predates this field) is treated as "unknown, assume supported" for backward compatibility.

### Dead Code Removal (DP-15)

`pkg/tunnel/pool.go` implemented a connection-pooling abstraction that was never wired into any caller — `Client`/`Server` always create a fresh `Mux` per connection rather than pulling from a pool. It and its tests were removed rather than kept as unreachable code that only adds maintenance burden and coverage noise.

### UDP Protocol Cleanup (V1)

The client CLI and config file previously listed `udp` as an accepted `--protocol` value even though the server has no UDP dataplane implementation (only the P2P subsystem uses UDP, as a *transport* underneath the reliable `UDPMux`/`UDPStream` layer — never exposed as a raw tunnel protocol). `ValidateProtocolString` now explicitly rejects `udp` with an actionable error message at the client/config-file layer, instead of silently falling back to HTTP semantics or letting a confusing failure surface deep in the server. `parseProtocol` (used at lower layers, e.g. persisted state) still defaults unrecognized strings to HTTP rather than erroring, preserving backward compatibility for already-persisted config.

### CLI Parity (U1 / U4)

- **`wormhole tunnels create/delete` (U1)**: the client's control API (`pkg/client/control.go`, gated behind `--ctrl-port` like the existing `list` endpoint) gained `POST /tunnels` and `DELETE /tunnels/{name}`, backed by new `Client.CreateTunnel`/`Client.DeleteTunnel` methods that register/unregister a tunnel on an already-running client process. This is the imperative counterpart to editing the YAML config and sending `SIGHUP` — useful for scripting or ad hoc tunnels without touching the client's persisted config at all. Tunnels added this way are not persisted; they don't survive a client restart unless also added to the config file.
- **`wormhole server -c server.yml` (U4)**: `pkg/server/config_file.go` mirrors the client's existing `FileConfig`/`LoadClientFileConfig` pattern — a `FileConfig` struct maps the YAML schema to server settings (including custom `time.Duration` string parsing), `validate()` catches malformed values (bad durations, unknown persistence/backend enum values) at load time rather than failing confusingly deep inside `Config` consumers, and `ToServerConfig(base)` merges only explicitly-set fields onto a base config (typically `DefaultConfig()`), leaving everything else untouched. Boolean fields that need a real tri-state (unset / explicitly false / explicitly true) — like `EnableMetrics` — use `*bool` rather than `bool`, since a plain `bool` can't distinguish "not mentioned in the file" from "set to false".

---

## Data Flow Summary

### Complete HTTP Request Path

```
Browser → DNS → Server:80/443
  → TLS termination
  → Router.Route(Host, Path) → find ClientSession
  → resolveTunnelID(client, Host, Path) → disambiguate which registered tunnel (multi-tunnel)
  → Mux.OpenStream() → new Stream
  → sendStreamRequest(metadata incl. TunnelID)
  → r.Write(stream) [raw HTTP request]
  ─── Mux frame encoding → TCP connection → reaches Client ───
  → handleStream() → read StreamRequest metadata
  → resolveLocalAddr(TunnelID) → this tunnel's LocalHost:LocalPort
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
