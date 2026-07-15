# Wormhole Architecture Guide

> This document describes the system architecture, network protocol design, and data flow of Wormhole in detail. It doubles as a learning guide: start with [How to Read This Document & the Code](#how-to-read-this-document--the-code) if you are new to the project.

**[中文版](architecture_zh.md)**

## Table of Contents

- [How to Read This Document & the Code](#how-to-read-this-document--the-code)
- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
- [Design Decisions & Trade-offs](#design-decisions--trade-offs)
- [Tunnel Multiplexing Protocol](#tunnel-multiplexing-protocol)
- [Frame Protocol](#frame-protocol)
- [Control Protocol](#control-protocol)
- [Authentication & Authorization](#authentication--authorization)
- [HTTP Proxy Flow](#http-proxy-flow)
- [TCP Tunnel Flow](#tcp-tunnel-flow)
- [Inspector Traffic Capture](#inspector-traffic-capture)
- [P2P Direct Connection](#p2p-direct-connection)
- [Connection Management](#connection-management)
- [Security Model](#security-model)
- [Multi-Tunnel Configuration & Hot-Reload](#multi-tunnel-configuration--hot-reload)
- [HA / Multi-Node Control Plane](#ha--multi-node-control-plane)
- [Server & Client Composition](#server--client-composition)
- [Reliability & Protocol Safeguards](#reliability--protocol-safeguards)
- [Hot-Path Performance](#hot-path-performance)
- [Go Patterns Used in This Codebase](#go-patterns-used-in-this-codebase)
- [Testing Strategy](#testing-strategy)
- [Data Flow Summary](#data-flow-summary)

---

## How to Read This Document & the Code

Wormhole is deliberately built with a small dependency footprint — the multiplexer, the reliable-UDP transport, and the control protocol are all implemented in this repository rather than pulled in as libraries. That makes it a good codebase for studying how a tunneling system works end to end. Below are three suggested paths, depending on how much time you have.

### 30 minutes — run it and see the moving parts

1. Build and run the three-terminal demo: `wormhole server` in one terminal, a local HTTP service (`python3 -m http.server 8080`) in another, `wormhole 8080` in a third, then `curl` the public URL.
2. Read [System Overview](#system-overview) and [Component Architecture](#component-architecture) to map what you just ran onto the boxes in the diagrams.
3. Open the Inspector UI (printed on client startup) and watch a request flow through.

### 2 hours — understand the relay path

Read the code in this order; each step builds on the previous one:

1. `pkg/tunnel/frame.go` — the 9-byte frame header. Everything on the wire is one of these frames.
2. `pkg/tunnel/mux.go` and `pkg/tunnel/stream.go` — how many logical streams share one TCP connection, and how flow control keeps one stream from starving the rest. Read [Tunnel Multiplexing Protocol](#tunnel-multiplexing-protocol) alongside.
3. `pkg/proto/messages.go` — the control messages (register, auth, heartbeat) that ride on stream 1. Read [Control Protocol](#control-protocol) alongside.
4. `pkg/server/server.go` (composition root) → `pkg/server/proxy_service.go` (`ServeHTTP` is where a public request meets a tunnel stream).
5. `pkg/client/relay_client.go` — the mirror image on the client: dial, authenticate, register, accept streams, reconnect.

Useful companion commands: `go test -run TestMux ./pkg/tunnel/...`, `go test -run TestHandler ./pkg/server/...`.

### 1 day — P2P, HA, and the security layer

6. `pkg/p2p/nat.go` → `hole_punch.go` → `stream.go` → `crypto.go` — NAT discovery, hole punching, the custom reliable-UDP ARQ, and end-to-end encryption. Read [P2P Direct Connection](#p2p-direct-connection) alongside; the ARQ section is the densest part of the codebase.
7. `pkg/client/p2p_session.go` and `pkg/server/p2p_broker.go` — how `wormhole connect` signaling flows through the relay before the direct link exists.
8. `pkg/server/state_redis.go` and `pkg/server/tunnel_registry.go` — cluster routing, TTL heartbeats, cross-node proxying. Read [HA / Multi-Node Control Plane](#ha--multi-node-control-plane) alongside.
9. `pkg/auth/` — HMAC tokens, OIDC validation, OAuth Device Flow, RBAC, audit logging.

Two sections then tie the design together: [Design Decisions & Trade-offs](#design-decisions--trade-offs) explains *why* the major components are built the way they are, and [Go Patterns Used in This Codebase](#go-patterns-used-in-this-codebase) catalogs the language techniques worth stealing.

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
| `Server` | `pkg/server/server.go` | Composition root; wires up `TunnelRegistry`/`ProxyService`/`P2PBroker` and owns the listener lifecycle (see [Server & Client Composition](#server--client-composition)) |
| `TunnelRegistry` | `pkg/server/tunnel_registry.go` | Client session lifecycle; local + cluster routing (subdomain/hostname/path); TCP port allocation; cluster heartbeat and state-store health |
| `ProxyService` | `pkg/server/proxy_service.go` | HTTP/WebSocket/TCP data-plane forwarding (`http.Handler`); concurrent-stream budget (global + per-client); cross-node proxy fallback. Replaces the former `HTTPHandler` |
| `P2PBroker` | `pkg/server/p2p_broker.go` | `wormhole connect` signaling: offer matching, NAT-compatibility checks, port-prediction candidates |
| `Router` | `pkg/server/router.go` | Host/Path routing table; subdomain, custom domains, path prefixes |
| `TLSManager` | `pkg/server/tls.go` | TLS termination; Let's Encrypt auto-certs and manual certificates |
| `AdminAPI` | `pkg/server/admin.go` | RESTful admin API including `/audit` and `/audit/export` |
| `TCPPortAllocator` | `pkg/server/tunnel_registry.go` | Allocates ports for TCP tunnels |
| `StateStore` | `pkg/server/state*.go` | Cluster shared state (subdomain/hostname/path routes + nodes); Memory or Redis backend |
| Cluster heartbeat | `pkg/server/tunnel_registry.go` | Periodic heartbeat + route TTL refresh, dead-node eviction, cross-node HTTP proxying, shared-secret verification |

### Client-Side Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| `Client` | `pkg/client/client.go` | Composition root; wires up `RelayClient`/`P2PSession`, aggregates `Stats`, owns the inspector and local control/inspector HTTP servers, and implements the `localForwarder`/`statsRecorder` callbacks both components use (see [Server & Client Composition](#server--client-composition)) |
| `RelayClient` | `pkg/client/relay_client.go` | Control-plane connection lifecycle: dial (+TLS), auth (with token refresh), single-/multi-tunnel registration, heartbeat, accepting inbound streams, and the reconnect loop |
| `P2PSession` | `pkg/client/p2p_session.go` | `wormhole connect` / P2P hole-punching lifecycle: NAT discovery, ECDH key exchange, hole punching, the multiplexed P2P transport, and the connect-mode local listener |
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

## Design Decisions & Trade-offs

This section records the rationale behind the major build-vs-buy and design choices, so readers can evaluate them rather than take them as given.

### Custom multiplexer instead of yamux / QUIC

The tunnel mux (`pkg/tunnel`) is written from scratch rather than using `hashicorp/yamux` or a QUIC library.

- **Why**: full control over the frame format lets the control channel (stream 1), protocol-version negotiation, and capability exchange live inside the same connection without adapter layers; the Inspector can observe stream boundaries natively; and the frame codec doubles as the P2P framing layer. QUIC would bring streams and flow control for free, but adds a large dependency, UDP-only transport (a problem for restrictive networks where TCP:443 is the whole point of a relay), and far less pedagogical value.
- **Cost**: the flow-control and keep-alive logic must be maintained and tested here (which is why `pkg/tunnel` has the highest test coverage in the repo, >90%).
- **Design mirror**: the API deliberately mirrors `net.Listener`/`net.Conn` (`mux.Accept()`, `stream.Read/Write/Close`), so code that consumes streams doesn't know it isn't talking to a plain TCP connection.

### Custom reliable UDP instead of KCP / QUIC for P2P

The P2P data plane (`pkg/p2p/stream.go`) implements its own ARQ: sliding window, RFC 6298 RTO estimation (SRTT/RTTVAR + Karn's algorithm), fast retransmit, and ACK-withholding for backpressure.

- **Why**: hole-punched UDP paths need a session that starts from a simultaneous-open handshake and layers end-to-end encryption (X25519 + AES-256-GCM) directly above the datagrams. KCP optimizes for latency at the cost of bandwidth (aggressive retransmission), which is the wrong trade-off for bulk tunnel traffic. QUIC again would work but hides exactly the mechanisms this project sets out to demonstrate.
- **Cost**: no congestion control beyond the ARQ window; a well-tested library would perform better on lossy long-fat networks.

### Protobuf with a JSON fallback

Control messages are encoded as Protobuf, but every decoder first tries Protobuf and falls back to JSON (`pkg/proto/messages.go`).

- **Why**: the project started with JSON; the Protobuf migration preserved wire compatibility with older clients during rollout. The dual decode also makes hand-testing with scripts easy.
- **Guard rails**: length-prefixed messages with a hard `maxControlMessageSize`, and empty/unknown payloads are rejected rather than silently zero-valued.

### Redis as the only distributed state store

HA mode (`pkg/server/state_redis.go`) uses Redis with TTL-refreshed route keys; there is no etcd/consensus option.

- **Why**: routes are soft state — every entry is re-announced by the owning node's heartbeat, so the store only needs fast lookups + TTL expiry, not consensus. Losing Redis degrades to single-node behavior instead of taking the data plane down.
- **Trade-off**: no linearizable registration (see the [HA chapter](#ha--multi-node-control-plane) for the conflict-handling rules), and Redis itself becomes the availability bottleneck for *new* cross-node routes.

### Everything else: boring on purpose

CLI is Cobra, logging is zerolog, tests use testify + miniredis, the web UI is embedded with `go:embed`. These are deliberately mainstream choices so the interesting code stays in the protocol layers.

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

### Control/Data Frame Prioritization

`Mux` queues outgoing frames on two channels instead of one: `ctrlCh` for `WINDOW_UPDATE`/`PING`/`PONG`/`HANDSHAKE`/`ERROR`, and `sendCh` for `DATA` and `CLOSE`. `sendLoop` always drains `ctrlCh` first. This matters because `WINDOW_UPDATE`/`PONG` are what unblock a stalled peer: on a connection saturated with data in both directions, `recvLoop` answers a `PING` by calling `sendPong` synchronously — if that send shared a queue with a deep backlog of `DATA` frames, it would block, `recvLoop` would stop draining the socket, and TCP backpressure would stall the peer's writes the same way, which is a classic single-queue mux deadlock. `CLOSE` deliberately stays on `sendCh` with `DATA` rather than joining the fast lane: it marks the end of a stream's data, so it must never be delivered ahead of that same stream's own still-queued bytes — jumping the queue would let the peer see EOF before all data arrived.

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

1. **Server side** (`proxy_service.go: forwardHTTP`):
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

4. **Multi-tunnel dispatch** (`proxy_service.go: resolveTunnelID` / `client.go: resolveLocalAddr`):
   - Step 1 (`Route(Host)`) only resolves the request down to a `ClientSession` — a single client connection may have **multiple** registered tunnels (multi-tunnel YAML config), each with its own local backend.
   - The server's `resolveTunnelID(client, host, path)` disambiguates which of the client's tunnels the request is actually for, matching in priority order: custom hostname → per-tunnel subdomain → longest path-prefix. The result populates `StreamRequest.TunnelID`.
   - The client's `resolveLocalAddr(tunnelID)` looks up that `TunnelID` in its `activeTunnels` map to find the tunnel-specific `LocalHost`/`LocalPort`, falling back to the top-level client config only when `TunnelID` is empty or unrecognized (single-tunnel backward compatibility).
   - This ensures that in multi-tunnel mode, traffic for each subdomain/hostname/path is forwarded to its own configured local port instead of all traffic collapsing onto the first-registered tunnel.

### WebSocket Proxy

WebSocket upgrade requests are handled specially (`proxy_service.go: handleWebSocket`):

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

`captureHeaders()` redacts a fixed set of sensitive header names (`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, etc., matched case-insensitively) to a constant placeholder on both request and response capture, so a token or session cookie never lands in a stored record or gets pushed to the inspector UI.

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

## P2P Direct Connection

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

The following components together provide NAT discovery, hole punching, and the reliable transport built on top of it:

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

> **Note on scope:** P2P only ever carries traffic between two `wormhole` processes that can both run the hole-punch protocol — i.e. `wormhole client` ↔ `wormhole connect`. A public visitor hitting your tunnel's hostname (a browser, curl, mobile app, etc.) is not running Wormhole's P2P protocol and physically cannot be hole-punched, so that traffic always goes through the Server relay; P2P for that path is not a gap, it's a hard physical constraint. `wormhole connect` (below) is what makes P2P carry real traffic in the one scenario where it's physically possible.

### Reliable UDP Transport Layer

Production P2P data transfer is carried by `UDPMux` + `UDPStream` (`pkg/p2p/mux.go`, `pkg/p2p/stream.go`) — a custom ARQ-based reliable, ordered, multiplexed stream layer over a single UDP socket pair.

**Adaptive retransmission (RFC 6298):** instead of a fixed retransmit timeout, `UDPStream` maintains per-stream SRTT/RTTVAR estimates (`updateRTO`, gains α=1/8, β=1/4, `RTO = SRTT + 4×RTTVAR`, clamped to `[100ms, 10s]`) sampled from ACKs of segments that were **not** retransmitted (Karn's algorithm — a retransmitted segment's ACK is ambiguous about which transmission it's acking, so it's excluded from the sample to avoid skewing the estimate). Each in-flight segment additionally backs off its *own* retransmit timer exponentially (doubling per attempt, capped at 32× the base RTO) rather than sharing one global timer, so a single lossy segment doesn't inflate the timeout applied to every other segment on the stream. This lets the stream retransmit aggressively on a clean low-latency link and back off gracefully on a lossy/high-RTT one, instead of picking one fixed value that's wrong for most conditions.

**Reduced copies on the encrypted send path:** `SessionCipher.EncryptInto` encrypts directly into the pre-sized outbound frame buffer instead of encrypting into a scratch buffer and then copying into the frame; the receive path (`handleData`/`deliverLocked`) doesn't re-copy a payload that `decryptPayload` already returned as an independently-owned buffer.

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

### `wormhole connect`: Client-to-Client Direct Data Plane

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
│  3. Both sides STUN + hole-punch (the same primitives      │
│     described above); on success both have a UDPMux over a │
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

Server-side, `TunnelRegistry.FindPeerBySubdomain` (in `pkg/server/tunnel_registry.go`) resolves `target_subdomain` to both the owning `ClientSession` and the specific `TunnelInfo.ID` serving it (a peer may expose more than one tunnel), distinguishing "no target requested" (a normal `wormhole client` registering its own P2P reachability, silently ignored), "target not found", "target is self", and "target has no usable P2P/NAT info" as distinct `P2POfferResponse.Error` reasons.

This is deliberately **not** how the normal public-visitor tunnel path works — see the scope note above.

**P2P signaling is same-node only under HA.** `FindPeerBySubdomain` only has a `ClientSession` (holding the peer's NAT type, address, and ECDH key) for clients connected to *this* node — that state is never replicated to `StateStore`, which only tracks routing metadata (`NodeID`/`NodeAddr`), not P2P reachability info. If the local lookup misses, `FindPeerBySubdomain` checks `StateStore` as a fallback purely to give an honest answer: finding the subdomain owned by a *different* node returns a distinct `errP2PTargetOnOtherNode` ("target is connected to a different cluster node ... falling back to relay") instead of the misleading "not found" a genuinely-absent target would get. Either way `wormhole connect` cannot reach that peer directly — the offer fails and, unlike `wormhole client`, there's no relay fallback (see the degradation strategy above). Implementing real cross-node P2P signaling would mean replicating each session's NAT/address/key material through `StateStore` and proxying the offer/result exchange to the owning node; given `wormhole connect` already has no relay fallback of its own, this was judged not worth the added complexity — clients that need P2P reliably under a multi-node deployment should pin both peers to the same node (e.g. via a consistent-hashing load balancer) rather than relying on cross-node signaling.

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
- The tunnel *control* listener (where auth tokens travel) has its own independent TLS setting (`--tunnel-tls`, via `TLSManager.TunnelTLSConfig()`/`WrapTunnelListenerStrict()`) rather than inheriting the HTTP data-plane listener's TLS config — it defaults to `--tls`'s value, and additionally defaults to `true` whenever `--require-auth` is combined with a real `--domain`, since requiring authentication while leaving the channel that carries those tokens unencrypted would defeat the purpose. A TLS *config* error (e.g. bad cert paths) fails server startup outright when auth is required, instead of silently falling back to plaintext

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
| **Anti-Replay** | `SessionCipher` tracks the highest counter seen plus a 1024-slot sliding-window bitmap; `Decrypt` rejects a counter that's already been seen or has fallen outside the window before attempting decryption. Out-of-order delivery within the window (normal on UDP) is still accepted. A forged packet (bad GCM tag) never marks its counter as seen, so it can't be used to burn a legitimate sender's slot |
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
- **Fail-closed revocation checks**: if the backing store can't be consulted during validation (e.g. Redis/SQLite outage), `validatePayload` returns `ErrRevocationCheckUnavailable` and the token is rejected rather than accepted with an unverifiable revocation status — a store hiccup can never resurrect an already-revoked credential. A genuinely absent team record (`ErrTeamNotFound`) is still treated as "no revocation applies" and validates normally
- **No auth-state leakage**: the handshake returns a generic `authentication failed` to the client regardless of the underlying reason (expired / revoked / malformed / store-unavailable). The specific reason is logged server-side only, so an attacker can't probe a token's exact state

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

The `OIDCValidator` caches JWKS keys with a 1-hour TTL and auto-refreshes on unknown `kid`. Supported algorithms: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`; `verifyJWTSignature` has a dedicated `case "none", ""` that rejects an unsigned token immediately, closing off the classic signature-bypass attack. Issuer comparison (`normalizeIssuer`) strips trailing slashes before matching, so `https://issuer.example.com` and `https://issuer.example.com/` are treated as equal; `nbf` (not-before) is validated with the same 60s clock-skew leeway already applied to `exp`.

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
- `--audit-retention-days` (default 90) bounds log growth on a long-running server via a periodic `AuditStore.DeleteOlderThan(cutoff)` sweep
- A failed `AuditStore.Store()` call (e.g. a full disk or locked SQLite file) increments an `atomic.Uint64` counter instead of silently dropping the event; `GET /stats` surfaces it as `audit_store_errors` so persistence failures are monitorable rather than invisible
- `/metrics` requires the same admin authentication as the rest of the Admin API — it's never exposed unauthenticated
- `Server.Start()` schedules a background sweep of the revoked-token blacklist every 10 minutes so it doesn't grow unbounded

### Input Validation

- HTML escaping on Host header routing (XSS prevention)
- Client-supplied subdomains are validated as DNS labels (`isValidSubdomainLabel`: 1–63 chars, letters/digits/hyphen only, no leading/trailing hyphen) at both the auth handshake and dynamic tunnel registration, before the value reaches the router, the cluster state store, or any log line — rejecting dots, path separators, `..`, and control-character injection
- Path prefix normalization (leading/trailing `/`)

### Subdomain Reservation Semantics

`RegisterRoute` (both the in-memory router and the Redis-backed cluster store) is an atomic reservation with four defined outcomes: free → reserved; same client re-registering → idempotent TTL refresh; a *live* different owner → `ErrSubdomainConflict` (connection rejected); a *stale* owner (its route entry already expired) → reclaimed. The Redis implementation uses `SetArgs{Mode: "NX"}`. A subdomain conflict — local or cluster-wide — rejects and closes the connection outright rather than merely logging it and letting the client believe (via `AuthResponse`) that it owns a subdomain it doesn't actually control; the client's own reconnect logic retries afterward.

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

`RouteEntry` carries `{RouteID, ClientID, TeamName, Subdomain, Hostname, PathPrefix, NodeID, NodeAddr, RegisteredAt}` — a single client can hold several `RouteEntry`s at once (one tunnel's subdomain, another's custom hostname, a third's path prefix), each independently addressable by `RouteID` for targeted unregistration. `NodeInfo` carries `{NodeID, NodeAddr, LastHeartbeat}`.

`RegisterRoute` must atomically reserve the entry's routing key (subdomain, hostname, or path — whichever is set): free → reserve; same `ClientID` re-registering → idempotent TTL refresh; held by a different, still-live client → return `ErrSubdomainConflict`; held by a stale (expired) entry → reclaim. `MemoryStateStore` implements these four-way semantics under its own lock via a shared `conflictsWith` helper. `RedisStateStore` runs the entire reservation — conflict check, index-key `SET`, route-record `SET`, and the client's route-ID-set `SADD` — as a single `EVAL`'d Lua script (`registerRouteScript`) rather than a `SETNX` call followed by a separate pipelined `SET`. The two-step version had a real (if narrow) window between those two round trips where the index key pointed at a `routeID` with no backing record yet — a lookup landing in that window would see the route as "not found" despite the reservation having technically succeeded, and a crash between the two calls could leave that broken half-state around until the client's own retry (see below) papered over it. One `EVAL` closes the window entirely: any concurrent lookup now always observes either a fully-formed reservation or none at all.

### Availability vs. Consistency Trade-off on Route Registration

`TunnelRegistry.registerClusterRoute` explicitly favors availability over strict consistency when the state store is unreachable or otherwise erroring for a reason *other than* a genuine `ErrSubdomainConflict`: it still returns success (the connection is not rejected) rather than fail-closed. Rejecting every new connection whenever Redis hiccups would take down the whole cluster's ability to accept traffic over what's often a transient blip — worse than the alternative below.

The trade-off only works because the failure isn't silent. A route that failed to register is still appended to `client.clusterRoutes` (previously it was dropped, which meant the client stayed permanently invisible to the rest of the cluster until it reconnected — even after Redis recovered). `refreshClusterRoutes`, driven by the existing 30s heartbeat tick, retries every entry in `clusterRoutes` unconditionally, so a route that failed at registration time gets folded into the same retry loop that ordinarily just refreshes TTLs — no separate "pending registration" queue or retry policy needed. The net effect: a transient state-store outage self-heals within one heartbeat interval of Redis recovering, with zero action required from the client.

This does open a narrow split-brain window: while this node believes it owns a route (it's sitting in `clusterRoutes`, unsynced), a *different* node could legitimately claim the same key for real. The next `refreshClusterRoutes` retry surfaces this the moment it happens — `RegisterRoute` returning `ErrSubdomainConflict` for an entry the node thought it already owned means the cluster's shared state now disagrees with this node's belief. That's logged at `Error` (not the routine `Warn` used for an ordinary sync failure) and counted in `ClusterRouteConflictsTotal`, since there is no automatic remediation — the other node's registration wins by construction (this node's `RegisterRoute` call simply fails), but this node will keep serving local traffic for the stale route until an operator notices and intervenes (e.g. by disconnecting the affected client). `ClusterRouteSyncFailuresTotal` separately counts the more common, self-resolving case — any non-conflict registration/refresh failure, whether or not it ever turns into a conflict. Operators should alert on `ClusterRouteConflictsTotal` being non-zero; `ClusterRouteSyncFailuresTotal` moving is expected during a Redis blip and only interesting as a sustained non-zero rate.

### Multi-Tenancy: Team-Scoped Route Isolation

Two independent mechanisms keep one team's routes from being disrupted by another team sharing the same cluster:

- **Stale-owner reclaim is team-scoped.** A subdomain/hostname/path left behind by a session that died without a clean disconnect (network blip, crash) is reclaimable once its `Mux.IsClosed()` — see "Stale ownership reclaim" under [Cross-Node HTTP Routing](#cross-node-http-routing) below — but `isStaleOwner` (`pkg/server/router.go`) additionally requires the reclaiming client to share the stale owner's `TeamName` (or either side to have no team at all, e.g. auth disabled or a single-tenant deployment). Without this, a client from team B racing to claim the exact subdomain team A's client just dropped — during the brief window before team A's own reconnect lands — could transiently steal a route that legitimately belongs to team A. `TeamName` is threaded from `ClientSession` into every `RouteEntry` at registration time specifically so this check has something to compare cluster-wide, not just against this node's local `Router`.
- **Reserved subdomains keep operator-facing names out of the team pool.** `Config.ReservedSubdomains` (default via `DefaultReservedSubdomains()`: `admin`/`api`/`www`/`status`/`metrics`/`health`; override with `--reserved-subdomains`, or `[]` to disable) blocks any non-admin-role client from claiming one of these labels, so whichever team's client happens to register first can't accidentally (or deliberately) squat on a name the operator wants for their own infrastructure. `isReservedSubdomain` (`pkg/server/server.go`) is enforced at both auth time (the connection-level subdomain) and per-tunnel registration time (`handleRegister`), is a case-insensitive match, and is a no-op when `RequireAuth` is off (there's no role to check, and no teams to isolate between). `auth.RoleAdmin` tokens always bypass it.

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

`ListRoutes`/`GetNodes` (and the auth store's `ListTeams`/`CountRevokedTokens`) use `SCAN` cursors rather than `KEYS`, so large key spaces don't block the shared Redis instance.

### Route TTL Refresh

A route that were only ever registered once would silently expire out of Redis after 5 minutes even if the client is still connected. To prevent that, `ClientSession.clusterRoutes` tracks every `RouteEntry` a session has registered cluster-wide (its primary subdomain, plus any extra subdomains/hostnames/path prefixes from `RegisterTunnel`), and `TunnelRegistry.StartHeartbeat`'s 30s tick calls `refreshClusterRoutes` to re-run `RegisterRoute` for all of them — a `pipeline`-friendly batch that's functionally an `EXPIRE`/TTL-refresh rather than a fresh reservation, since the entry already belongs to this client.

### Cluster Heartbeat (`pkg/server/tunnel_registry.go`)

Cluster bookkeeping (heartbeat, routing, port allocation) lives entirely in `TunnelRegistry`, one of the three components `Server` composes (see [Component Architecture](#component-architecture)); it never touches `Server`'s fields directly.

```
TunnelRegistry.StartHeartbeat(ctx)
  ├── tick every 30s → NodeHeartbeat(NodeInfo{NodeID, NodeAddr})
  │                     sendHeartbeat tracks StateStore reachability → tunnelRegistry.stateStoreHealthy
  ├── tick every 30s → refreshClusterRoutes(client) for every connected session
  └── tick every 60s → EvictDeadNodes(90s threshold)
                           └── MemoryStateStore: scan + delete dead nodes + owned routes
                               RedisStateStore: no-op — Redis TTL is the single source of truth for eviction
```

### Cross-Node HTTP Routing

```
ProxyService.ServeHTTP(r)
  ├── verifyClusterSecret(r) → reject if --cluster-secret set and header present-but-wrong;
  │                            always strip the header on accept (external traffic has none)
  ├── router.Route(host, path) → local ClientSession?
  │     └── Yes → forwardHTTP / handleWebSocket (normal path)
  └── No → registry.ResolveRemote(host, path)   [hostname → longest path-prefix → subdomain]
              └── found remote RouteEntry?
                    ├── registry.IsLocalNode? → continue to 404 (stale entry)
                    └── No  → proxyToNode(route.NodeAddr, w, r)
                                  └── attach X-Wormhole-Cluster-Secret header
                                  └── validateClusterNodeAddr rejects anything but a bare host:port
                                  └── httputil.ReverseProxy → target node
```

Hostname and path-prefix routes are indexed into Redis exactly like subdomains, so a tunnel registered with `--hostname`/`--path` on node A is reachable through node B, not just its own subdomain.

**Node identity**: `applyClusterNodeIDDefault` defaults `Config.ClusterNodeID` to `os.Hostname()` whenever a cluster backend is configured but no explicit ID was given, so two nodes never accidentally share an empty NodeID.

**Stale ownership reclaim**: `router.go`'s `RegisterSubdomain`/`RegisterHostname`/`RegisterPath` check `isStaleOwner` (the existing owner's `Mux.IsClosed()`, and — see [Multi-Tenancy: Team-Scoped Route Isolation](#multi-tenancy-team-scoped-route-isolation) — the same `TeamName`) before returning a conflict; `TunnelRegistry.registerClientRoute` mirrors this on the cluster side, proactively unregistering the dead session's `StateStore` entries. A client that reconnects after a network blip gets its subdomain/hostname/path back immediately instead of a transient conflict error, and a different team's client cannot race in and take it instead.

**Health surfacing**: `GET /health` includes `cluster: {node_id, state_store_healthy}` (sourced from `TunnelRegistry.StateStoreHealth()`); if the state store becomes unreachable, overall `status` flips from `"ok"` to `"degraded"` so monitoring picks it up without needing a separate Redis probe.

### Inter-Node Authentication

`--cluster-secret` is a shared secret across all nodes in a cluster. `proxyToNode` (`pkg/server/proxy_service.go`) attaches it as `X-Wormhole-Cluster-Secret` on every proxied request via its own outbound clone; `verifyClusterSecret` (called first in `ProxyService.ServeHTTP`) rejects requests where the header is *present but doesn't match*, and **always strips the header on every accepting path** — whether the feature is on or off, and whether the request is a genuine peer hop or ordinary external traffic — so the secret can never be relayed into the tunnel client's local service (and its logs). A request that simply omits the header is ordinary external traffic and passes through normally. Starting a Redis-backed cluster without a secret is allowed but logs a loud warning, since inter-node proxied requests would then be unauthenticated; `--cluster-node-addr` is *required* in that mode (startup fails fast without it, since peers use it to reach this node).

Before building the outbound proxy request, `proxyToNode` also runs the target through `validateClusterNodeAddr`, which rejects anything that isn't a clean `host:port` pair. This is defense in depth against a corrupted or tampered `StateStore` entry smuggling a scheme, userinfo, path, or query component into the proxy target — the request is always rebuilt from validated `host`/`port` components (`net.JoinHostPort`), never from the raw string.

### Shared Auth/Revocation State

`--persistence redis` (`pkg/auth/store_redis.go`, `auth.RedisStore`) stores teams under `wormhole:auth:team:<name>` and revoked tokens under `wormhole:auth:revoked:<tokenID>` with a Redis TTL matching the token's remaining lifetime — a token revoked on node A is invisible on node B the moment the write completes, with no propagation delay and no periodic sweep needed (`CleanupExpiredRevocations` is a no-op on this backend, since TTL already deletes the key). `--auth-redis-addr/-password/-db` fall back to `--cluster-redis-*` when unset, so a single Redis instance can back both cluster routing state and auth/revocation state with one flag.

### TCP Tunnels Under HA

TCP tunnels are **node-local only**: a TCP tunnel's listener lives on whichever node the client happens to be connected to, and there is no cross-node TCP proxy (unlike the HTTP/WebSocket path, `StateStore` doesn't track TCP port ownership across nodes). Operators who need HA for TCP tunnels must put a TCP-aware load balancer (e.g. HAProxy in `mode tcp`, or an L4 DNS/anycast scheme) in front of the individual node addresses/ports themselves; Wormhole does not attempt to abstract this away.

### Connection Limits

- `MaxClients` limits concurrent online clients
- TCP port allocation range restriction (default 10000-20000)
- Per-IP connection tracking for rate limiting

---

## Server & Client Composition

Both `Server` and `Client` are composition roots: each constructs a small set of focused, independently testable components and wires them together, rather than owning every responsibility directly on one struct.

### Server

`NewServer` constructs three components and hands each only the dependencies it needs:

```
NewServer(config)
  ├── registry := newTunnelRegistry(config)                                    // TunnelRegistry
  ├── metrics, auditLogger, authenticator, rateLimiter, tlsManager, adminAPI
  ├── proxy  := newProxyService(registry.router, registry, config, metrics,
  │                             &stats, server.serverCtx)                       // ProxyService
  └── broker := newP2PBroker(registry, metrics, auditLogger, server.serverCtx)  // P2PBroker
```

| Component | File | Owns |
|-----------|------|------|
| `TunnelRegistry` | `pkg/server/tunnel_registry.go` | `*Router`, the `clients` map + its lock, `TCPPortAllocator`, `StateStore` + its health flag, and the cluster-heartbeat goroutine |
| `ProxyService` | `pkg/server/proxy_service.go` | HTTP/WebSocket/TCP forwarding (implements `http.Handler`) and the concurrent-stream budget |
| `P2PBroker` | `pkg/server/p2p_broker.go` | `wormhole connect` offer/result handling, NAT-compatibility checks, port-prediction candidate generation |

`ProxyService` and `P2PBroker` depend on `TunnelRegistry` through a small `TunnelRegistry` interface, not the concrete struct — it only exposes what a forwarding/signaling caller actually needs (`ResolveLocal`, `ResolveRemote`, `IsLocalNode`, `FindPeerBySubdomain`, `AllocatePort`, ...), not the registry's full internal surface. `admin.go`'s `/health`, `/stats`, `/clients`, and `/tunnels` handlers go through this same interface (`registry.StateStoreHealth()`, `registry.AllocatedPorts()`, `registry.ActiveRoutes()`, `registry.Snapshot()`) rather than reaching into `Server`'s internals — the admin API's read path doesn't need to know anything about the registry's internal locking scheme.

### Client

`NewClient` constructs two components and wires them together with a handful of callbacks:

```
NewClient(config)
  ├── p2p   := newP2PSession(config, manager, forwarder, stats, closeCh)   // P2PSession
  └── relay := newRelayClient(config, forwarder, stats, p2p.Manager(),
                               closeCh, &closeWg)                          // RelayClient
       relay.setAfterConnect(p2p.MaybeSendOffer)                          // wire callbacks
       relay.setNotificationHandler(p2p.HandleNotification)
```

| Component | File | Owns |
|-----------|------|------|
| `RelayClient` | `pkg/client/relay_client.go` | The control-plane `net.Conn`/`tunnel.Mux`, auth + token-refresh, single-/multi-tunnel registration and the `activeTunnels` map, the heartbeat goroutine, and the reconnect loop (`Run`) |
| `P2PSession` | `pkg/client/p2p_session.go` | The P2P `net.PacketConn`/`*p2p.UDPMux`, ECDH `KeyPair`/`SessionCipher`, the hole-punch attempt (`attemptP2P`), and the `wormhole connect` local listener (`startConnectListener`/`proxyConnectConn`) |

Both components depend on `Client` only through two small consumer-side interfaces it implements — `localForwarder` (hand a stream off to be proxied to the local service) and `statsRecorder` (report bytes/connections into the aggregate `Stats`) — so neither `RelayClient` nor `P2PSession` needs to know `Client` exists as a concrete type. `P2PSession` talks back to `RelayClient` only through the minimal `RelayChannel` interface (send a P2P result over the control connection), not the full `RelayClient` surface. `Client` retains its own mutex only for state it still owns directly (the local control/inspector HTTP servers); connection state lives behind `RelayClient`'s own lock, and P2P session state behind `P2PSession`'s.

**Session replacement and singleflight.** A P2P offer/notification can legitimately fire more than once for the same peer (retries, a racing offer from each side), and each successful hole-punch replaces `P2PSession`'s live `conn`/`udpMux`/`sessionCloseCh`. Two things guard this under `P2PSession.mu`: an `attempting atomic.Bool` makes `attemptP2P` a singleflight — a second concurrent attempt observes the flag already set and returns immediately instead of racing the first — and a `sessionGen` counter tags every installed session. `installSession` always tears down whatever session it's replacing (closing the old `conn`/`udpMux`, signaling the old accept loop to exit) before installing the new one, so a superseded session never lingers as an orphaned goroutine + UDP socket. Because `acceptP2PStreams` runs in its own goroutine per session, an error on a *stale* session's accept loop must not be allowed to tear down whatever newer session has since replaced it — it captures the `sessionGen` it was started with and compares against the current generation before acting, via `fallbackFromStaleSession`.

---

## Reliability & Protocol Safeguards

### Graceful Shutdown

`Server` holds the `*http.Server` values it constructs for the HTTP and admin listeners. `Server.Shutdown()` calls `http.Server.Shutdown(ctx)` on each with a bounded timeout (`ShutdownTimeout`, default 10s) before closing the tunnel listener, so in-flight HTTP/admin requests get a chance to finish instead of having their connections cut on `SIGTERM`.

`Start(ctx)` also derives a root context (`s.rootCtx`/`s.rootCancel`) that `Shutdown()` cancels as its first step, before draining the HTTP/admin servers. Several operations deep in the handler tree — the auth handshake's stream-accept, TCP port allocation, opening a P2P peer-notification stream, opening a TCP-tunnel stream — take this root context instead of `context.Background()`, so a shutdown in progress unblocks them immediately rather than waiting out their own fixed timeout (e.g. `AuthTimeout`). `tunnel.Stream` exposes `ReadContext`/`WriteContext` variants for the same reason: a caller holding a cancelable context can interrupt an in-progress blocking read/write. The plain `Read`/`Write` methods still delegate to them with `context.Background()`, so the data-plane hot path (`io.CopyBuffer` and friends) pays no extra cost — no watcher goroutine is spawned when the context can never fire. Every control-plane RPC on both server and client (auth, tunnel registration, heartbeat ping, stats, tunnel close, P2P offer/result) uses the context-aware variants, so `Client.Close()` or a caller-supplied deadline can interrupt an in-flight control RPC the same way.

### Bidirectional Proxy Half-Close

The WebSocket and TCP tunnel proxy paths pump two directions concurrently (client→local and local→client). The first direction to hit EOF/error explicitly closes (or `CloseWrite`s) the other side's connection, so both directions unwind together regardless of which one errors first — a mostly one-way conversation (e.g. a long-poll or an idle keep-alive) doesn't stall teardown until the other side's own read timeout elapses.

### Concurrent Stream Limits

Two server flags cap how many data-plane streams (HTTP/WebSocket/TCP proxy streams, not control-channel streams) can be open at once: `--max-concurrent-streams` (default 10000, a global process-wide cap) and `--max-streams-per-client` (default 500, scoped to a single client connection so one busy tenant can't starve everyone else's share). Both are non-blocking `atomic.Int64` counters — a stream request over the limit is rejected outright rather than queued, so a traffic spike degrades as predictable fast rejections instead of unboundedly growing goroutines/memory.

The server's control plane and the client have matching limits of their own, since either side can be handed an unbounded number of inbound streams by its peer: `Server.Config.MaxControlStreamsPerClient` (default 128, `--max-control-streams-per-client`) bounds how many control-channel streams (register/ping/stats/close/P2P-offer, not data-plane traffic) one client connection may have in flight; `client.Config.MaxConcurrentStreams` (default 1000) bounds how many inbound streams `RelayClient.acceptStreams` and `P2PSession.acceptP2PStreams` will service concurrently — relevant because a compromised or misbehaving server could otherwise open unbounded streams against the client. All four limits share the same lock-free pattern: `tryIncrementBounded32`/`64` does a CAS loop that increments a counter only while it's below the limit, and a deferred decrement on stream completion releases the slot.

### Control-Frame Validation

`DecodeControlMessage` rejects all-zero/garbage input that happens to decode to `MessageType_MESSAGE_TYPE_UNKNOWN` with every oneof field unset, since that shape can only be malformed or corrupted input, never a legitimate message. The check is narrow by design: a message with `Type == UNKNOWN` that *does* carry a recognized payload (session or P2P) is still accepted, preserving forward compatibility for message types a newer client might send to an older server.

### Version Gating & Capability Advertisement

`pkg/version` implements a minimal semver parser/comparator (`ParseSemver`, `Compare`) — deliberately not a full semver library, since Wormhole only needs `MAJOR.MINOR.PATCH` comparison. The server's `--min-client-version` flag rejects `AuthRequest`s from clients reporting an older version, with a clear auth-failure reason; clients built from a non-tagged source (e.g. `dev`, empty string) fail semver parsing and are deliberately *never* rejected, since version gating is an opt-in operator control rather than a hard requirement for running unreleased builds.

`AuthResponse.Capabilities` is populated from `Server.capabilities()`, which derives the list (`p2p`, `multi-tunnel`, `cluster`, `audit`, ...) from the server's actual runtime configuration. The client stores the server's advertised capabilities and gates optional behavior on them — e.g. it skips sending a P2P offer entirely if the server didn't advertise `"p2p"`, instead of always attempting one and relying on the server to silently ignore it. An absent/empty capability list (e.g. from an older server that predates this field) is treated as "unknown, assume supported" for backward compatibility.

---

## Hot-Path Performance

The tunnel multiplexer's data-send path and every bidirectional proxy loop reuse pooled scratch buffers instead of allocating a fresh one per write/connection, which meaningfully reduces per-operation allocation and GC pressure under load:

- `Mux` owns a `dataBufPool` (`sync.Pool`) that `sendData` borrows from instead of doing `make([]byte, len(data)); copy(...)` on every `Stream.Write`; the buffer is returned once the frame has been written to the connection.
- `copyWithPooledBuffer(dst, src)` is a drop-in `io.Copy` replacement (via `io.CopyBuffer`) backed by a package-level pool (`pkg/server` and `pkg/client` each keep their own), used by every forwarding loop: the server's HTTP response body copy, WebSocket proxy, and TCP tunnel proxy, and the client's relay-mode `dialAndProxy` and `wormhole connect`'s `proxyConnectConn`.

`forwardHTTPWithInspect` bounds its request/response body reads with `io.LimitReader(body, MaxBodySize+1)` — enabling `--inspector` never buffers an unbounded body in memory regardless of upload/download size. `Inspector.MaxBodySize()` exposes the configured limit so callers outside the `inspector` package can size their own reads consistently with what `Capture` stores. This only applies to the inspector code path; relay/P2P forwarding without inspection remains fully unbounded, since the inspector is a debugging aid rather than something enabled for large-payload production traffic.

---

## Go Patterns Used in This Codebase

For readers using Wormhole to study Go, these are the recurring techniques and where to find a canonical example of each.

### Composition root + narrow consumer-side interfaces

`Server` and `Client` are composition roots: they construct their components and wire them together, but delegate all real work (see [Server & Client Composition](#server--client-composition)). The interfaces between components are defined on the *consumer* side and kept minimal — `P2PSession` sees `RelayClient` only as `RelayChannel` (one method group for sending signaling messages), and both client components see `Client` only as `localForwarder` + `statsRecorder`. This is the Go interface idiom ("accept interfaces, return structs") applied at the architecture level: components can be unit-tested with tiny fakes, and dependency direction is visible in the type system.

### One writer goroutine per connection

`tunnel.Mux` funnels all outbound frames through a single writer path guarded by `sendLock`, so frame writes are never interleaved mid-frame regardless of how many streams write concurrently. The same pattern appears in the P2P `UDPMux`. This is the standard Go answer to "many producers, one ordered sink" — serialize at the boundary instead of locking inside every producer.

### Lock granularity follows ownership

There is no global lock. Each component guards exactly the state it owns: `RelayClient.mu` for connection/tunnel state, `P2PSession.mu` for session state, `Stream.mu` for per-stream buffers, and the registry/router each have their own. Simple flags that are checked on hot paths (`connected`, P2P `mode`) use `sync/atomic` instead of mutexes. When reading the code, the reliable rule is: find the struct that owns the field, and its mutex is the one protecting it.

### `context.Context` for cancellation, but not on the data path

Control-plane RPCs (auth, register, heartbeat, P2P signaling) all take contexts and use `Stream.ReadContext`/`WriteContext`, so shutdown or a caller deadline interrupts them immediately. The data path (`io.CopyBuffer` loops) deliberately does *not* use context-aware reads — the plain `Read`/`Write` delegate with `context.Background()` and spawn no watcher goroutine, keeping the hot path allocation-free. Cancellation there is handled by closing the underlying stream instead. This split — contexts where responsiveness matters, connection-close where throughput matters — is worth internalizing.

### `sync.Pool` for hot-path buffers

`dataBufPool` in the mux and the `copyWithPooledBuffer` pools in `pkg/server`/`pkg/client` (see [Hot-Path Performance](#hot-path-performance)) show the standard pattern: pool the buffer, not the object graph; return it in a `defer`; never let a pooled buffer escape past the return.

### Channel-based lifecycle: `closeCh` + `sync.WaitGroup` + `sync.Once`

Long-lived goroutines (heartbeat loops, accept loops, TTL refreshers) follow the same shape everywhere: a `closeCh` channel closed exactly once (guarded by `sync.Once` or an atomic CAS) signals shutdown, `select` statements race work against `<-closeCh`, and a `WaitGroup` lets `Close()` block until every goroutine has actually exited. `Mux.CloseNotify()` extends the pattern across component boundaries — the client's reconnect loop just waits on the channel rather than polling connection health.

### Table-driven tests and behavior-level integration tests

Unit tests are table-driven where inputs enumerate well (frame codec, config validation). The more interesting pattern is the *mux-pair* test used throughout `pkg/client` and `pkg/server`: create two ends of a `net.Pipe`, wrap each in a real `tunnel.Mux`, and drive one side as a scripted fake peer. This tests actual wire behavior (framing, flow control, message ordering) without sockets, and it is the main reason refactors like the composition-root split could lean on the test suite to catch real bugs. See [Testing Strategy](#testing-strategy).

### Others worth noticing

- `go:embed` serves the entire Inspector web UI from the binary (`pkg/web`), keeping single-binary deployment.
- `crypto/subtle.ConstantTimeCompare` / `hmac.Equal` for every secret comparison — never `==` on credentials.
- Bounded atomic counters via CAS loops (`tryIncrementBounded`) implement limit-checked increments without locks.
- The custom errors follow `errors.Is`/`errors.As` conventions with sentinel values (`ErrSubdomainConflict`, `ErrTokenExpired`) wrapped with `%w`.

## Testing Strategy

The test suite (roughly 25k lines, exceeding production code) is layered; knowing which layer a test belongs to tells you how to write new ones.

| Layer | Where | Technique |
|-------|-------|-----------|
| Unit | `pkg/tunnel`, `pkg/proto`, `pkg/auth` | Table-driven tests on codecs, validation, token logic; benchmarks alongside |
| Component integration | `pkg/client/client_test.go`, `pkg/server/*_test.go` | Mux-pair over `net.Pipe`: a real mux on the side under test, a scripted fake peer on the other |
| Cluster integration | `pkg/server/cluster_test.go` | Two full server instances sharing a `miniredis`, real HTTP round-trips across nodes |
| P2P stress | `pkg/p2p/stress_test.go` | Loopback UDP with simulated packet loss, exercising the ARQ retransmission path |
| Race detection | CI | The entire suite runs under `go test -race` on every push |

Guidelines that keep the suite healthy:

- **Test behavior, not fields.** Prefer driving the public API and asserting on observable protocol effects (what frames the fake peer received) over reaching into unexported state.
- **Every bug fix lands with a regression test** at the lowest layer that can reproduce it.
- **Security-relevant code paths get explicit negative tests** — wrong HMAC, expired token, invalid cluster secret, oversized control message.

Run locally with `go test -race ./...`; per-package coverage with `go test -cover ./pkg/...`. Lint and security gates mirror CI: `golangci-lint run ./...` and `gosec -exclude=G115 -exclude-dir=web -exclude-dir=pkg/proto/pb ./...`.

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
