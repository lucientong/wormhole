// Package server implements the Wormhole server: it accepts client
// control connections, authenticates and registers tunnels, routes public
// HTTP/TCP traffic to the right client, and brokers `wormhole connect` P2P
// signaling — optionally coordinating all of that across an HA cluster of
// nodes sharing state in Redis.
//
// # Composition
//
// [Server] is a composition root for three independently-owned,
// independently-testable components, plus the cross-cutting concerns none
// of them individually own:
//
//   - [TunnelRegistry] (tunnel_registry.go) tracks which clients are
//     connected and which subdomain/hostname/path routes they own, backed
//     by a pluggable [StateStore] (in-memory for a single node, Redis for
//     HA — see "HA / Multi-Node" below).
//   - [ProxyService] (proxy_service.go) forwards public traffic — HTTP,
//     WebSocket, and TCP tunnels — from the router's incoming connections
//     to the owning [ClientSession]'s multiplexed stream.
//   - [P2PBroker] (p2p_broker.go) mediates `wormhole connect` signaling:
//     matching an offer from the connecting peer to the exposing peer's
//     registered presence and relaying ICE-like candidate/result messages,
//     without ever touching the resulting P2P data path.
//
// Server itself holds only what genuinely cuts across all three:
// connection lifecycle (accept/auth/register/heartbeat per client),
// rate-limiting and audit logging, Prometheus metrics, and graceful
// shutdown sequencing.
//
// # Request Lifecycle
//
// A client connection goes through Server.handleClient: TLS handshake (if
// enabled) → Server.authenticateClient (HMAC/OIDC/simple token via
// `pkg/auth`, rate-limit check) → Server.handleRegister (claims a
// subdomain/hostname atomically against the [StateStore], allocates a TCP
// port for TCP tunnels) → Server.handleClientStreams, a per-connection
// loop dispatching each new multiplexed stream to the right handler
// (register/ping/stats/close/P2P-offer on the control plane; proxied bytes
// on the data plane). Losing the connection triggers Server.removeClient,
// which releases routes back to the [StateStore] and notifies the audit
// log.
//
// # HA / Multi-Node
//
// With `--cluster-backend redis`, multiple [Server] instances share route
// state through a Redis-backed [StateStore] implementation instead of the
// default in-memory one. Each node re-registers (TTL-refreshes) its own
// routes on a heartbeat interval and proxies requests for routes owned by
// other nodes via `pkg/server/cluster.go`'s reverse-proxy path, so any node
// can accept traffic for any subdomain regardless of which node the owning
// client is actually connected to. TCP tunnels are the one exception —
// they stay node-local (see the architecture doc's HA section) since
// proxying raw TCP cross-node isn't implemented.
//
// # Admin & Observability
//
// [AdminAPI] (admin.go) exposes `/health`, `/stats`, `/clients`, team
// management, and audit query/export endpoints on a separate
// loopback-by-default listener. Prometheus metrics (metrics.go) and audit
// events (`pkg/auth`) are populated by the same request lifecycle described
// above, so operators can observe exactly what the proxy path is doing
// without instrumenting call sites twice.
package server
