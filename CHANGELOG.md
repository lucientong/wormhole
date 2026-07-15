# Changelog

All notable changes to Wormhole are documented here. See [README.md](README.md) for usage and [docs/architecture.md](docs/architecture.md) for the current system design.

**[中文版](CHANGELOG_zh.md)**

## v0.6.10

Security hardening: the cluster-peer secret header (`X-Wormhole-Cluster-Secret`) is now stripped from every request before it is forwarded into a tunnel client's local service, so the shared secret can no longer leak into a user's internal network or application logs. Token revocation checks now fail closed — a Redis/SQLite outage during validation rejects the token instead of silently accepting one whose revocation status can't be confirmed. Authentication failures return a generic "authentication failed" to the client (the specific reason is logged server-side only) so token state can't be enumerated. Client-supplied subdomains are validated as DNS labels before routing or storage, rejecting malformed values that could produce bogus routes or inject control characters into logs. Starting a Redis-backed cluster now fails fast if `--cluster-node-addr` is missing and warns loudly if no `--cluster-secret` is set (inter-node proxying would otherwise be unauthenticated).

## v0.6.9

Client-side refactor: the ~2,100-line `Client` is now a composition root over `RelayClient` (control-plane connection, auth with token refresh, single/multi-tunnel registration, heartbeat, reconnect loop) and `P2PSession` (`wormhole connect`'s NAT discovery, ECDH key exchange, hole punching, and P2P data plane). Both depend on `Client` only through two small interfaces (`localForwarder`, `statsRecorder`), and `P2PSession` talks back to `RelayClient` through a minimal `RelayChannel` interface — none of the three needs to know the others' concrete types. The single lock that used to guard both subsystems is now two separate locks, each scoped to what it actually protects. This mirrors the v0.6.8 server-side refactor below and completes it.

## v0.6.8

Server-side refactor: the ~2,200-line `Server` is now a composition root over three focused components: `TunnelRegistry` (client session lifecycle, local/cluster routing, TCP port allocation, cluster heartbeat), `ProxyService` (HTTP/WebSocket/TCP data-plane forwarding and the concurrent-stream budget), and `P2PBroker` (`wormhole connect` offer/result signaling). The admin API's `/stats`/`/health`/`/clients`/`/tunnels` endpoints now go through `TunnelRegistry`'s public methods instead of reaching into `Server`'s internals directly. Cross-node proxying also gained `validateClusterNodeAddr`, which rejects anything but a bare `host:port` before it's used to build the outbound proxy target — defense in depth against a corrupted state-store entry smuggling a scheme/userinfo/path into the request.

## v0.6.7

`Server` now derives a cancelable root context in `Start(ctx)` and cancels it as the first step of `Shutdown()`, so operations blocked deep in the handler tree (auth handshake accept, TCP port allocation, P2P peer notification, TCP-tunnel stream open) unblock immediately on shutdown instead of waiting out their own fixed timeouts (e.g. the auth timeout). `tunnel.Stream` gained `ReadContext`/`WriteContext` so a caller holding a cancelable context can interrupt an in-progress blocking `Read`/`Write` — the plain `Read`/`Write` still delegate to them with a non-cancelable background context, so the data-plane hot path (`io.Copy` et al.) pays no extra cost. The same fix was applied to 14 client-side control-plane RPCs (auth, register, ping, stats, close, P2P offer/result) that had the identical gap.

## v0.6.6

`Mux.sendData` now reuses a pooled 32KB payload buffer instead of allocating a fresh one on every `Stream.Write` (99.7% less memory per send in isolated benchmarks, +72% throughput). HTTP response/WebSocket/TCP-tunnel forwarding on both server and client (including `wormhole connect`) switched from bare `io.Copy` to a pooled `io.CopyBuffer`, cutting per-copy allocation by 88.5% in isolated benchmarks and logging previously-discarded copy errors at debug level. Fixed an inspector OOM risk where request/response bodies were read with no size cap despite a comment claiming otherwise — now bounded by the configured `MaxBodySize`.

## v0.6.5

Graceful `Shutdown(ctx)` for the HTTP/admin listeners instead of an abrupt process exit; bidirectional proxying (WebSocket/TCP) now unblocks and closes both sides as soon as either direction errors, instead of waiting for the peer to time out; new `--max-concurrent-streams`/`--max-streams-per-client` caps reject excess data-plane streams instead of unbounded queuing; the control-message decoder rejects malformed empty `UNKNOWN`-typed control frames while still accepting forward-compatible unknown types that carry a payload; new `--min-client-version` semantic-version gate plus real server-capability advertisement (`p2p`/`multi-tunnel`/`cluster`/`audit`) so clients no longer blindly assume optional features are present; removed dead, never-wired connection-pooling code; UDP dropped from `--protocol`'s accepted values (the server never had a UDP dataplane) with an explicit rejection error instead of silent fallback; new `wormhole tunnels create/delete` for imperative tunnel management on a running client; new `wormhole server -c server.yml` config-file support mirroring the client's.

## v0.6.4

HA phase 2: cluster heartbeat now re-registers (TTL-refreshes) every route a node owns each cycle, fixing routes silently expiring out of Redis on long-lived connections; hostname/path-prefix routes are indexed into Redis and resolvable cross-node, not just subdomains; `ClusterNodeID` defaults to `os.Hostname()` when unset; new `--cluster-secret` authenticates inter-node proxy requests; new `--persistence redis` shares team/token-revocation state across nodes with instant cross-node invalidation; `/health` now reports Redis connectivity (`cluster.state_store_healthy`, degrading overall status when unreachable); reconnecting clients reclaim a stale-owner subdomain/hostname/path immediately instead of hitting a spurious conflict; TCP tunnels documented as node-local under HA (no cross-node TCP proxying).

## v0.6.3

Security hardening: RBAC write-permission checks (viewers can no longer register/close tunnels); tunnel control-channel TLS decoupled from the HTTP listener's TLS setting and defaulted on whenever `--require-auth` is combined with a real domain (fails closed instead of silently falling back to plaintext); subdomain registration is now an atomic, cluster-wide reservation that rejects connections on genuine conflicts instead of silently overwriting the previous owner; fixed a token-expiry data race and scheduled periodic revoked-token cleanup; OIDC now explicitly rejects `alg: none` and validates `nbf` with clock-skew leeway; Inspector redacts sensitive headers (`Authorization`/`Cookie`/`Set-Cookie`/etc.) and lowered its default body-capture limit; `/metrics` now requires admin auth; audit logging gained successful-auth/IP-blocked/token-generated/IP-unblocked events plus a configurable retention sweep (`--audit-retention-days`) and an `audit_store_errors` counter on `/stats` so persistence failures are no longer silent.

## v0.6.2

P2P data plane access + transport optimization: new `wormhole connect <subdomain>` command lets two `wormhole` clients hole-punch and exchange real traffic entirely peer-to-peer (server only signals, never relays a byte); the reliable UDP transport upgraded from a fixed 200ms retransmit timer to RFC 6298-style adaptive RTO with per-segment exponential backoff; send/receive path copies reduced (direct in-place encryption, no redundant buffer copies); removed the superseded single-stream ARQ implementation.

## v0.6.1

Correctness closure: reliable reconnection detection (mux close notification + heartbeat-triggered force-close), true multi-tunnel routing (per-tunnel dispatch end-to-end), fixed a P2P signaling frame mismatch, P2P receive-buffer backpressure (bounded blocking delivery + reset on stuck consumers), TCP port-allocation-failure rejection, a reliable P2P stream handshake (SYN retransmission + SYN-ACK — previously a single lost SYN packet under packet loss would leave a connection silently half-open forever), and a WebSocket inspector data race fix. **End-to-end SSO**: `wormhole login` credentials are now auto-loaded by `wormhole client` (no more manual `--token`), expired access tokens are silently renewed via refresh token (including mid-session, across reconnects), the device-flow token poll now includes `client_id` per RFC 8628, and `wormhole client` with no `--local`/`--config` falls back to a default config path.

## v0.6.0

P2 (enterprise capabilities) closure: fixed 22 lint warnings and several security-scan findings (explicit error handling on close paths, fully parameterized SQL); all tests including the race detector pass; lint and security scans are clean.

## v0.5.4

HA / multi-node control plane: pluggable `StateStore` interface (route entries, node heartbeats, dead-node eviction); in-memory implementation for single-node validation plus a Redis-backed implementation for production clustering; cluster heartbeat goroutine (30s interval, 2-minute eviction threshold); cross-node HTTP reverse-proxying; new `--cluster-node-id`/`--cluster-redis-addr` etc. flags.

## v0.5.3

OIDC/OAuth SSO: OIDC Discovery + JWKS JWT validation (RS256/ES256/ES384); OAuth2 Device Code Flow; local credential persistence; `wormhole login` subcommand.

## v0.5.2

Declarative tunnel config and lifecycle management: YAML client config file; multiple tunnels registered in parallel; `SIGHUP` hot-reload (diffs added/removed tunnels); local control API exposing tunnel state; `wormhole tunnels list` subcommand.

## v0.5.1

Audit log enhancement: six new event types; pluggable `AuditStore` (in-memory ring buffer or SQLite-backed); Admin API query (`GET /audit`, filterable) and export (`GET /audit/export`, CSV/JSON) endpoints.

## v0.5.0

P2P data plane completion: a multiplexed, reliable UDP transport (custom frame header, ARQ + sliding-window flow control); the client fully switches to the P2P transport when available, falling back to the relay otherwise; NAT-type-aware peer matching; port-prediction candidates for symmetric-NAT pairs; stress-tested under simulated packet loss.

## v0.4.5

Control protocol migrated to Protobuf: full message schema, generated bindings, a complete protobuf↔struct adapter layer, and a length-prefixed framing protocol; JSON retained as an automatic fallback for backward compatibility; ~4.2x faster decode.

## v0.4.0 – v0.4.4

Initial security and core-capability baseline: TLS end-to-end, multi-protocol CLI (HTTP/HTTPS/TCP/WebSocket/gRPC), connection/quota enforcement, Prometheus metrics, and the initial control-protocol request/response lifecycle (stats query, tunnel close, graceful client shutdown).

## Earlier development

Before the version-per-change discipline above started, Wormhole went through an initial development arc covering: a multiplexed TCP tunnel; HTTP host-based routing with TLS and an Admin API; the traffic inspector UI; the P2P primitives (STUN, hole punching, port prediction, signaling) and their end-to-end integration (peer matching, data transfer, automatic relay→P2P switching); team authentication with HMAC tokens and role-based access control; and P2P end-to-end encryption (X25519 ECDH + AES-256-GCM with HMAC-authenticated hole punching).
