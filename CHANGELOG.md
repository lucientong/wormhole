# Changelog

All notable changes to Wormhole are documented here. See [README.md](README.md) for usage and [docs/architecture.md](docs/architecture.md) for the current system design.

**[中文版](CHANGELOG_zh.md)**

## v0.8.0

P5 hardening closure: this release folds the planned v0.7.1-v0.7.5 hardening batches into one v0.8.0 release. Wormhole now validates custom hostnames and path-prefix routes before they reach the router or cluster state, rejecting invalid DNS labels, ports/wildcards/control characters, path traversal, query/fragment delimiters, and malformed path values. Redis-backed cluster startup now requires `--cluster-secret`, making unauthenticated inter-node proxying a fail-fast configuration error instead of a warning; the architecture docs also now describe Redis route reservation as the current atomic Lua script implementation rather than the old `SETNX` wording.

HA and data-plane resilience were tightened as well. When a node refreshes a route it believed it owned and Redis reports that a different live owner has won the route, the losing node now removes only its stale local route and drops that entry from its heartbeat retry list without deleting the winner's Redis entry. `sendPong` and `sendWindowUpdate` no longer block forever behind a full mux control queue, client-side raw proxying now reacts to context cancellation by closing the local connection, and P2P sessions skip duplicate late notifications for the same active peer while still allowing a real peer-address change to trigger a fresh attempt.

P2P and OIDC also received targeted hardening. For Symmetric+Symmetric NAT pairs, server-predicted candidate endpoints now participate in the actual UDP hole-punch loop alongside the primary endpoint, and tests cover the case where only a predicted candidate responds. OIDC JWKS cache refreshes are now singleflighted, and OIDC role mapping no longer grants Wormhole `admin` by default when a claim says `admin`; operators must explicitly enable `--oidc-allow-admin-role` (or `oidc.allow_admin_role` in `server.yml`). Documentation, README, architecture notes, and package docs have been updated to match the new behavior.

## v0.7.0

Documentation and learnability: the README's Quick Start now includes a fully worked, copy-pasteable three-terminal walkthrough (server → local service → client → `curl` verification) that runs entirely on `localhost` with no domain or deployment required, plus dedicated usage docs for `wormhole nat-check`. `docs/architecture.md` gained a "Debugging & Operations Runbook" section — log verbosity flags, a guided tour of the Admin API, the Prometheus metrics worth alerting on, and a table of common failure signatures with where to look for each — and its Testing Strategy section now reflects the full-stack/P2P-signaling/fuzz test layers added in v0.6.13. `pkg/auth`, `pkg/client`, and `pkg/server` each gained (or, for `pkg/auth`, substantially expanded) a package-level `doc.go` covering their composition, request lifecycle, and key extension points, so `go doc` on any of the three now gives a genuinely useful overview rather than a one-line stub. New `CONTRIBUTING.md` covers the dev workflow, code style, and testing conventions for external contributors. Also: the internal review-finding shorthand (e.g. `NS-04`, `NDP-06`) sprinkled through code comments across the last several releases has been swept and rewritten as plain descriptive prose — purely a comment change, no behavioral difference.

## v0.6.13

Test-suite hardening: a full-stack end-to-end test now drives a real server + client pair over actual TCP (auth, tunnel registration, HTTP proxying, graceful shutdown) instead of relying solely on component-level tests to catch a wiring regression across the two. A companion `wormhole connect` integration test starts two real clients against a real server and drives the P2P offer/answer signaling chain end to end, asserting on the (relay-fallback, in this sandboxed CI environment) outcome and the `wormhole_p2p_connections_total` metric rather than on internal state. New fuzz targets for the two decoders that parse attacker-controlled wire bytes directly — the tunnel frame header and the control-message envelope — seeded with the existing malformed-input regression cases and now run for a short, fixed time budget on every CI push (in addition to `go test`'s normal seed-corpus pass) to keep looking for new crashers. `wormhole tunnels create/delete/list` and the client's SIGHUP config-reload path (previously exercised only by hand) now have direct unit coverage; the reload logic was split out of the signal handler into a standalone, testable `reloadClientConfig` function in the process.

## v0.6.12

HA correctness and multi-tenancy: a route registration that fails against the cluster state store for a reason other than a genuine conflict (e.g. a transient Redis outage) is no longer silently dropped — it's kept and retried on every subsequent heartbeat until it succeeds, closing a gap where a client could stay permanently invisible to the rest of the cluster after a Redis hiccup (self-healing is now also backed by `wormhole_cluster_route_sync_failures_total`/`wormhole_cluster_route_conflicts_total` metrics for observability, the latter flagging the rarer case where a retried registration turns out to have raced a real conflict). Redis-backed route registration is now a single atomic Lua script instead of a `SETNX`-then-`SET` sequence, removing a window where a concurrent lookup or a crash mid-registration could see a route as reserved but not yet resolvable. Reclaiming a subdomain/hostname/path left behind by a session that died without disconnecting cleanly now also requires the reclaiming client to belong to the same team as the original owner (or either side to have no team), so a different team can no longer race in and steal a route during another team's reconnect window. New `--reserved-subdomains` (default: `admin`/`api`/`www`/`status`/`metrics`/`health`) keeps operator-facing subdomains from being claimed by whichever team's client registers first; admin-role tokens bypass the list. `wormhole connect` P2P signaling against a target connected to a *different* cluster node now returns an explicit "connected elsewhere, falling back to relay" reason instead of a misleading "not found" (true cross-node P2P signaling remains unsupported — the peer's NAT/address/key material only ever lives in that node's own memory). Token refresh/extension via the admin API is now audited (`token_refreshed`); `/audit/export`'s `limit` parameter is no longer silently capped to `/audit`'s own 1,000-row interactive-listing limit and now supports bulk exports up to 100,000 rows (default 10,000).

## v0.6.11

Data-plane resilience: P2P session setup now tears down the previous connection/UDP socket/accept-loop before installing a new one and guards against concurrent hole-punch attempts, fixing a leak where retried or racing offers could leave orphaned sessions running. The P2P encryption layer gained a sliding-window anti-replay check (rejects duplicate or too-old packets before decrypting, out-of-order delivery within the window still accepted) — previously a captured ciphertext could be replayed since GCM tag verification alone doesn't guard against replay on a connectionless transport. The TCP mux now queues control frames (`WINDOW_UPDATE`/`PING`/`PONG`/`HANDSHAKE`) on their own channel ahead of bulk `DATA`, so a connection saturated with data in both directions can no longer starve the keep-alive/flow-control messages that would otherwise unstick it (a `CLOSE` frame still queues with `DATA` so it can never be delivered ahead of the stream's own pending bytes). Both the client (relay and P2P) and the server's control plane now enforce a configurable cap on concurrent inbound streams, protecting against goroutine exhaustion from a burst of stream opens. Also: removed a dead `EnableFlowControl` config flag that was never read; local-dial failures on the client no longer write a raw protobuf response onto a stream the peer treats as plain HTTP/TCP bytes; and the client's application-level heartbeat now validates the echoed ping ID instead of treating any response as success.

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
