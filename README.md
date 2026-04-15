# 🕳️ Wormhole

**Zero-config tunnel tool to expose local services to the internet.**

Wormhole folds network space like a wormhole, allowing developers to expose local services to the internet with a single command.

[![CI](https://github.com/lucientong/wormhole/actions/workflows/ci.yml/badge.svg)](https://github.com/lucientong/wormhole/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/lucientong/wormhole)](https://goreportcard.com/report/github.com/lucientong/wormhole)
[![Go Reference](https://pkg.go.dev/badge/github.com/lucientong/wormhole.svg)](https://pkg.go.dev/github.com/lucientong/wormhole)
[![codecov](https://codecov.io/gh/lucientong/wormhole/branch/master/graph/badge.svg)](https://codecov.io/gh/lucientong/wormhole)
[![Release](https://img.shields.io/github/v/release/lucientong/wormhole)](https://github.com/lucientong/wormhole/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/lucientong/wormhole)](go.mod)
[![License](https://img.shields.io/github/license/lucientong/wormhole)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/lucientong/wormhole)](https://hub.docker.com/r/lucientong/wormhole)
[![GitHub Downloads](https://img.shields.io/github/downloads/lucientong/wormhole/total)](https://github.com/lucientong/wormhole/releases)

**[中文文档](README_zh.md)**

## Features

- 🚀 **Zero Config** — Just one command to expose your local service
- 🔒 **Secure** — TLS encryption with Let's Encrypt auto-certificates
- 🌐 **HTTP/HTTPS** — Full HTTP support with Host-based routing
- 🔌 **TCP Tunnels** — Support for any TCP protocol (gRPC, WebSocket, etc.)
- 📊 **Inspector** — Built-in traffic inspection UI with real-time WebSocket streaming
- 🤝 **P2P** — NAT traversal and direct peer-to-peer connections with end-to-end encryption (X25519 + AES-256-GCM)
- 🔑 **Auth & RBAC** — HMAC-SHA256 team tokens with role-based access control
- 🪪 **SSO / OIDC** — OAuth2 Device Code Flow + OIDC JWT validation; `wormhole login` for CLI-based SSO
- 📋 **Audit Logs** — Structured audit event log with SQLite persistence and CSV/JSON export API
- 📁 **Declarative Config** — YAML config file, multi-tunnel, SIGHUP hot-reload, `wormhole tunnels list`
- 🏗️ **HA / Multi-Node** — Pluggable `StateStore` with Redis backend; cross-node HTTP routing and cluster heartbeat
- 🐳 **Docker Ready** — Easy deployment with Docker and systemd

## Quick Start

### Installation

**Homebrew (macOS/Linux)**

```bash
brew install lucientong/tap/wormhole
```

**Docker**

```bash
# Run client
docker run --rm -it lucientong/wormhole client --server tunnel.example.com:7000 --local 8080

# Run server
docker run -d -p 7000:7000 -p 80:80 lucientong/wormhole server --domain tunnel.example.com
```

**Go Install**

```bash
go install github.com/lucientong/wormhole/cmd/wormhole@latest
```

**Pre-built Binaries**

Download from [GitHub Releases](https://github.com/lucientong/wormhole/releases).

**Build from Source**

```bash
git clone https://github.com/lucientong/wormhole.git
cd wormhole && make build
```

### Usage

```bash
# Expose local port 8080
wormhole 8080

# Or with explicit client command
wormhole client --local 8080

# Connect to a specific server
wormhole client --server tunnel.example.com:7000 --local 8080

# Request a specific subdomain
wormhole client --local 8080 --subdomain myapp

# Connect with TLS
wormhole client --tls --server tunnel.example.com:7000 --local 8080

# Enable traffic inspector
wormhole client --local 8080 --inspector 4040

# Expose a TCP service (e.g. database)
wormhole client --protocol tcp --local 3306

# Use custom hostname routing
wormhole client --protocol http --hostname api.example.com --local 8080

# Disable P2P mode (use relay only)
wormhole client --local 8080 --p2p=false

# Load multi-tunnel config from YAML file (hot-reload with SIGHUP)
wormhole client --config ~/.wormhole/tunnels.yaml

# List active tunnels via local control API
wormhole tunnels list

# SSO login via OIDC Device Code Flow
wormhole login --issuer https://accounts.google.com --client-id <id>
```

That's it! Your local service is now accessible from the internet.

## Architecture

> 📖 For detailed protocol design and system architecture, see [Architecture Guide](docs/architecture.md).

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Your Users    │   HTTP  │  Wormhole       │  Tunnel │  Your Local     │
│   (Internet)    │ ──────► │  Server (VPS)   │ ──────► │  Service :8080  │
└─────────────────┘         └─────────────────┘         └─────────────────┘
                                    │
                            ┌───────┴───────┐
                            │ TLS + Routing │
                            │ + Port Alloc  │
                            └───────────────┘
```

### Key Design

- **Multiplexed Tunnel**: A single TCP connection carries multiple logical streams (control, HTTP requests, heartbeats) via a custom binary frame protocol
- **Host-based Routing**: Server routes incoming HTTP requests to the correct client based on `Host` header and subdomain
- **Inspector**: Client-side HTTP traffic capture with a real-time web UI (WebSocket push + REST API)
- **P2P**: STUN-based NAT discovery (IPv4/IPv6 dual-stack) + UDP hole punching for direct connections, with automatic relay fallback
- **Auth**: HMAC-SHA256 token signing with role-based access control (admin/member/viewer), pre-shared token mode for quick setup
- **OIDC/SSO**: OIDC Discovery + JWKS JWT validation; OAuth2 Device Code Flow for CLI-based login; credentials persisted to `~/.wormhole/credentials.json`
- **Audit Log**: Structured events (auth, tunnel, P2P) stored in memory (ring buffer) or SQLite; queryable via Admin API with CSV/JSON export
- **Multi-Tunnel Config**: YAML config file with multiple tunnel definitions; SIGHUP triggers diff-based hot-reload; local control API (`--ctrl-port`) for `wormhole tunnels list`
- **HA / Multi-Node**: Pluggable `StateStore` interface; in-memory (single-node) or Redis backend; cluster heartbeat + dead-node eviction; cross-node HTTP proxying via `httputil.ReverseProxy`

### Components

- **wormhole-server**: Runs on a VPS with public IP, handles routing and TLS
- **wormhole-client**: Runs locally, connects to server and forwards traffic

## Server Deployment

### Docker (Recommended)

```bash
# Using Docker Compose
docker-compose -f deployments/docker/docker-compose.yml up -d

# Or directly
docker run -d \
  -p 7000:7000 \
  -p 80:80 \
  -p 443:443 \
  -e WORMHOLE_DOMAIN=tunnel.example.com \
  lucientong/wormhole server
```

### Systemd

```bash
# Install binary
sudo cp wormhole /usr/local/bin/

# Create user
sudo useradd -r -s /bin/false wormhole

# Install service file
sudo cp deployments/systemd/wormhole-server.service /etc/systemd/system/

# Start service
sudo systemctl daemon-reload
sudo systemctl enable wormhole-server
sudo systemctl start wormhole-server
```

### Manual

```bash
wormhole server \
  --port 7000 \
  --domain tunnel.example.com \
  --tls
```

## Configuration

### Client Options

| Flag | Description | Default |
|------|-------------|---------|
| `--server` | Server address | `localhost:7000` |
| `--local` | Local port to expose | — |
| `--local-host` | Local host to forward to | `127.0.0.1` |
| `--subdomain` | Request specific subdomain | Auto-generated |
| `--token` | Team token for auth | None |
| `--inspector` | Inspector UI port | 0 (disabled) |
| `--inspector-host` | Host for inspector UI | `127.0.0.1` |
| `--p2p` | Enable P2P direct connection | true |
| `--tls` | Enable TLS for server connection | false |
| `--tls-insecure` | Skip TLS certificate verification (dev only) | false |
| `--tls-ca` | Path to custom CA certificate for TLS verification | None |
| `--protocol` / `-P` | Tunnel protocol: http, https, tcp, udp, ws, grpc | `http` |
| `--hostname` | Custom hostname for routing | None |
| `--path-prefix` | Path-based routing prefix | None |
| `--config` | Path to YAML tunnel config file (multi-tunnel mode) | None |
| `--ctrl-port` | Local control API port for `wormhole tunnels list` | 0 (disabled) |

### Server Options

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Tunnel listen port | `7000` |
| `--host` | Host to bind to | `0.0.0.0` |
| `--http-port` | HTTP traffic port | `80` |
| `--admin-port` | Admin API port | `7001` |
| `--admin-host` | Host for admin API (security: loopback only by default) | `127.0.0.1` |
| `--domain` | Domain for tunnel URLs (env: `WORMHOLE_DOMAIN`) | `localhost` |
| `--tls` | Enable TLS (auto-cert if domain is set) | false |
| `--tunnel-tls` | Enable TLS for tunnel control listener (defaults to `--tls`) | same as `--tls` |
| `--cert` | Path to TLS certificate file | None |
| `--key` | Path to TLS private key file | None |
| `--require-auth` | Require authentication for connections | false |
| `--auth-tokens` | Comma-separated pre-shared tokens | None |
| `--auth-secret` | HMAC secret for signed tokens (min 16 chars) | None |
| `--admin-token` | Token to protect admin API | None |
| `--persistence` | Storage backend: memory (default) or sqlite | memory |
| `--persistence-path` | Path to SQLite database | `~/.wormhole/wormhole.db` |
| `--audit` | Enable structured audit logging | false |
| `--audit-persistence` | Audit storage backend: memory or sqlite | memory |
| `--audit-path` | Path to SQLite audit database | `~/.wormhole/audit.db` |
| `--audit-buffer-size` | In-memory audit ring buffer size (events) | 10000 |
| `--oidc-issuer` | OIDC issuer URL for JWT validation | None |
| `--oidc-client-id` | OAuth2 client ID for OIDC audience validation | None |
| `--oidc-team-claim` | JWT claim to use as team name | `email` |
| `--oidc-role-claim` | JWT claim to use as Wormhole role | None |
| `--cluster-backend` | Cluster state backend: memory or redis | (disabled) |
| `--cluster-node-id` | Unique ID for this node in the cluster | hostname |
| `--cluster-node-addr` | Address other nodes use to reach this node | None |
| `--cluster-redis-addr` | Redis address for cluster state | None |
| `--cluster-redis-password` | Redis AUTH password | None |
| `--cluster-redis-db` | Redis database number | 0 |

## API

### Admin API (Server)

```bash
# Health check (always public)
curl http://localhost:7001/health

# Statistics (requires --admin-token if configured)
curl -H "Authorization: Bearer <admin-token>" http://localhost:7001/stats

# Connected clients
curl -H "Authorization: Bearer <admin-token>" http://localhost:7001/clients

# Query audit log (JSON, filterable by type/from/to/limit)
curl -H "Authorization: Bearer <admin-token>" \
  "http://localhost:7001/audit?type=auth_failure&limit=50"

# Export audit log as CSV
curl -H "Authorization: Bearer <admin-token>" \
  "http://localhost:7001/audit/export?format=csv" -o audit.csv
```

### Client Control API

When `--ctrl-port` is set, a local HTTP control server exposes tunnel state:

```bash
# Start client with control API on port 7100
wormhole client --local 8080 --ctrl-port 7100

# Or with a config file
wormhole client --config ~/.wormhole/tunnels.yaml --ctrl-port 7100

# List active tunnels
wormhole tunnels list --ctrl-port 7100
# or directly:
curl http://localhost:7100/tunnels
```

### Authentication

Wormhole supports three authentication modes:

```bash
# Simple pre-shared tokens
wormhole server --require-auth --auth-tokens token1,token2
wormhole client --server example.com:7000 --local 8080 --token token1

# HMAC-SHA256 signed tokens (for team management)
wormhole server --require-auth --auth-secret "my-secret-at-least-16-chars"

# OIDC / SSO (e.g. Google, Okta, Auth0)
wormhole server --require-auth \
  --oidc-issuer https://accounts.google.com \
  --oidc-client-id <your-client-id>

# Protect admin API with a separate token
wormhole server --admin-token my-admin-secret
```

### SSO Login (OIDC Device Code Flow)

```bash
# Log in via your identity provider — browser URL is printed, token saved locally
wormhole login \
  --issuer https://accounts.google.com \
  --client-id <client-id> \
  --server tunnel.example.com:7000

# Subsequent client commands automatically use the saved token
wormhole client --server tunnel.example.com:7000 --local 8080
```

### Multi-Tunnel Config File

Create `~/.wormhole/tunnels.yaml`:

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
    protocol: http
    subdomain: myapi
  - name: db
    local_port: 5432
    protocol: tcp
```

```bash
# Start all tunnels from config
wormhole client --config ~/.wormhole/tunnels.yaml --ctrl-port 7100

# Hot-reload tunnels without restart (add/remove tunnels in YAML, then:)
kill -HUP <wormhole-pid>

# List running tunnels
wormhole tunnels list
```

### Persistent Storage

By default, Wormhole uses in-memory storage, which is lost on restart. To persist team data and token revocations, enable SQLite storage:

```bash
# Enable SQLite persistence (default path: ~/.wormhole/wormhole.db)
wormhole server --require-auth --auth-secret "my-secret" --persistence sqlite

# Specify custom database path
wormhole server --require-auth --auth-secret "my-secret" \
  --persistence sqlite \
  --persistence-path /var/lib/wormhole/data.db
```

Persistent storage saves:
- Team information
- Revoked token blacklist

### Audit Logging

```bash
# Enable in-memory audit log (ring buffer, 10 000 events)
wormhole server --audit

# Enable SQLite-backed audit log
wormhole server --audit --audit-persistence sqlite --audit-path /var/log/wormhole/audit.db

# Query recent auth failures
curl -H "Authorization: Bearer <token>" \
  "http://localhost:7001/audit?type=auth_failure&limit=20"

# Export full audit log as CSV
curl -H "Authorization: Bearer <token>" \
  "http://localhost:7001/audit/export?format=csv" -o audit.csv
```

### High Availability / Multi-Node

```bash
# Node 1
wormhole server \
  --cluster-backend redis \
  --cluster-redis-addr redis.internal:6379 \
  --cluster-node-id node1 \
  --cluster-node-addr 10.0.0.1:7000 \
  --domain tunnel.example.com

# Node 2 (same Redis, different node ID/addr)
wormhole server \
  --cluster-backend redis \
  --cluster-redis-addr redis.internal:6379 \
  --cluster-node-id node2 \
  --cluster-node-addr 10.0.0.2:7000 \
  --domain tunnel.example.com
```

Each node:
- Sends a heartbeat to Redis every 30 seconds
- Evicts dead nodes (missed > 3 heartbeats) every 60 seconds
- Looks up unknown subdomains in Redis and proxies HTTP requests to the owning node
- Cleans up its routes from Redis on client disconnect

### Inspector API (Client)

```bash
# List captured records
curl http://localhost:4040/api/inspector/records

# Get record details
curl http://localhost:4040/api/inspector/records/:id

# Get inspector stats
curl http://localhost:4040/api/inspector/stats

# Clear all records
curl -X POST http://localhost:4040/api/inspector/clear

# Toggle capture on/off
curl -X POST http://localhost:4040/api/inspector/toggle

# Real-time stream (WebSocket)
wscat -c ws://localhost:4040/api/inspector/ws
```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/lucientong/wormhole.git
cd wormhole

# Build
make build

# Run tests
make test

# Run with coverage
make test-coverage

# Lint (requires golangci-lint)
golangci-lint run ./...
```

### Project Structure

```
wormhole/
├── cmd/
│   ├── wormhole/         # CLI entry point (Cobra)
│   │   └── cmd/
│   │       ├── client.go   # wormhole client
│   │       ├── server.go   # wormhole server
│   │       ├── tunnels.go  # wormhole tunnels list
│   │       └── login.go    # wormhole login (OIDC Device Flow)
│   ├── server/           # Standalone server entry (thin wrapper)
│   └── client/           # Standalone client entry (thin wrapper)
├── pkg/
│   ├── client/           # Client core (config, multi-tunnel, hot-reload, control API)
│   ├── server/           # Server core (config, routing, handler, TLS, admin, cluster)
│   │   ├── state.go        # StateStore interface
│   │   ├── state_memory.go # In-memory StateStore (single-node)
│   │   ├── state_redis.go  # Redis StateStore (multi-node)
│   │   └── cluster.go      # Heartbeat, dead-node eviction, cross-node proxy
│   ├── tunnel/           # Core tunneling (mux, frame, stream, pool)
│   ├── inspector/        # Traffic inspection (capture, storage, websocket)
│   ├── p2p/              # P2P direct connection (STUN, hole punch, predictor, UDPMux, UDPStream)
│   ├── proto/            # Control protocol (Protobuf + JSON fallback)
│   ├── auth/             # Authentication & RBAC
│   │   ├── token.go        # HMAC tokens, OIDC integration
│   │   ├── oidc.go         # OIDC Discovery + JWKS JWT validation
│   │   ├── oauth.go        # OAuth2 Device Code Flow
│   │   ├── credentials.go  # Token persistence (~/.wormhole/credentials.json)
│   │   ├── audit.go        # AuditLogger + event convenience methods
│   │   └── audit_store.go  # AuditStore interface (memory + SQLite backends)
│   ├── version/          # Build version info
│   └── web/              # Embedded web UI
├── web/                  # Frontend source (SolidJS)
├── docs/                 # Architecture documentation
├── deployments/          # Docker, systemd configs
└── scripts/              # Build and install scripts
```

## Security

Wormhole is designed with security in mind, but as a tunneling tool that exposes local services to the internet, proper configuration is essential.

### Security Features

| Feature | Description |
|---------|-------------|
| **TLS Encryption** | HTTP listener and tunnel control channel encrypted via TLS 1.2+ with Let's Encrypt auto-certificates or manual certificates; client supports `--tls` / `--tls-insecure` / `--tls-ca` |
| **P2P E2E Encryption** | X25519 ECDH key exchange + AES-256-GCM for direct P2P connections |
| **HMAC-SHA256 Tokens** | Signed team tokens with expiration and revocation support |
| **OIDC / SSO** | OIDC Discovery + JWKS JWT validation; claims-based team/role mapping; no password ever stored |
| **RBAC** | Role-based access control (admin / member / viewer) |
| **Rate Limiting** | Automatic IP blocking after repeated authentication failures |
| **Token Revocation** | Individual token blacklist + team-level bulk revocation (version-based) with persistent storage |
| **Constant-time Auth** | Admin token comparison uses `crypto/subtle` to prevent timing attacks |
| **Request Limits** | MaxHeaderBytes and request body size limits to mitigate DoS |
| **Audit Logging** | Immutable structured event log (auth, tunnel, P2P) with SQLite persistence and Admin API export |

### Production Deployment Checklist

> ⚠️ **Do not use default settings in production.** Follow this checklist to harden your deployment.

```bash
wormhole server \
  --domain tunnel.example.com \
  --tls \
  --require-auth \
  --auth-secret "$(openssl rand -base64 32)" \
  --admin-token "$(openssl rand -hex 16)" \
  --persistence sqlite \
  --persistence-path /var/lib/wormhole/wormhole.db \
  --audit \
  --audit-persistence sqlite
```

- [ ] **Enable TLS** (`--tls`): Without TLS, all traffic (including auth tokens) is transmitted in plaintext. Always enable TLS in production.
- [ ] **Enable Authentication** (`--require-auth`): Without auth, anyone can create tunnels on your server.
- [ ] **Set a strong auth secret** (`--auth-secret`): Use at least 32 random characters. This secret signs all team tokens.
- [ ] **Protect the Admin API** (`--admin-token`): Without this, anyone with network access to the admin port can manage your server.
- [ ] **Use persistent storage** (`--persistence sqlite`): Ensures token revocations survive server restarts.
- [ ] **Enable audit logging** (`--audit --audit-persistence sqlite`): Maintains an immutable record of authentication events and tunnel lifecycle.
- [ ] **Restrict admin port access**: Admin binds to `127.0.0.1` by default. If remote access is needed, use `--admin-host 0.0.0.0 --admin-token <token>`.

### Security Considerations

#### P2P Mode

P2P direct connections feature **end-to-end encryption** using X25519 ECDH key exchange and AES-256-GCM authenticated encryption. The key exchange happens via the server's signaling channel, but the server never sees the shared secret — only public keys are relayed. This provides:

- **X25519 ECDH** key agreement for perfect forward secrecy per session
- **AES-256-GCM** authenticated encryption for all data packets
- **HMAC-SHA256** authentication of hole-punch probes to prevent injection
- **HKDF-SHA256** key derivation with separate keys for encryption and probe authentication

If P2P hole punching fails, the client automatically falls back to the encrypted relay channel:

```bash
# Disable P2P to force all traffic through the encrypted relay
wormhole client --local 8080 --p2p=false
```

#### Inspector

The traffic inspector captures and displays HTTP request/response data. In production:

- **Do not enable the inspector** on public-facing deployments
- The inspector binds to **`127.0.0.1`** by default — use `--inspector-host 0.0.0.0` to allow external access (not recommended)
- CORS is restricted to localhost origins by default

#### Admin API Without Token

If `--admin-token` is not configured, the Admin API **only allows requests from loopback addresses** (`127.0.0.1` / `::1`). Non-loopback requests are rejected with a 403 error. This means:
- Local access (e.g. `curl http://localhost:7001/stats`) works without a token
- Remote access requires `--admin-token` to be configured

The admin API binds to `127.0.0.1` by default. If you need remote access, use `--admin-host 0.0.0.0 --admin-token <token>`.

Always configure `--admin-token` in production.

#### Subdomain Randomness

Auto-generated subdomains use 64-bit cryptographic randomness (`crypto/rand`), producing 16-character hex strings. This makes brute-force subdomain guessing infeasible.

## Roadmap

- [x] Phase 1: Basic TCP tunnel with multiplexing
- [x] Phase 2: HTTP routing + TLS + Admin API
- [x] Phase 3: Traffic inspector UI
- [x] Phase 4: P2P direct connection — primitives (STUN, hole punch, predictor, signaling)
- [x] Phase 4.5: P2P end-to-end integration (peer matching, data transfer, relay→P2P switch)
- [x] Phase 5: Team collaboration (auth, HMAC tokens, RBAC, admin API protection)
- [x] Phase 6: P2P end-to-end encryption (X25519 ECDH, AES-256-GCM, HMAC-authenticated hole punch)
- [x] Phase 7: Control protocol Protobuf migration + reliable UDP transport (UDPMux + UDPStream + ARQ)
- [x] Phase 8 (v0.5.1): Audit log enhancement — event types, SQLite persistence, Admin query/export API
- [x] Phase 9 (v0.5.2): Declarative tunnel config — YAML config file, multi-tunnel, SIGHUP hot-reload, `tunnels` subcommand
- [x] Phase 10 (v0.6.0): OIDC / OAuth SSO — OIDC Discovery, JWKS JWT validation, Device Code Flow, `wormhole login`
- [x] Phase 11 (v0.7.0): HA / Multi-node control plane — `StateStore` interface, Redis backend, cluster heartbeat, cross-node HTTP routing

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Apache License — see [LICENSE](LICENSE) for details.
