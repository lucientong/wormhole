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

**[中文文档](README_zh.md)**

## Features

- 🚀 **Zero Config** — Just one command to expose your local service
- 🔒 **Secure** — TLS encryption with Let's Encrypt auto-certificates
- 🌐 **HTTP/HTTPS** — Full HTTP support with Host-based routing
- 🔌 **TCP Tunnels** — Support for any TCP protocol (gRPC, WebSocket, etc.)
- 📊 **Inspector** — Built-in traffic inspection UI with real-time WebSocket streaming
- 🤝 **P2P** — NAT traversal and direct peer-to-peer connections with end-to-end encryption (X25519 + AES-256-GCM)
- 🔑 **Auth & RBAC** — HMAC-SHA256 team tokens with role-based access control
- 🐳 **Docker Ready** — Easy deployment with Docker and systemd

## Quick Start

### Installation

```bash
# With Go (recommended)
go install github.com/lucientong/wormhole/cmd/wormhole@latest

# Or download pre-built binaries from releases
# https://github.com/lucientong/wormhole/releases

# Or build from source
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

# Enable traffic inspector
wormhole client --local 8080 --inspector 4040

# Disable P2P mode (use relay only)
wormhole client --local 8080 --p2p=false
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
- **P2P**: STUN-based NAT discovery + UDP hole punching for direct connections, with automatic relay fallback
- **Auth**: HMAC-SHA256 token signing with role-based access control (admin/member/viewer), pre-shared token mode for quick setup

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
  wormhole/wormhole:latest server
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
| `--local` | Local port to expose | Required |
| `--local-host` | Local host to forward to | `127.0.0.1` |
| `--subdomain` | Request specific subdomain | Auto-generated |
| `--token` | Team token for auth | None |
| `--inspector` | Inspector UI port | 0 (disabled) |
| `--p2p` | Enable P2P direct connection | true |

### Server Options

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Tunnel listen port | `7000` |
| `--http-port` | HTTP traffic port | `80` |
| `--admin-port` | Admin API port | `7001` |
| `--domain` | Base domain | `localhost` |
| `--tls` | Enable TLS | false |
| `--tls-email` | Let's Encrypt email | None |
| `--require-auth` | Require authentication for connections | false |
| `--auth-tokens` | Comma-separated pre-shared tokens | None |
| `--auth-secret` | HMAC secret for signed tokens (min 16 chars) | None |
| `--admin-token` | Token to protect admin API | None |
| `--persistence` | Storage backend: memory (default) or sqlite | memory |
| `--persistence-path` | Path to SQLite database | ~/.wormhole/wormhole.db |

## API

### Admin API (Server)

```bash
# Health check (always public)
curl http://localhost:7001/health

# Statistics (requires --admin-token if configured)
curl -H "Authorization: Bearer <admin-token>" http://localhost:7001/stats

# Connected clients
curl -H "Authorization: Bearer <admin-token>" http://localhost:7001/clients
```

### Authentication

Wormhole supports two authentication modes:

```bash
# Simple pre-shared tokens
wormhole server --require-auth --auth-tokens token1,token2
wormhole client --server example.com:7000 --local 8080 --token token1

# HMAC-SHA256 signed tokens (for team management)
wormhole server --require-auth --auth-secret "my-secret-at-least-16-chars"

# Protect admin API with a separate token
wormhole server --admin-token my-admin-secret
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

### Inspector API (Client)

```bash
# List captured requests
curl http://localhost:4040/api/requests

# Get request details
curl http://localhost:4040/api/requests/:id

# Clear all records
curl -X DELETE http://localhost:4040/api/requests

# Real-time stream (WebSocket)
wscat -c ws://localhost:4040/api/ws
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
│   ├── wormhole/     # CLI entry point
│   ├── server/       # Server implementation
│   └── client/       # Client implementation
├── pkg/
│   ├── tunnel/       # Core tunneling (mux, frame, stream, pool)
│   ├── inspector/    # Traffic inspection (capture, storage, websocket)
│   ├── p2p/          # P2P direct connection (STUN, hole punch, predictor)
│   ├── proto/        # Control protocol (JSON messages)
│   ├── auth/         # Authentication & RBAC (HMAC tokens, roles, permissions)
│   ├── version/      # Build version info
│   └── web/          # Embedded web UI
├── web/              # Frontend source (SolidJS)
├── docs/             # Architecture documentation
├── deployments/      # Docker, systemd configs
└── scripts/          # Build and install scripts
```

## Security

Wormhole is designed with security in mind, but as a tunneling tool that exposes local services to the internet, proper configuration is essential.

### Security Features

| Feature | Description |
|---------|-------------|
| **TLS Encryption** | All HTTP traffic encrypted via TLS 1.2+ with Let's Encrypt auto-certificates |
| **P2P E2E Encryption** | X25519 ECDH key exchange + AES-256-GCM for direct P2P connections |
| **HMAC-SHA256 Tokens** | Signed team tokens with expiration and revocation support |
| **RBAC** | Role-based access control (admin / member / viewer) |
| **Rate Limiting** | Automatic IP blocking after repeated authentication failures |
| **Token Revocation** | Blacklist compromised tokens with persistent storage |
| **Constant-time Auth** | Admin token comparison uses `crypto/subtle` to prevent timing attacks |
| **Request Limits** | MaxHeaderBytes and request body size limits to mitigate DoS |

### Production Deployment Checklist

> ⚠️ **Do not use default settings in production.** Follow this checklist to harden your deployment.

```bash
wormhole server \
  --domain tunnel.example.com \
  --tls \
  --tls-email admin@example.com \
  --require-auth \
  --auth-secret "$(openssl rand -base64 32)" \
  --admin-token "$(openssl rand -hex 16)" \
  --persistence sqlite \
  --persistence-path /var/lib/wormhole/wormhole.db
```

- [ ] **Enable TLS** (`--tls`): Without TLS, all traffic (including auth tokens) is transmitted in plaintext. Always enable TLS in production.
- [ ] **Enable Authentication** (`--require-auth`): Without auth, anyone can create tunnels on your server.
- [ ] **Set a strong auth secret** (`--auth-secret`): Use at least 32 random characters. This secret signs all team tokens.
- [ ] **Protect the Admin API** (`--admin-token`): Without this, anyone with network access to the admin port can manage your server.
- [ ] **Use persistent storage** (`--persistence sqlite`): Ensures token revocations survive server restarts.
- [ ] **Restrict admin port access**: Bind the admin port to localhost or use firewall rules (e.g., `--admin-port 127.0.0.1:7001`).

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
- The inspector API binds to localhost by default, but be cautious if your network allows local access

#### Admin API Without Token

If `--admin-token` is not configured, the Admin API is **completely open** with no authentication. This allows anyone with network access to:
- View all connected clients and tunnels
- Generate and revoke tokens
- Manage teams

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

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Apache License — see [LICENSE](LICENSE) for details.
