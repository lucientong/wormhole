# 🕳️ Wormhole

**Zero-config tunnel tool to expose local services to the internet.**

Wormhole folds network space like a wormhole, allowing developers to expose local services to the internet with a single command.

[![CI](https://github.com/lucientong/wormhole/actions/workflows/ci.yml/badge.svg)](https://github.com/lucientong/wormhole/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/lucientong/wormhole)](https://goreportcard.com/report/github.com/lucientong/wormhole)
[![License](https://img.shields.io/github/license/lucientong/wormhole)](LICENSE)

**[中文文档](README_zh.md)**

## Features

- 🚀 **Zero Config** — Just one command to expose your local service
- 🔒 **Secure** — TLS encryption with Let's Encrypt auto-certificates
- 🌐 **HTTP/HTTPS** — Full HTTP support with Host-based routing
- 🔌 **TCP Tunnels** — Support for any TCP protocol (gRPC, WebSocket, etc.)
- 📊 **Inspector** — Built-in traffic inspection UI with real-time WebSocket streaming
- 🤝 **P2P** — NAT traversal and direct peer-to-peer connections when possible
- 🐳 **Docker Ready** — Easy deployment with Docker and systemd

## Quick Start

### Installation

```bash
# One-line install (Linux/macOS)
curl -sSL https://install.wormhole.dev | sh

# Or with Go
go install github.com/wormhole-tunnel/wormhole/cmd/wormhole@latest

# Or download from releases
# https://github.com/lucientong/wormhole/releases
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
- **P2P (Phase 4)**: STUN-based NAT discovery + UDP hole punching for direct connections, with automatic relay fallback

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

## API

### Admin API (Server)

```bash
# Health check
curl http://localhost:7001/health

# Statistics
curl http://localhost:7001/stats

# Connected clients
curl http://localhost:7001/clients
```

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
│   ├── version/      # Build version info
│   └── web/          # Embedded web UI
├── web/              # Frontend source (SolidJS)
├── docs/             # Architecture documentation
├── deployments/      # Docker, systemd configs
└── scripts/          # Build and install scripts
```

## Roadmap

- [x] Phase 1: Basic TCP tunnel with multiplexing
- [x] Phase 2: HTTP routing + TLS + Admin API
- [x] Phase 3: Traffic inspector UI
- [x] Phase 4: P2P direct connection (STUN + NAT traversal + hole punching)
- [ ] Phase 5: Team collaboration

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Apache License — see [LICENSE](LICENSE) for details.
