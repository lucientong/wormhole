# 🕳️ Wormhole

**Zero-config tunnel tool to expose local services to the internet.**

Wormhole folds network space like a wormhole, allowing developers to expose local services to the internet with a single command.

[![CI](https://github.com/lucientong/wormhole/actions/workflows/ci.yml/badge.svg)](https://github.com/lucientong/wormhole/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/lucientong/wormhole)](https://goreportcard.com/report/github.com/lucientong/wormhole)
[![License](https://img.shields.io/github/license/lucientong/wormhole)](LICENSE)

## Features

- 🚀 **Zero Config** - Just one command to expose your local service
- 🔒 **Secure** - TLS encryption with Let's Encrypt auto-certificates
- 🌐 **HTTP/HTTPS** - Full HTTP support with Host-based routing
- 🔌 **TCP Tunnels** - Support for any TCP protocol (gRPC, WebSocket, etc.)
- 📊 **Inspector** - Built-in traffic inspection UI
- 🤝 **P2P** - Direct peer-to-peer connections when possible
- 👥 **Teams** - Multi-user collaboration with team tokens
- 🐳 **Docker Ready** - Easy deployment with Docker

## Quick Start

### Installation

```bash
# One-line install (Linux/macOS)
curl -sSL https://install.wormhole.dev | sh

# Or with Go
go install github.com/wormhole-tunnel/wormhole/cmd/wormhole@latest

# Or download from releases
# https://github.com/wormhole-tunnel/wormhole/releases
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
| `--p2p` | Enable P2P mode | true |

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
```

### Project Structure

```
wormhole/
├── cmd/
│   ├── wormhole/     # CLI entry point
│   ├── server/       # Server implementation
│   └── client/       # Client implementation
├── pkg/
│   ├── tunnel/       # Core tunneling (mux, frame, pool)
│   ├── inspector/    # Traffic inspection
│   ├── p2p/          # P2P direct connection
│   ├── proto/        # Control protocol
│   └── web/          # Embedded web UI
├── web/              # Frontend source
├── deployments/      # Docker, systemd configs
└── scripts/          # Build scripts
```

## Roadmap

- [x] Phase 1: Basic TCP tunnel
- [x] Phase 2: HTTP routing + TLS
- [x] Phase 3: Traffic inspector UI
- [ ] Phase 4: P2P direct connection
- [ ] Phase 5: Team collaboration

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Apache License - see [LICENSE](LICENSE) for details.

---
