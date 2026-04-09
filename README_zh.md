# 🕳️ Wormhole

**零配置隧道工具，一键将本地服务暴露到公网。**

Wormhole 像虫洞一样折叠网络空间，让开发者用一条命令就能将本地服务暴露到互联网。

[![CI](https://github.com/lucientong/wormhole/actions/workflows/ci.yml/badge.svg)](https://github.com/lucientong/wormhole/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/lucientong/wormhole)](https://goreportcard.com/report/github.com/lucientong/wormhole)
[![Go Reference](https://pkg.go.dev/badge/github.com/lucientong/wormhole.svg)](https://pkg.go.dev/github.com/lucientong/wormhole)
[![codecov](https://codecov.io/gh/lucientong/wormhole/branch/master/graph/badge.svg)](https://codecov.io/gh/lucientong/wormhole)
[![Release](https://img.shields.io/github/v/release/lucientong/wormhole)](https://github.com/lucientong/wormhole/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/lucientong/wormhole)](go.mod)
[![License](https://img.shields.io/github/license/lucientong/wormhole)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/lucientong/wormhole)](https://hub.docker.com/r/lucientong/wormhole)
[![GitHub Downloads](https://img.shields.io/github/downloads/lucientong/wormhole/total)](https://github.com/lucientong/wormhole/releases)

**[English](README.md)**

## 功能特性

- 🚀 **零配置** — 一条命令即可暴露本地服务
- 🔒 **安全** — TLS 加密，支持 Let's Encrypt 自动证书
- 🌐 **HTTP/HTTPS** — 完整 HTTP 支持，基于 Host 的路由
- 🔌 **TCP 隧道** — 支持任意 TCP 协议（gRPC、WebSocket 等）
- 📊 **流量检查** — 内置流量检查 UI，WebSocket 实时推送
- 🤝 **P2P 直连** — NAT 穿透与点对点直连，端到端加密（X25519 + AES-256-GCM）
- 🔑 **认证与权限** — HMAC-SHA256 团队 Token + 角色权限控制（Admin/Member/Viewer）
- 🐳 **Docker 就绪** — 支持 Docker 和 systemd 部署

## 快速开始

### 安装

**Homebrew（macOS/Linux）**

```bash
brew install lucientong/tap/wormhole
```

**Docker**

```bash
# 运行客户端
docker run --rm -it lucientong/wormhole client --server tunnel.example.com:7000 --local 8080

# 运行服务端
docker run -d -p 7000:7000 -p 80:80 lucientong/wormhole server --domain tunnel.example.com
```

**Go Install**

```bash
go install github.com/lucientong/wormhole/cmd/wormhole@latest
```

**预编译二进制**

从 [GitHub Releases](https://github.com/lucientong/wormhole/releases) 下载。

**从源码构建**

```bash
git clone https://github.com/lucientong/wormhole.git
cd wormhole && make build
```

### 使用

```bash
# 暴露本地 8080 端口
wormhole 8080

# 显式指定客户端命令
wormhole client --local 8080

# 连接到指定服务器
wormhole client --server tunnel.example.com:7000 --local 8080

# 请求指定子域名
wormhole client --local 8080 --subdomain myapp

# 启用流量检查器
wormhole client --local 8080 --inspector 4040

# 禁用 P2P 模式（仅使用中继）
wormhole client --local 8080 --p2p=false
```

就这么简单！你的本地服务现在可以从公网访问了。

## 架构

> 📖 详细的协议设计和系统架构，请参阅 [架构指南](docs/architecture_zh.md)。

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   外部用户       │   HTTP  │  Wormhole       │   隧道  │  你的本地        │
│   (互联网)       │ ──────► │  Server (VPS)   │ ──────► │  服务 :8080     │
└─────────────────┘         └─────────────────┘         └─────────────────┘
                                    │
                            ┌───────┴───────┐
                            │ TLS + 路由    │
                            │ + 端口分配    │
                            └───────────────┘
```

### 核心设计

- **多路复用隧道**：单个 TCP 连接承载多个逻辑 Stream（控制、HTTP 请求、心跳），使用自定义二进制帧协议
- **基于 Host 的路由**：Server 根据 `Host` 头和子域名将 HTTP 请求路由到对应的 Client
- **流量检查器**：客户端 HTTP 流量捕获，带实时 Web UI（WebSocket 推送 + REST API）
- **P2P 直连**：基于 STUN 的 NAT 发现 + UDP 打洞，自动降级到中继模式
- **认证授权**：HMAC-SHA256 签名 Token + 角色权限控制（admin/member/viewer），支持预共享 Token 快速接入

### 组件

- **wormhole-server**：运行在有公网 IP 的 VPS 上，处理路由和 TLS
- **wormhole-client**：在本地运行，连接服务器并转发流量

## 服务器部署

### Docker（推荐）

```bash
# 使用 Docker Compose
docker-compose -f deployments/docker/docker-compose.yml up -d

# 或直接运行
docker run -d \
  -p 7000:7000 \
  -p 80:80 \
  -p 443:443 \
  -e WORMHOLE_DOMAIN=tunnel.example.com \
  lucientong/wormhole server
```

### Systemd

```bash
# 安装二进制文件
sudo cp wormhole /usr/local/bin/

# 创建用户
sudo useradd -r -s /bin/false wormhole

# 安装 service 文件
sudo cp deployments/systemd/wormhole-server.service /etc/systemd/system/

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable wormhole-server
sudo systemctl start wormhole-server
```

### 手动运行

```bash
wormhole server \
  --port 7000 \
  --domain tunnel.example.com \
  --tls
```

## 配置

### 客户端选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--server` | 服务器地址 | `localhost:7000` |
| `--local` | 要暴露的本地端口 | 必填 |
| `--local-host` | 转发目标主机 | `127.0.0.1` |
| `--subdomain` | 请求指定子域名 | 自动生成 |
| `--token` | 团队认证 Token | 无 |
| `--inspector` | 检查器 UI 端口 | 0（禁用） |
| `--p2p` | 启用 P2P 直连 | true |

### 服务器选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--port` | 隧道监听端口 | `7000` |
| `--http-port` | HTTP 流量端口 | `80` |
| `--admin-port` | 管理 API 端口 | `7001` |
| `--domain` | 基础域名 | `localhost` |
| `--tls` | 启用 TLS | false |
| `--tls-email` | Let's Encrypt 邮箱 | 无 |
| `--require-auth` | 要求客户端认证 | false |
| `--auth-tokens` | 预共享 Token 列表（逗号分隔） | 无 |
| `--auth-secret` | HMAC 签名密钥（至少 16 字符） | 无 |
| `--admin-token` | 管理 API 访问 Token | 无 |
| `--persistence` | 存储后端：memory（默认）或 sqlite | memory |
| `--persistence-path` | SQLite 数据库路径 | ~/.wormhole/wormhole.db |

## API

### 管理 API（服务器端）

```bash
# 健康检查（始终公开）
curl http://localhost:7001/health

# 统计信息（配置 --admin-token 后需携带 Token）
curl -H "Authorization: Bearer <admin-token>" http://localhost:7001/stats

# 已连接的客户端
curl -H "Authorization: Bearer <admin-token>" http://localhost:7001/clients
```

### 认证

Wormhole 支持两种认证模式：

```bash
# 简单预共享 Token 模式
wormhole server --require-auth --auth-tokens token1,token2
wormhole client --server example.com:7000 --local 8080 --token token1

# HMAC-SHA256 签名 Token 模式（团队管理）
wormhole server --require-auth --auth-secret "my-secret-at-least-16-chars"

# 保护管理 API
wormhole server --admin-token my-admin-secret
```

### 持久化存储

默认情况下，Wormhole 使用内存存储，服务重启后数据会丢失。如果需要持久化团队和 Token 吊销数据，可以启用 SQLite 存储：

```bash
# 使用 SQLite 持久化（默认路径：~/.wormhole/wormhole.db）
wormhole server --require-auth --auth-secret "my-secret" --persistence sqlite

# 指定自定义数据库路径
wormhole server --require-auth --auth-secret "my-secret" \
  --persistence sqlite \
  --persistence-path /var/lib/wormhole/data.db
```

持久化存储会保存：
- 团队信息
- 已吊销的 Token 黑名单

### 检查器 API（客户端）

```bash
# 列出捕获的请求
curl http://localhost:4040/api/requests

# 获取请求详情
curl http://localhost:4040/api/requests/:id

# 清空所有记录
curl -X DELETE http://localhost:4040/api/requests

# 实时流（WebSocket）
wscat -c ws://localhost:4040/api/ws
```

## 开发

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/lucientong/wormhole.git
cd wormhole

# 构建
make build

# 运行测试
make test

# 代码覆盖率
make test-coverage

# Lint 检查（需要 golangci-lint）
golangci-lint run ./...
```

### 项目结构

```
wormhole/
├── cmd/
│   ├── wormhole/     # CLI 入口
│   ├── server/       # 服务端实现
│   └── client/       # 客户端实现
├── pkg/
│   ├── tunnel/       # 核心隧道（多路复用器、帧编解码、流、连接池）
│   ├── inspector/    # 流量检查（捕获、存储、WebSocket）
│   ├── p2p/          # P2P 直连（STUN、打洞、端口预测）
│   ├── proto/        # 控制协议（JSON 消息）
│   ├── auth/         # 认证授权（HMAC Token、角色、权限）
│   ├── version/      # 构建版本信息
│   └── web/          # 嵌入式 Web UI
├── web/              # 前端源码（SolidJS）
├── docs/             # 架构文档
├── deployments/      # Docker、systemd 配置
└── scripts/          # 构建和安装脚本
```

## 安全

Wormhole 在设计时充分考虑了安全性，但作为一个将本地服务暴露到公网的隧道工具，正确的配置至关重要。

### 安全特性

| 特性 | 说明 |
|------|------|
| **TLS 加密** | 所有 HTTP 流量通过 TLS 1.2+ 加密，支持 Let's Encrypt 自动证书 |
| **P2P 端到端加密** | X25519 ECDH 密钥交换 + AES-256-GCM 认证加密，保护 P2P 直连数据 |
| **HMAC-SHA256 Token** | 签名的团队 Token，支持过期和吊销 |
| **RBAC 权限控制** | 基于角色的访问控制（admin / member / viewer） |
| **速率限制** | 认证失败后自动封锁 IP |
| **Token 吊销** | 支持将已泄露的 Token 加入黑名单，配合持久化存储 |
| **常量时间比较** | Admin Token 使用 `crypto/subtle` 比较，防止时序攻击 |
| **请求限制** | MaxHeaderBytes 和请求体大小限制，缓解 DoS 攻击 |

### 生产环境部署清单

> ⚠️ **请勿在生产环境中使用默认配置。** 按照以下清单加固你的部署。

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

- [ ] **启用 TLS**（`--tls`）：不启用 TLS 时，所有流量（包括认证 Token）都是明文传输。生产环境必须启用 TLS。
- [ ] **启用认证**（`--require-auth`）：不启用认证时，任何人都可以在你的服务器上创建隧道。
- [ ] **设置强密钥**（`--auth-secret`）：使用至少 32 个随机字符。该密钥用于签名所有团队 Token。
- [ ] **保护管理 API**（`--admin-token`）：不设置时，任何能访问管理端口的人都可以管理你的服务器。
- [ ] **使用持久化存储**（`--persistence sqlite`）：确保 Token 吊销记录在服务器重启后不会丢失。
- [ ] **限制管理端口访问**：将管理端口绑定到 localhost 或配合防火墙规则（如 `--admin-port 127.0.0.1:7001`）。

### 安全注意事项

#### P2P 模式

P2P 直连使用**端到端加密**，基于 X25519 ECDH 密钥交换和 AES-256-GCM 认证加密。密钥交换通过服务器的信令通道完成，但服务器无法获知共享密钥——仅中继公钥。加密方案包括：

- **X25519 ECDH** 密钥协商，每次会话独立的前向安全
- **AES-256-GCM** 认证加密，保护所有数据包的机密性和完整性
- **HMAC-SHA256** 认证打洞探测包，防止注入攻击
- **HKDF-SHA256** 密钥派生，加密密钥和探测认证密钥分离

如果 P2P 打洞失败，客户端会自动降级到加密的中继通道：

```bash
# 禁用 P2P，强制所有流量走加密的中继通道
wormhole client --local 8080 --p2p=false
```

#### 流量检查器

流量检查器会捕获并展示 HTTP 请求/响应数据。在生产环境中：

- **不要在面向公网的部署中启用检查器**
- 检查器 API 默认绑定到 localhost，但要注意局域网内的访问风险

#### 未配置 Token 的管理 API

如果未配置 `--admin-token`，管理 API **完全开放**，无任何认证。这意味着任何能访问管理端口的人可以：
- 查看所有已连接的客户端和隧道
- 生成和吊销 Token
- 管理团队

生产环境请务必配置 `--admin-token`。

#### 子域名随机性

自动生成的子域名使用 64 位加密随机数（`crypto/rand`），产生 16 字符的十六进制字符串，使暴力猜测子域名在计算上不可行。

## 路线图

- [x] Phase 1：基础 TCP 隧道 + 多路复用
- [x] Phase 2：HTTP 路由 + TLS + 管理 API
- [x] Phase 3：流量检查器 UI
- [x] Phase 4：P2P 直连 — 基础原语（STUN、打洞、端口预测、信令）
- [x] Phase 4.5：P2P 端到端集成（peer 匹配、数据传输、Relay→P2P 切换）
- [x] Phase 5：团队协作（认证、HMAC Token、角色权限、Admin API 保护）
- [x] Phase 6：P2P 端到端加密（X25519 ECDH、AES-256-GCM、HMAC 认证打洞）

## 贡献

欢迎贡献！请阅读 [贡献指南](CONTRIBUTING.md) 了解详情。

## 许可证

Apache License — 详见 [LICENSE](LICENSE)。
