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
- 🤝 **P2P 直连** — NAT 穿透与点对点直连，端到端加密（X25519 + AES-256-GCM），IPv4/IPv6 双栈
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

# client 间直连（完全绕过中继）：peer A 正常暴露服务，peer B 通过对方的
# 子域名直接打洞连过去，全程走加密 UDP 通道——server 只做信令，不转发流量
wormhole client --local 8080 --subdomain peer-a   # 在 peer A 上执行
wormhole connect peer-a --local 9090               # 在 peer B 上执行
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
| `--inspector-host` | 检查器 UI 绑定地址 | `127.0.0.1` |
| `--p2p` | 启用 P2P 直连 | true |
| `--tls` | 启用 TLS 连接 | false |
| `--tls-insecure` | 跳过 TLS 证书验证（仅开发环境） | false |
| `--tls-ca` | 自定义 CA 证书路径 | 无 |
| `--protocol` / `-P` | 隧道协议：http、https、tcp、udp、ws、grpc | `http` |
| `--hostname` | 自定义域名路由 | 无 |
| `--path-prefix` | 路径前缀路由 | 无 |

### `wormhole connect` 选项

`wormhole connect <对方子域名>` 直接通过 P2P 连接另一个 `wormhole client` 暴露的服务，完全绕过服务器中继。它不会像 `wormhole client` 那样注册自己的隧道，只是打开一个本地监听，把接受到的连接直接转发给对端（经过打洞后的加密 UDP 通道）。由于该模式没有中继兜底，一旦打洞失败（例如双方 NAT 类型不兼容），命令会直接失败退出。

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--server` / `-s` | 要连接的服务器地址 | `localhost:7000` |
| `--local` / `-l` | 本地监听端口（必填） | 无 |
| `--local-host` | 本地监听绑定地址 | `127.0.0.1` |
| `--token` / `-t` | 认证 Token | 无 |
| `--tls` | 对服务器控制连接启用 TLS | false |
| `--tls-insecure` | 跳过 TLS 证书验证（仅开发环境） | false |
| `--tls-ca` | 自定义 CA 证书路径 | 无 |

### 服务器选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--port` | 隧道监听端口 | `7000` |
| `--host` | 绑定地址 | `0.0.0.0` |
| `--http-port` | HTTP 流量端口 | `80` |
| `--admin-port` | 管理 API 端口 | `7001` |
| `--admin-host` | 管理 API 绑定地址（安全：默认仅监听本地） | `127.0.0.1` |
| `--domain` | 隧道 URL 域名（环境变量：`WORMHOLE_DOMAIN`） | `localhost` |
| `--tls` | 启用 TLS（设置域名时自动申请证书） | false |
| `--tunnel-tls` | 隧道控制链路 TLS（默认跟随 `--tls`） | 同 `--tls` |
| `--cert` | TLS 证书文件路径 | 无 |
| `--key` | TLS 私钥文件路径 | 无 |
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
# 列出捕获的记录
curl http://localhost:4040/api/inspector/records

# 获取记录详情
curl http://localhost:4040/api/inspector/records/:id

# 获取检查器统计
curl http://localhost:4040/api/inspector/stats

# 清空所有记录
curl -X POST http://localhost:4040/api/inspector/clear

# 切换捕获开关
curl -X POST http://localhost:4040/api/inspector/toggle

# 实时流（WebSocket）
wscat -c ws://localhost:4040/api/inspector/ws
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
│   ├── wormhole/     # CLI 入口（Cobra）
│   ├── server/       # 独立服务端入口（薄包装层）
│   └── client/       # 独立客户端入口（薄包装层）
├── pkg/
│   ├── client/       # 客户端核心（配置、连接、持久化）
│   ├── server/       # 服务端核心（配置、路由、处理器、TLS、管理 API）
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
| **TLS 加密** | HTTP 监听和隧道控制通道通过 TLS 1.2+ 加密，支持 Let's Encrypt 自动证书或手动证书；客户端支持 `--tls` / `--tls-insecure` / `--tls-ca` |
| **P2P 端到端加密** | X25519 ECDH 密钥交换 + AES-256-GCM 认证加密，保护 P2P 直连数据 |
| **HMAC-SHA256 Token** | 签名的团队 Token，支持过期和吊销 |
| **RBAC 权限控制** | 基于角色的访问控制（admin / member / viewer） |
| **速率限制** | 认证失败后自动封锁 IP |
| **Token 吊销** | 支持单个 Token 黑名单 + 团队级批量吊销（基于版本号），配合持久化存储 |
| **常量时间比较** | Admin Token 使用 `crypto/subtle` 比较，防止时序攻击 |
| **请求限制** | MaxHeaderBytes 和请求体大小限制，缓解 DoS 攻击 |

### 生产环境部署清单

> ⚠️ **请勿在生产环境中使用默认配置。** 按照以下清单加固你的部署。

```bash
wormhole server \
  --domain tunnel.example.com \
  --tls \
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
- [ ] **限制管理端口访问**：Admin 默认绑定 `127.0.0.1`。如需远程访问，使用 `--admin-host 0.0.0.0 --admin-token <token>`。

### 安全注意事项

#### P2P 模式

P2P 直连使用**端到端加密**，基于 X25519 ECDH 密钥交换和 AES-256-GCM 认证加密。密钥交换通过服务器的信令通道完成，但服务器无法获知共享密钥——仅中继公钥。加密方案包括：

- **X25519 ECDH** 密钥协商，每次会话独立的前向安全
- **AES-256-GCM** 认证加密，保护所有数据包的机密性和完整性
- **HMAC-SHA256** 认证打洞探测包，防止注入攻击
- **HKDF-SHA256** 密钥派生，加密密钥和探测认证密钥分离

**两种 P2P 场景，两条不同的流量路径。** 公网访客（浏览器、curl 等普通 HTTP 客户端）访问你的隧道 hostname 时永远无法打洞——服务器物理上不可能替一个任意的 HTTP 客户端做 NAT 穿透——所以这条流量始终走加密中继。P2P 真正加速的是 **`wormhole connect`**：当对端也是一个 `wormhole client` 时，双方打洞成功后所有数据全程走端到端加密的 UDP 直连通道，服务器只用于信令（不会看到任何一个字节的隧道流量）。如果打洞失败或 P2P 通道之后中断，`wormhole connect` 会直接关闭本地监听，而不是悄悄降级到中继——connect 模式没有中继兜底路径（服务器从未为这类会话注册过隧道），所以 P2P 路径丢失就意味着连接真的断了，需要重试。

`wormhole connect` 与 P2P 加速数据面底层共用的可靠 UDP 传输（`UDPMux` + `UDPStream`）采用 RFC 6298 风格的自适应重传（SRTT/RTTVAR/RTO 估算 + 按段指数退避），替代固定超时时间，在真实网络抖动和丢包下吞吐能平滑退化，不会因固定超时过短而过度重传、也不会因固定超时过长而恢复迟缓。

```bash
# 禁用 P2P，强制所有流量走加密的中继通道
wormhole client --local 8080 --p2p=false

# 直接连接另一个 client，设计上没有中继兜底
wormhole connect <对方子域名> --local 9090
```

#### 流量检查器

流量检查器会捕获并展示 HTTP 请求/响应数据。在生产环境中：

- **不要在面向公网的部署中启用检查器**
- 检查器默认绑定到 **`127.0.0.1`** — 使用 `--inspector-host 0.0.0.0` 允许外部访问（不推荐）
- CORS 默认限制为 localhost 来源

#### 未配置 Token 的管理 API

如果未配置 `--admin-token`，管理 API **仅允许回环地址**（`127.0.0.1` / `::1`）发起的请求。非回环请求将被拒绝并返回 403 错误。这意味着：
- 本地访问（如 `curl http://localhost:7001/stats`）无需 Token 即可使用
- 远程访问需要配置 `--admin-token`

Admin API 默认绑定 `127.0.0.1`。如需远程访问，使用 `--admin-host 0.0.0.0 --admin-token <token>`。

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
- [x] Phase 7：控制协议迁移到 Protobuf + 可靠 UDP 传输（UDPMux + UDPStream + ARQ）
- [x] Phase 8（v0.5.1）：审计日志增强 — 新增事件类型、SQLite 持久化、Admin 查询/导出 API
- [x] Phase 9（v0.5.2）：声明式隧道配置 — YAML 配置文件、多隧道、SIGHUP 热重载、`tunnels` 子命令
- [x] Phase 10（v0.5.3）：OIDC / OAuth SSO — OIDC Discovery、JWKS JWT 校验、Device Code Flow、`wormhole login`
- [x] Phase 11（v0.6.0）：HA / 多节点控制面 — `StateStore` 接口、Redis 后端、集群心跳、跨节点 HTTP 路由
- [x] Phase 12（v0.6.1）：可靠的连接丢失检测（`Mux.CloseNotify()` + 心跳触发强制重连）、真正生效的多隧道路由（`TunnelID` 端到端接线分发）、修复 P2P 信令帧不匹配、P2P 接收缓冲背压（带超时的阻塞交付 + 消费者卡死时 RST）、TCP 端口分配失败拒绝注册、可靠的 P2P 建流握手（SYN 重传 + SYN-ACK，此前只要一个 SYN 包在丢包环境下丢失，连接就会悄无声息地"半开"卡死）、修复 WebSocket inspector 的数据竞争
- [x] Phase 13（v0.6.1）：端到端 SSO 可用——`wormhole login` 保存的凭证现在会被 `wormhole client` 自动加载（无需再手动 `--token`/`jq`），access token 过期后通过 `refresh_token` 静默续期（包括会话中途、断线重连场景），device flow 轮询请求补齐 `client_id`（符合 RFC 8628），`wormhole client` 未传 `--local`/`--config` 时会回退到 `~/.wormhole/wormhole.yml`
- [x] Phase 14（v0.6.2）：P2P 数据面接入与传输优化——新增 `wormhole connect <子域名>` 命令，两个 `wormhole client` 打洞后流量全程 P2P 直连（server 只做信令，不转发一个字节）；`UDPStream` 从固定 200ms 重传升级为 RFC 6298 风格自适应 RTO + 按段指数退避；发送/接收路径降拷贝（加密直写目标 buffer、消除冗余拷贝）；删除已被 `UDPMux`/`UDPStream` 取代的 `pkg/p2p/transport.go` 旧 ARQ 实现

## 贡献

欢迎贡献！

## 许可证

Apache License — 详见 [LICENSE](LICENSE)。
