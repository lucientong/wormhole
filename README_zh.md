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
- 🤝 **P2P 直连** — NAT 穿透与点对点直连，端到端加密（X25519 + AES-256-GCM），IPv4/IPv6 双栈；`wormhole connect` 让两个客户端全程走 P2P 交换真实流量，完全绕开服务端中转
- 🔑 **认证与权限** — HMAC-SHA256 团队 Token + 角色权限控制（Admin/Member/Viewer）
- 🪪 **SSO / OIDC** — OAuth2 设备码流程 + OIDC JWT 校验；`wormhole login` 支持命令行式 SSO 登录
- 📋 **审计日志** — 结构化审计事件日志，支持 SQLite 持久化及 CSV/JSON 导出 API
- 📁 **声明式配置** — YAML 配置文件、多隧道、SIGHUP 热重载、`wormhole tunnels list`
- 🏗️ **HA / 多节点** — 可插拔的 `StateStore`，支持 Redis 后端；跨节点 HTTP/hostname/path 路由、TTL 自动刷新的心跳、集群共享密钥、跨节点 token 吊销
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
- **P2P 直连**：基于 STUN 的 NAT 发现（IPv4/IPv6 双栈）+ UDP 打洞实现直连，自动降级到中继模式
- **认证授权**：HMAC-SHA256 签名 Token + 角色权限控制（admin/member/viewer），支持预共享 Token 快速接入
- **OIDC/SSO**：OIDC Discovery + JWKS JWT 校验；OAuth2 设备码流程支持命令行登录；凭证持久化到 `~/.wormhole/credentials.json`
- **审计日志**：结构化事件（认证、隧道、P2P）存储在内存（环形缓冲）或 SQLite；通过 Admin API 查询，支持 CSV/JSON 导出
- **多隧道配置**：YAML 配置文件定义多个隧道（客户端和服务端均支持，通过 `--config`/`-c`）；SIGHUP 触发差量热重载；本地控制 API（`--ctrl-port`）支持 `wormhole tunnels list/create/delete`——无需重启即可给运行中的 client 增删隧道
- **HA / 多节点**：可插拔的 `StateStore` 接口；内存（单节点）或 Redis 后端；集群心跳周期刷新每条路由的 TTL，子域名/hostname/path 路由均可跨节点索引；跨节点代理通过 `httputil.ReverseProxy` 转发，并附带 `--cluster-secret` 校验；TCP 隧道在 HA 下仅限节点本地（详见[架构文档](docs/architecture_zh.md#ha--多节点控制面)）
- **资源上限与版本协商**：`--max-concurrent-streams`/`--max-streams-per-client` 限制并发数据流数量（全局 + 单客户端），防止负载过高时资源被打爆；`--min-client-version` 拒绝低于指定语义化版本的 client；server 在鉴权阶段广播真实能力集（`p2p`/`multi-tunnel`/`cluster`/`audit` 等），client 据此决定是否尝试可选行为（例如是否发送 P2P offer），而不是盲目假设对端支持
- **热路径分配池化**：隧道多路复用器的数据发送路径，以及每一条双向代理循环（HTTP 响应体、WebSocket、TCP 隧道、`wormhole connect`）都复用池化的临时缓冲区，而不是每次写入/每条连接都重新分配，在压测中明显降低了单次操作的分配量（具体基准数据见[架构文档](docs/architecture_zh.md#热路径分配池化-p3-6-批次-b)）
- **感知 ctx 取消的优雅关闭**：服务端根生命周期 context 在 `Shutdown()` 的第一步就被取消，因此阻塞在调用树深处（认证握手、TCP 端口分配、P2P 对端通知）的操作会立即响应，不再需要等自身的固定超时；`tunnel.Stream` 新增可取消的 `ReadContext`/`WriteContext`，服务端和客户端的每一个控制面 RPC（认证、注册、心跳、统计、关闭、P2P offer/result）都统一使用它们，纯 `Read`/`Write` 数据面热路径不会有任何额外开销（详见[架构文档](docs/architecture_zh.md#context-贯通-p3-6-批次-c)）

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

### 服务器配置文件

除了长长的命令行参数，服务器也可以从 YAML 文件加载配置（`--config` / `-c`），风格与客户端的 `--config` 文件一致：

```yaml
# server.yml
listen_addr: :7000
http_addr: :80
admin_addr: 127.0.0.1:7001
domain: tunnel.example.com

tls:
  enabled: true

require_auth: true
auth_secret: my-secret-key-at-least-16-chars
min_client_version: 0.6.0

max_concurrent_streams: 10000
max_streams_per_client: 500

persistence:
  type: sqlite

audit:
  enabled: true
  retention_days: 90
```

```bash
wormhole server -c server.yml
```

只有文件中出现的字段才会覆盖默认值——省略的字段保持对应命令行参数的默认行为，所以一个只写 `domain:` 的最小文件也是合法的。

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
| `--protocol` / `-P` | 隧道协议：http、https、tcp、ws、grpc（udp 会被拒绝——服务端尚未实现 UDP 数据面） | `http` |
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
| `--config` / `-c` | YAML 服务器配置文件路径；文件中明确设置的字段会覆盖下方的命令行默认值（见[示例](#服务器配置文件)） | 无 |
| `--port` | 隧道监听端口 | `7000` |
| `--host` | 绑定地址 | `0.0.0.0` |
| `--http-port` | HTTP 流量端口 | `80` |
| `--admin-port` | 管理 API 端口 | `7001` |
| `--admin-host` | 管理 API 绑定地址（安全：默认仅监听本地） | `127.0.0.1` |
| `--domain` | 隧道 URL 域名（环境变量：`WORMHOLE_DOMAIN`） | `localhost` |
| `--max-concurrent-streams` | 所有客户端合计的最大并发数据流数；超出上限会拒绝新流而非排队等待（0 = 不限制） | `10000` |
| `--max-streams-per-client` | 单个客户端的最大并发数据流数，独立于上面的全局上限（0 = 不限制） | `500` |
| `--min-client-version` | 拒绝声明版本低于此值的 client，例如 `0.6.0`；版本号不是标准 semver 的 client（如 dev 构建）永远不会被拒绝 | （禁用） |
| `--tls` | 启用 TLS（设置域名时自动申请证书） | false |
| `--tunnel-tls` | 隧道控制链路 TLS（默认跟随 `--tls`；**当 `--require-auth` 且配置了真实 `--domain` 时也默认开启**，见 [安全](#安全)） | 见说明 |
| `--cert` | TLS 证书文件路径 | 无 |
| `--key` | TLS 私钥文件路径 | 无 |
| `--require-auth` | 要求客户端认证 | false |
| `--auth-tokens` | 预共享 Token 列表（逗号分隔） | 无 |
| `--auth-secret` | HMAC 签名密钥（至少 16 字符） | 无 |
| `--admin-token` | 管理 API 访问 Token | 无 |
| `--persistence` | 存储后端：memory（默认）、sqlite 或 redis | memory |
| `--persistence-path` | SQLite 数据库路径 | ~/.wormhole/wormhole.db |
| `--audit` | 启用结构化审计日志 | false |
| `--audit-persistence` | 审计存储后端：memory 或 sqlite | memory |
| `--audit-path` | SQLite 审计数据库路径 | ~/.wormhole/audit.db |
| `--audit-buffer-size` | 内存审计环形缓冲区大小（事件数） | 10000 |
| `--audit-retention-days` | 审计事件保留天数，超过则清理（0 = 永久保留） | 90 |
| `--oidc-issuer` | 用于 JWT 验证的 OIDC issuer URL | 无 |
| `--oidc-client-id` | 用于 OIDC audience 校验的 OAuth2 client ID | 无 |
| `--oidc-team-claim` | 用作团队名的 JWT claim | `email` |
| `--oidc-role-claim` | 用作 Wormhole 角色的 JWT claim | 无 |
| `--cluster-backend` | 集群状态后端：memory 或 redis | （禁用） |
| `--cluster-node-id` | 本节点在集群中的唯一 ID | `os.Hostname()` |
| `--cluster-node-addr` | 其他节点访问本节点的地址 | 无 |
| `--cluster-redis-addr` | 集群状态使用的 Redis 地址 | 无 |
| `--cluster-redis-password` | Redis AUTH 密码 | 无 |
| `--cluster-redis-db` | Redis 数据库编号 | 0 |
| `--cluster-secret` | 节点间代理请求校验用的共享密钥（`X-Wormhole-Cluster-Secret`） | 无 |
| `--auth-redis-addr` | 鉴权/团队/吊销状态使用的 Redis 地址（`--persistence redis`）；未设置时回退到 `--cluster-redis-addr` | 无 |
| `--auth-redis-password` | 鉴权存储的 Redis AUTH 密码；未设置时回退到 `--cluster-redis-password` | 无 |
| `--auth-redis-db` | 鉴权存储的 Redis 数据库编号；未设置时回退到 `--cluster-redis-db` | 0 |

## API

### 管理 API（服务器端）

```bash
# 健康检查（始终公开）
curl http://localhost:7001/health

# 统计信息（配置 --admin-token 后需携带 Token）
curl -H "Authorization: Bearer <admin-token>" http://localhost:7001/stats

# 已连接的客户端
curl -H "Authorization: Bearer <admin-token>" http://localhost:7001/clients

# 查询审计日志（JSON，支持按类型/起止时间/条数过滤）
curl -H "Authorization: Bearer <admin-token>" \
  "http://localhost:7001/audit?type=auth_failure&limit=50"

# 将审计日志导出为 CSV
curl -H "Authorization: Bearer <admin-token>" \
  "http://localhost:7001/audit/export?format=csv" -o audit.csv
```

### 客户端控制 API

设置 `--ctrl-port` 后，本地 HTTP 控制服务会暴露隧道状态：

```bash
# 启动客户端并在 7100 端口开启控制 API
wormhole client --local 8080 --ctrl-port 7100

# 或使用配置文件
wormhole client --config ~/.wormhole/tunnels.yaml --ctrl-port 7100

# 列出活跃隧道
wormhole tunnels list --ctrl-port 7100
# 或直接：
curl http://localhost:7100/tunnels

# 无需重启即可给运行中的 client 动态新增一条隧道
wormhole tunnels create db --local 5432 --protocol tcp --ctrl-port 7100
# 或直接：
curl -X POST http://localhost:7100/tunnels \
  -d '{"name":"db","local_port":5432,"protocol":"tcp"}'

# 从运行中的 client 删除一条隧道
wormhole tunnels delete db --ctrl-port 7100
# 或直接：
curl -X DELETE http://localhost:7100/tunnels/db
```

### 认证

Wormhole 支持三种认证模式：

```bash
# 简单预共享 Token 模式
wormhole server --require-auth --auth-tokens token1,token2
wormhole client --server example.com:7000 --local 8080 --token token1

# HMAC-SHA256 签名 Token 模式（团队管理）
wormhole server --require-auth --auth-secret "my-secret-at-least-16-chars"

# OIDC / SSO（例如 Google、Okta、Auth0）
wormhole server --require-auth \
  --oidc-issuer https://accounts.google.com \
  --oidc-client-id <your-client-id>

# 使用独立 Token 保护管理 API
wormhole server --admin-token my-admin-secret
```

### SSO 登录（OIDC 设备码流程）

```bash
# 通过身份提供商登录——终端会打印浏览器登录 URL，登录成功后 Token 保存到本地
wormhole login \
  --issuer https://accounts.google.com \
  --client-id <client-id> \
  --server tunnel.example.com:7000

# 之后运行 client 命令会自动使用已保存的 Token
wormhole client --server tunnel.example.com:7000 --local 8080
```

### 多隧道配置文件

创建 `~/.wormhole/tunnels.yaml`：

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
# 根据配置文件启动所有隧道
wormhole client --config ~/.wormhole/tunnels.yaml --ctrl-port 7100

# 无需重启即可热重载隧道（在 YAML 中增删隧道后执行）：
kill -HUP <wormhole-pid>

# 列出正在运行的隧道
wormhole tunnels list
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

# Redis 后端持久化：在 HA 节点之间共享团队/吊销状态
# （见下方"高可用 / 多节点"）；若未单独设置 --auth-redis-addr，
# 会回退使用 --cluster-redis-addr
wormhole server --require-auth --auth-secret "my-secret" \
  --persistence redis \
  --auth-redis-addr redis.internal:6379
```

持久化存储会保存：
- 团队信息
- 已吊销的 Token 黑名单（Redis 模式下吊销记录通过 TTL 自动过期，无需清理任务）

### 审计日志

```bash
# 启用内存审计日志（环形缓冲区，10000 条事件）
wormhole server --audit

# 启用 SQLite 持久化审计日志
wormhole server --audit --audit-persistence sqlite --audit-path /var/log/wormhole/audit.db

# 查询最近的认证失败事件
curl -H "Authorization: Bearer <token>" \
  "http://localhost:7001/audit?type=auth_failure&limit=20"

# 将完整审计日志导出为 CSV
curl -H "Authorization: Bearer <token>" \
  "http://localhost:7001/audit/export?format=csv" -o audit.csv
```

### 高可用 / 多节点

```bash
# 节点 1
wormhole server \
  --cluster-backend redis \
  --cluster-redis-addr redis.internal:6379 \
  --cluster-secret "$(openssl rand -hex 32)" \
  --persistence redis \
  --domain tunnel.example.com \
  --cluster-node-addr 10.0.0.1:7000

# 节点 2（同一个 Redis + 集群密钥，NodeID 未设置时默认取 os.Hostname()）
wormhole server \
  --cluster-backend redis \
  --cluster-redis-addr redis.internal:6379 \
  --cluster-secret "$(openssl rand -hex 32)" \
  --persistence redis \
  --domain tunnel.example.com \
  --cluster-node-addr 10.0.0.2:7000
```

每个节点会：
- `--cluster-node-id` 未设置时默认取本机主机名，避免多个节点意外共用空字符串 ID
- 每 30 秒向 Redis 发送一次心跳，并在同一周期内重新注册（刷新 TTL）它当前持有的每一条路由——子域名、hostname、path 前缀均一视同仁——确保长连接的隧道不会从共享状态存储中静默过期
- 在 Redis 中查找未知的子域名/hostname/path，并通过 `httputil.ReverseProxy` 将 HTTP 请求代理给真正持有该路由的节点，转发时附带 `--cluster-secret` 头，拒绝伪造的节点间代理流量
- 配置了 `--persistence redis` 后，在某一节点吊销 Token 或更新团队信息会立即对所有其他节点可见（没有传播延迟）；若未单独设置 `--auth-redis-*`，会回退使用 `--cluster-redis-addr`/`--cluster-redis-password`/`--cluster-redis-db`
- 在 `GET /health` 中暴露 Redis 连接状态（`cluster.state_store_healthy`）；状态存储不可达时整体状态会降级为 `"degraded"`
- 重连时，如果原持有者的会话已经失效（mux 已关闭），会立即回收对应的子域名/hostname/path，而不是返回一次虚假的冲突错误
- 客户端断开连接时清理其在 Redis 中的路由
- **TCP 隧道仅限节点本地**：TCP 隧道只能通过客户端当前连接的那个节点访问（不像 HTTP/WebSocket 那样支持跨节点代理）——如果需要 TCP 隧道的 HA 能力，请在各节点地址/端口前面自行部署支持 TCP 的负载均衡器（例如 HAProxy 的 `mode tcp`）

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
│   ├── tunnel/       # 核心隧道（多路复用器、帧编解码、流）
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
| **OIDC / SSO** | OIDC Discovery + JWKS JWT 验证；基于 claim 的团队/角色映射；不存储任何密码 |
| **RBAC 权限控制** | 基于角色的访问控制（admin / member / viewer）；写操作（注册/关闭隧道）要求 `PermissionWrite`——`viewer` Token 在服务端直接被拒绝，而不只是前端隐藏入口 |
| **速率限制** | 认证失败后自动封锁 IP |
| **Token 吊销** | 支持单个 Token 黑名单 + 团队级批量吊销（基于版本号），配合持久化存储 |
| **常量时间比较** | Admin Token 使用 `crypto/subtle` 比较，防止时序攻击 |
| **请求限制** | MaxHeaderBytes 和请求体大小限制，缓解 DoS 攻击 |
| **审计日志** | 不可篡改的结构化事件日志（认证/隧道/P2P），支持 SQLite 持久化、Admin API 导出，以及可配置的保留期清理（`--audit-retention-days`，默认 90 天） |
| **Metrics 保护** | `/metrics` 与其余管理 API 共用同一套认证机制，绝不会未授权对外暴露 |
| **子域名原子申请** | 子域名申请是原子操作（本地 map / Redis `SETNX`）；与存活所有者的真实冲突会拒绝新连接，而不是悄悄覆盖已有路由 |
| **集群共享密钥** | `--cluster-secret` 校验节点间代理请求（`X-Wormhole-Cluster-Secret`），防止伪造的节点间流量注入 |
| **跨节点吊销共享** | `--persistence redis` 让团队信息和 Token 吊销黑名单在所有节点间共享、即时可见，无跨节点传播延迟 |

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
  --persistence-path /var/lib/wormhole/wormhole.db \
  --audit \
  --audit-persistence sqlite
```

- [ ] **启用 TLS**（`--tls`）：不启用 TLS 时，所有流量（包括认证 Token）都是明文传输。生产环境必须启用 TLS。
- [ ] **启用认证**（`--require-auth`）：不启用认证时，任何人都可以在你的服务器上创建隧道。
- [ ] **设置强密钥**（`--auth-secret`）：使用至少 32 个随机字符。该密钥用于签名所有团队 Token。
- [ ] **保护管理 API**（`--admin-token`）：不设置时，任何能访问管理端口的人都可以管理你的服务器。
- [ ] **使用持久化存储**（`--persistence sqlite`）：确保 Token 吊销记录在服务器重启后不会丢失。
- [ ] **启用审计日志**（`--audit --audit-persistence sqlite`）：保留认证事件和隧道生命周期的不可篡改记录。
- [ ] **限制管理端口访问**：Admin 默认绑定 `127.0.0.1`。如需远程访问，使用 `--admin-host 0.0.0.0 --admin-token <token>`。

### 安全注意事项

#### 隧道控制链路 TLS

`--tunnel-tls` 控制隧道**控制链路**（认证 Token 经过的通道）的 TLS，与控制 HTTP 数据面的 `--tls` 相互独立。若不显式传 `--tunnel-tls`，其默认值跟随 `--tls`——**并且，只要同时设置了 `--require-auth` 和真实的 `--domain`，也会默认开启**：要求认证却不加密承载这些 Token 的通道是自相矛盾的。如果开启了认证但既没有可用域名也没有证书来源，服务器会打印明显的告警后继续以明文启动；但如果证书*配置本身*有误（例如证书路径写错），服务器会直接启动失败，而不是悄悄退回明文。

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
- 无论上述配置如何，敏感请求头（`Authorization`、`Cookie`、`Set-Cookie`、`Proxy-Authorization`、`X-Api-Key` 等）在捕获的请求/响应中都会被脱敏打码，单条记录的默认正文捕获上限为 256KB

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
- [x] Phase 15（v0.6.3）：安全加固——RBAC 写权限检查（viewer 不能再注册/关闭隧道）；隧道控制链路 TLS 与 HTTP 数据面 TLS 解耦，`--require-auth` 配合真实域名时默认开启（配置错误时启动失败而非静默明文）；子域名注册改为原子的、集群一致的申请（本地 + Redis `SETNX`），真实冲突拒绝新连接而非悄悄覆盖已有路由；修复 token 过期计算的数据竞争，补齐吊销黑名单的周期清理调度；OIDC 显式拒绝 `alg: none` 并校验 `nbf`（带时钟容差）；Inspector 默认对敏感请求头脱敏，并下调默认正文捕获上限；`/metrics` 现在需要管理员认证；审计日志补齐认证成功/IP 封禁/Token 生成/IP 解封事件，并支持可配置的保留期清理（`--audit-retention-days`），同时在 `/stats` 新增 `audit_store_errors` 计数，使审计持久化失败不再无声无息
- [x] Phase 16（v0.6.4）：HA 二期——集群心跳每轮同时重新注册（刷新 TTL）该节点持有的每一条路由，修复长连接下路由从 Redis 静默过期的问题；hostname/path 前缀路由现已索引进 Redis，可跨节点访问，不再局限于子域名；`ClusterNodeID` 未设置时默认取 `os.Hostname()`；新增 `--cluster-secret` 校验节点间代理请求；新增 `--persistence redis`（`auth.RedisStore`），团队/Token 吊销状态跨节点共享、即时失效；Redis 后端存储全面把 `KEYS` 替换为 `SCAN`；`/health` 新增 Redis 连接状态（`cluster.state_store_healthy`，不可达时整体状态降级）；客户端重连时立即回收陈旧持有者的子域名/hostname/path，不再遇到虚假冲突；文档明确 TCP 隧道在 HA 下仅节点本地可达（不支持跨节点 TCP 代理）
- [x] Phase 17（v0.6.5）：架构重构批次 A（正确性收尾 + 死代码清理）——HTTP/管理监听改为带超时的 `Shutdown(ctx)` 优雅关闭，而非进程直接退出；双向代理（WebSocket/TCP）任一方向出错即触发双侧收尾，不再需要等对端超时才释放连接；新增 `--max-concurrent-streams`/`--max-streams-per-client`，超出上限直接拒绝新流而非无限排队；`DecodeControlMessage` 拒绝畸形的 `UNKNOWN` 类型空控制帧，同时继续放行携带 payload 的、面向未来兼容的未知类型；新增 `--min-client-version` 语义化版本门禁，以及服务端真实能力集广播（`p2p`/`multi-tunnel`/`cluster`/`audit`），client 不再盲目假设可选特性一定存在；删除从未接线的 `tunnel.Pool` 死代码；`--protocol` 可选值中移除 udp（服务端从未实现 UDP 数据面），现在会显式报错而非静默降级；新增 `wormhole tunnels create/delete`，支持给运行中的 client 命令式增删隧道；新增 `wormhole server -c server.yml`，服务端配置文件支持与客户端保持一致
- [x] Phase 18（v0.6.6）：架构重构批次 B（热路径性能）——`Mux.sendData` 现在复用一个池化的 32KB payload 缓冲区，替代每次 `Stream.Write` 都 `make+copy`（隔离基准测试显示单次发送内存占用降低 99.7%，吞吐 +72%）；服务端 HTTP 响应体/WebSocket/TCP 隧道转发与客户端转发（包括 `wormhole connect`）统一由裸 `io.Copy` 改为池化的 `io.CopyBuffer`，隔离基准测试显示单次拷贝内存占用降低 88.5%，此前被吞掉的拷贝错误现在会以 debug 级别记录；修复了 Inspector 的 OOM 风险——`forwardHTTPWithInspect` 此前读取请求/响应正文时没有任何大小上限（尽管代码注释声称有），现已用 `io.LimitReader(body, MaxBodySize+1)` 限定，与 `Inspector.Wrap` 已有的截断取舍保持一致
- [x] Phase 19（v0.6.7）：架构重构批次 C（context 贯通）——`Server` 在 `Start(ctx)` 中派生出 `rootCtx`/`rootCancel`，并在 `Shutdown()` 的第一步取消它，因此服务端调用树深处此前硬编码 `context.Background()` 的 4 个位置（认证握手接受、TCP 端口分配、P2P 对端通知、TCP 隧道流打开）在关闭时会立即响应取消，不再需要等自身的固定超时（如 `AuthTimeout`）才返回；`tunnel.Stream` 新增 `ReadContext`/`WriteContext`，持有可取消 ctx 的调用方现在能中断正在阻塞的 `Read`/`Write`——`Read`/`Write` 仍以 `context.Background()` 委托给它们，因此数据面热路径（`io.Copy` 等）不会有任何额外开销，因为永远不会触发的 ctx 不会启动 watcher goroutine；同样的修复也应用到了客户端 14 处存在相同缺口的控制面 RPC（认证、注册、心跳、统计、关闭、P2P offer/result）
- [ ] Phase 20（v0.6.8，待发布）：架构重构批次 D，server 侧检查点（拆上帝对象）——此前 ~2200 行、身兼 ~15 项职责的 `Server` 现在降级为组合根，由三个独立组件承接：`TunnelRegistry`（客户端会话生命周期、本地/集群路由、TCP 端口分配、集群心跳）、`ProxyService`（HTTP/WebSocket/TCP 数据面转发与并发流预算，替代原 `handler.go`）、`P2PBroker`（`wormhole connect` 的 offer/result 信令编排）；`admin.go` 的 stats/health/clients/tunnels 接口现在改为调用 `TunnelRegistry` 的公开方法，不再直接伸手进 `Server` 内部。跨节点转发同时新增 `validateClusterNodeAddr`，在拼接转发目标前先校验为纯 `host:port`——防止状态存储中的异常条目被拼入意料之外的 scheme/用户信息/路径，属于与拆分无关的纵深防御修复。批次 D 的 client 侧（`RelayClient`/`P2PSession`）待下一个检查点完成

## 贡献

欢迎贡献！

## 许可证

Apache License — 详见 [LICENSE](LICENSE)。
