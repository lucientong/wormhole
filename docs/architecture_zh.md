# Wormhole 架构指南

> 本文档详细描述 Wormhole 的系统架构、网络协议设计和数据流。

**[English](architecture.md)**

## 目录

- [系统概览](#系统概览)
- [组件架构](#组件架构)
- [隧道多路复用协议](#隧道多路复用协议)
- [帧协议](#帧协议)
- [控制协议](#控制协议)
- [认证授权](#认证授权)
- [HTTP 代理流程](#http-代理流程)
- [TCP 隧道流程](#tcp-隧道流程)
- [Inspector 流量捕获](#inspector-流量捕获)
- [P2P 直连](#p2p-直连-phase-4--45)
- [连接管理](#连接管理)
- [安全模型](#安全模型)
- [多隧道配置与热重载](#多隧道配置与热重载)
- [HA / 多节点控制面](#ha--多节点控制面)
- [健壮性与协议加固 (P3-6 批次 A)](#健壮性与协议加固-p3-6-批次-a)
- [热路径分配池化 (P3-6 批次 B)](#热路径分配池化-p3-6-批次-b)
- [context 贯通 (P3-6 批次 C)](#context-贯通-p3-6-批次-c)
- [数据流总结](#数据流总结)

---

## 系统概览

Wormhole 是一个 Client-Server 架构的内网穿透工具。核心思路是：

1. **Client** 在开发者本地运行，连接到公网 VPS 上的 **Server**
2. Server 为 Client 分配一个公网可访问的 URL（子域名或端口）
3. 外部流量通过 Server 中继到 Client，Client 转发到本地服务
4. 可选的 **P2P 直连** 模式：Client 之间直接通信，跳过 Server 中继

```
                        Internet
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
         ┌─────────┐  ┌─────────┐  ┌─────────┐
         │ Browser │  │  curl   │  │  gRPC   │
         │  用户    │  │  客户端  │  │  客户端  │
         └────┬────┘  └────┬────┘  └────┬────┘
              │             │            │
              └──────┬──────┘────────────┘
                     │ HTTP/TCP/WebSocket
                     ▼
         ┌───────────────────────┐
         │   Wormhole Server     │
         │  (VPS with public IP) │
         │                       │
         │  ┌─────────────────┐  │
         │  │  HTTP Router    │  │   ← Host/Path 路由
         │  │  TLS Terminator │  │   ← Let's Encrypt
         │  │  Admin API      │  │   ← /health, /stats
         │  │  TCP Allocator  │  │   ← 端口分配
         │  └─────────────────┘  │
         │           │           │
         │     Mux Tunnel        │   ← 多路复用隧道
         └───────────┬───────────┘
                     │
           ┌─────────┴─────────┐
           │  单个 TCP 连接     │
           │  承载多个 Stream   │
           └─────────┬─────────┘
                     │
         ┌───────────┴───────────┐
         │   Wormhole Client     │
         │   (Developer Local)   │
         │                       │
         │  ┌─────────────────┐  │
         │  │  Stream Handler │  │   ← 接收并转发
         │  │  Inspector      │  │   ← 流量捕获
         │  │  Inspector UI   │  │   ← Web 面板
         │  └─────────────────┘  │
         │           │           │
         └───────────┴───────────┘
                     │
              ┌──────┴──────┐
              │ Local Service│
              │ :8080        │
              └──────────────┘
```

## 组件架构

### Server 端组件

| 组件 | 位置 | 职责 |
|------|------|------|
| `Server` | `pkg/server/server.go` | 核心控制器，管理客户端会话、协调各组件 |
| `HTTPHandler` | `pkg/server/handler.go` | HTTP 反向代理，将请求通过隧道转发给 Client |
| `Router` | `pkg/server/router.go` | Host/Path 路由表，支持子域名、自定义域名和路径前缀 |
| `TLSManager` | `pkg/server/tls.go` | TLS 终止，支持 Let's Encrypt 自动证书和手动证书 |
| `AdminAPI` | `pkg/server/admin.go` | RESTful 管理 API |
| `TCPPortAllocator` | `pkg/server/handler.go` | 为 TCP 隧道分配端口 |
| `StateStore` | `pkg/server/state*.go` | 集群共享状态（子域名/hostname/path 路由 + 节点信息）；内存或 Redis 后端 |
| 集群心跳 | `pkg/server/cluster.go` | 周期心跳 + 路由 TTL 刷新、失效节点驱逐、跨节点 HTTP 代理、共享密钥校验 |

### Client 端组件

| 组件 | 位置 | 职责 |
|------|------|------|
| `Client` | `pkg/client/client.go` | 核心控制器，管理连接、转发、重连 |
| `Inspector` | `pkg/inspector/inspector.go` | HTTP 流量捕获和记录 |
| `Handler` | `pkg/inspector/handler.go` | Inspector HTTP API + WebSocket 推送 |
| `Storage` | `pkg/inspector/storage.go` | 请求记录环形缓冲存储 |
| `WebSocket Hub` | `pkg/inspector/websocket.go` | 实时推送新请求到浏览器 |
| `Web Server` | `pkg/web/handler.go` | 嵌入式静态文件服务（Inspector UI） |

### 核心库

| 包 | 位置 | 职责 |
|---|------|------|
| `tunnel` | `pkg/tunnel/` | 多路复用器、帧编解码、流管理 |
| `proto` | `pkg/proto/` | 控制协议消息定义（Protobuf 编码 + JSON 兜底） |
| `auth` | `pkg/auth/` | 认证授权（HMAC Token、角色权限、速率限制、审计日志、SQLite 持久化） |
| `p2p` | `pkg/p2p/` | STUN 客户端（IPv4/IPv6 双栈）、NAT 发现、UDP 打洞、端口预测、可靠 UDP 传输（UDPMux + UDPStream + ARQ）、端到端加密（X25519 + AES-256-GCM） |
| `version` | `pkg/version/` | 构建版本信息 |

---

## 隧道多路复用协议

### 设计目标

在 **单个 TCP 连接** 上运行多个逻辑 Stream，避免为每个请求建立新连接。

### 架构

```
┌─────────────────────────────────────────────────┐
│              Single TCP Connection              │
│                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ Stream 1 │ │ Stream 2 │ │ Stream 3 │   ...   │
│  │ (Control)│ │ (HTTP #1)│ │ (HTTP #2)│         │
│  └──────────┘ └──────────┘ └──────────┘         │
│       │             │             │             │
│       ▼             ▼             ▼             │
│  ┌───────────────────────────────────────────┐  │
│  │               Mux (多路复用器)              │  │
│  │                                           │  │
│  │  • Stream 创建/销毁                        │   │
│  │  • 帧分发 (根据 StreamID)                   │  │
│  │  • 流量控制 (WINDOW_UPDATE)                 │  │
│  │  • 心跳检测 (PING/PONG)                     │  │
│  └───────────────────────────────────────────┘   │
│       │                                          │
│       ▼                                          │
│  ┌───────────────────────────────────────────┐   │
│  │            Frame Codec (帧编解码)           │  │
│  │                                           │   │
│  │  [Version][Type][StreamID][Length][Payload]│  │
│  └───────────────────────────────────────────┘   │
│       │                                          │
│       ▼                                          │
│  ┌───────────────────────────────────────────┐   │
│  │               net.Conn (TCP)              │   │
│  └───────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
```

### Stream 生命周期

```
  Client                                Server
    │                                      │
    │  ── OpenStream() ──►                 │
    │     (发送 HANDSHAKE 帧)               │
    │                                      │  ◄── AcceptStream()
    │                                      │
    │  ◄── DATA 帧 (StreamID=N) ──          │
    │  ── DATA 帧 (StreamID=N) ──►          │
    │  ── WINDOW_UPDATE (StreamID=N) ──►   │
    │                                      │
    │  ── CLOSE 帧 (StreamID=N) ──►         │
    │     (stream 关闭)                     │
```

### 角色

- **Server 端 Mux**：`tunnel.Server(conn, config)` — 被动接受新 Stream
- **Client 端 Mux**：`tunnel.Client(conn, config)` — 主动创建新 Stream（控制、心跳），也被动接受 Server 推送的 Stream（HTTP 请求转发）

> ⚠️ 注意：在 Wormhole 中，**Server 是打开 Stream 给 Client 的一方**（当有外部 HTTP 请求到来时），Client 也可以打开 Stream 发送控制消息（注册、心跳）。这是双向的。

---

## 帧协议

### 帧格式

每个 Stream 的数据都被封装成帧在 TCP 连接上传输：

```
+----------+----------+------------+----------+------------------+
| Version  |   Type   |  StreamID  |  Length  |     Payload      |
|  1 byte  |  1 byte  |  4 bytes   |  4 bytes |    N bytes       |
+----------+----------+------------+----------+------------------+

帧头固定 10 字节 (HeaderSize)
```

### 帧类型

| Type | 值 | 方向 | 用途 |
|------|----|------|------|
| `DATA` | 0x01 | 双向 | 承载用户数据（HTTP 请求/响应体等） |
| `WINDOW_UPDATE` | 0x02 | 双向 | 流量控制——通知对端可以发送更多数据 |
| `PING` | 0x03 | Client→Server | 心跳检测 |
| `CLOSE` | 0x04 | 双向 | 关闭指定 Stream |
| `HANDSHAKE` | 0x05 | 打开方→接收方 | 创建新 Stream |
| `ERROR` | 0x06 | 双向 | 错误通知（携带错误码和消息） |

### 流量控制

- 每个 Stream 有一个接收窗口（默认 256KB）
- 发送方不能发送超过对端窗口大小的数据
- 接收方消费数据后，通过 `WINDOW_UPDATE` 帧通知发送方增大窗口
- 防止快速发送方淹没慢速接收方

### 编解码

- 使用 `sync.Pool` 复用 buffer，减少 GC 压力
- 大端字节序（`binary.BigEndian`）
- 最大 Payload 大小限制为 16MB

---

## 控制协议

控制消息默认使用 Protobuf 编码（`pkg/proto/messages.go`），并在 `DecodeControlMessage` 中保留了 JSON 兜底解码路径以保持兼容。每条消息通过一个 Mux Stream 传输。

### 线上帧格式

根据一个 Stream 上承载的是单条消息还是一串消息，存在两种并存的帧约定：

- **每个 Stream 一条消息**（Auth/Register/Ping/Stats/Close 的请求-响应对）：直接写入编码后的消息，不加长度前缀——Stream 的边界本身就界定了消息范围。
- **每个 Stream 多条消息**（P2P 信令，见下文）：每条消息通过 `proto.WriteControlMessage` 包装 4 字节大端长度前缀，读取端用 `proto.ReadControlMessage` 读回，这样即可在单个 Stream 上循环读取多条带帧消息而不产生歧义。

P2P 信令需要带长度前缀的形式，是因为一个通知 Stream 上会先后承载数量不定的 `P2PCandidates`（Symmetric NAT 端口预测候选）**加上**一条终止性的 `P2POfferResponse`——服务端（`handleP2POffer`、`notifyPeerOfP2P`）和客户端（`handleStream`、`sendP2POffer`）都会循环读取带帧消息，先收集 `P2PCandidates`，直到终止响应到达。

### 消息类型

| 类型 | 值 | 方向 | 用途 |
|------|----|------|------|
| `AuthRequest` | 1 | C→S | 认证请求（Token + 版本） |
| `AuthResponse` | 2 | S→C | 认证结果 |
| `RegisterRequest` | 3 | C→S | 注册隧道 |
| `RegisterResponse` | 4 | S→C | 返回分配的 URL/端口 |
| `PingRequest` | 5 | C→S | 心跳 |
| `PingResponse` | 6 | S→C | 心跳回复 |
| `StreamRequest` | 7 | S→C | 通知 Client 有新请求到来 |
| `StreamResponse` | 8 | C→S | Client 确认接受/拒绝 |
| `StatsRequest` | 9 | C→S | 请求统计信息 |
| `StatsResponse` | 10 | S→C | 返回统计信息 |
| `CloseRequest` | 11 | C→S | 关闭隧道 |
| `CloseResponse` | 12 | S→C | 确认关闭 |
| `P2POfferRequest` | 13 | C→S | 发起 P2P 连接 |
| `P2POfferResponse` | 14 | S→C | P2P 提议响应 |
| `P2PCandidates` | 15 | 双向 | 额外的 P2P 候选地址 |
| `P2PResult` | 16 | C→S | P2P 连接结果 |

### 消息信封格式

```json
{
  "type": 3,
  "sequence": 1,
  "register_request": {
    "local_port": 8080,
    "protocol": 1,
    "subdomain": "myapp"
  }
}
```

所有消息都包在 `ControlMessage` 信封中，通过 `type` 字段区分，`sequence` 用于请求/响应配对。

### 连接建立流程

```
  Client                                  Server
    │                                        │
    │ ──── TCP Connect ──────────────────►   │
    │                                        │
    │ ◄──── Mux Handshake ──────────────►    │  (隧道层握手)
    │                                        │
    │ ── [Stream 1] AuthRequest ──────────►  │  (若启用认证)
    │     { token: "xxx",                    │
    │       version: "1.0",                  │
    │       subdomain: "myapp" }             │
    │                                        │  → 验证 Token
    │                                        │  → 检查 connect 权限
    │ ◄── [Stream 1] AuthResponse ────────   │
    │     { success: true,                   │
    │       subdomain: "myapp",              │
    │       session_id: "abc123" }           │
    │                                        │
    │ ── [Stream 2] RegisterRequest ──────►  │
    │     { local_port: 8080,                │
    │       protocol: "HTTP",                │
    │       subdomain: "myapp" }             │
    │                                        │  → 分配子域名
    │                                        │  → 注册路由
    │ ◄── [Stream 2] RegisterResponse ────   │
    │     { success: true,                   │
    │       tunnel_id: "abc123",             │
    │       public_url: "http://myapp.ex.." }│
    │                                        │
    │ ── [Stream 3] PingRequest ──────────►  │  (定时心跳)
    │ ◄── [Stream 3] PingResponse ────────   │
    │                                        │
```

---

## HTTP 代理流程

这是最核心的数据流——外部 HTTP 请求如何通过隧道到达本地服务。

### 整体流程

```
  Browser              Server                 Client           Local Service
    │                     │                     │                    │
    │ ── HTTP Request ──► │                     │                    │
    │    GET /api/users   │                     │                    │
    │    Host: myapp.ex.. │                     │                    │
    │                     │                     │                    │
    │                     │ 1. Route(Host)      │                    │
    │                     │    → 找到 Client     │                    │
    │                     │                     │                    │
    │                     │ 2. OpenStream()     │                    │
    │                     │ ──────────────────► │                    │
    │                     │                     │                    │
    │                     │ 3. StreamRequest    │                    │
    │                     │ ──────────────────► │                    │
    │                     │ { request_id: "x",  │                    │
    │                     │   protocol: HTTP,   │                    │
    │                     │   http_metadata: {  │                    │
    │                     │     method: "GET",  │                    │
    │                     │     uri: "/api/..", │                    │
    │                     │     host: "myapp.." │                    │
    │                     │   }}                │                    │
    │                     │                     │                    │
    │                     │ 4. r.Write(stream)  │                    │
    │                     │ ──────────────────► │ 5. ReadRequest()   │
    │                     │  (原始 HTTP 请求)    │    解析 HTTP        │
    │                     │                     │                    │
    │                     │                     │ 6. RoundTrip()     │
    │                     │                     │ ──────────────────►│
    │                     │                     │                    │
    │                     │                     │ ◄── HTTP Response ─│
    │                     │                     │                    │
    │                     │                     │ 7. Capture()       │
    │                     │                     │    (Inspector 记录) │
    │                     │                     │                    │
    │                     │ ◄── resp.Write() ── │ 8. 写回 stream      │
    │                     │   (原始 HTTP 响应)   │                    │
    │                     │                     │                    │
    │                     │ 9. ReadResponse()   │                    │
    │                     │    复制 Headers      │                    │
    │                     │    写 Body           │                    │
    │                     │                     │                    │
    │ ◄── HTTP Response ──│                     │                    │
    │    200 OK           │                     │                    │
    │    + X-Wormhole-*   │                     │                    │
```

### 关键细节

1. **Server 端**（`handler.go: forwardHTTP`）：
   - 通过 `r.Write(stream)` 将完整的原始 HTTP 请求（包括 headers 和 body）序列化到 Stream
   - 从 Stream 读取原始 HTTP 响应：`http.ReadResponse(bufio.NewReader(stream), r)`
   - 添加 `X-Wormhole-Tunnel` 和 `X-Wormhole-Duration` 响应头

2. **Client 端**（`client.go: forwardHTTPWithInspect`）：
   - 当 Inspector 启用且协议为 HTTP 时，走 HTTP 感知路径
   - 用 `http.ReadRequest(bufio.NewReader(stream))` 解析请求
   - 用 `http.Transport.RoundTrip()` 转发到本地服务
   - 将响应通过 `resp.Write(stream)` 写回
   - 调用 `inspector.Capture()` 记录请求/响应

3. **降级路径**：
   - Inspector 未启用 → 走 `forwardRawTCP`（`io.Copy` 盲透传）
   - HTTP 解析失败 → 回退到 `forwardRawTCP`（带 buffer 拼接）
   - 本地服务不可达 → 返回 502 Bad Gateway

4. **多隧道分发**（`handler.go: resolveTunnelID` / `client.go: resolveLocalAddr`）：
   - 第 1 步 `Route(Host)` 只能把请求解析到某个 `ClientSession`——同一个客户端连接可能注册了**多个**隧道（多隧道 YAML 配置），每个隧道有自己的本地后端。
   - 服务端的 `resolveTunnelID(client, host, path)` 会进一步判断请求究竟对应客户端的哪个隧道，匹配优先级为：自定义 hostname → 该隧道专属 subdomain → 最长路径前缀。匹配结果会填充到 `StreamRequest.TunnelID`。
   - 客户端的 `resolveLocalAddr(tunnelID)` 会用该 `TunnelID` 在 `activeTunnels` 中查找对应隧道的 `LocalHost`/`LocalPort`；只有当 `TunnelID` 为空或未识别时才回退到客户端顶层配置（用于单隧道场景的向后兼容）。
   - 这保证了多隧道模式下，各子域名/hostname/路径的流量会分别转发到各自配置的本地端口，而不会全部汇聚到最先注册的那个隧道。

### WebSocket 代理

WebSocket 升级请求特殊处理（`handler.go: handleWebSocket`）：

1. Server 通过 `http.Hijacker` 接管底层连接
2. 原始升级请求写入 Stream
3. 之后进入双向 `io.Copy` 透传模式
4. 不走 Inspector（WebSocket 是长连接）

---

## TCP 隧道流程

TCP 隧道用于非 HTTP 协议（gRPC、数据库连接等）：

```
  TCP Client             Server                 Client           Local Service
    │                     │                     │                    │
    │ ── TCP Connect ───► │                     │                    │
    │    → port 10001     │                     │                    │
    │                     │                     │                    │
    │                     │ 1. OpenStream()     │                    │
    │                     │ ──────────────────► │                    │
    │                     │                     │                    │
    │                     │ 2. StreamRequest    │                    │
    │                     │ ──────────────────► │                    │
    │                     │ { protocol: TCP }   │                    │
    │                     │                     │                    │
    │                     │                     │ 3. Connect to local│
    │                     │                     │ ──────────────────►│
    │                     │                     │                    │
    │ ── data ──────────► │ ── stream ────────► │ ── data ─────────► │
    │ ◄── data ────────── │ ◄── stream ──────── │ ◄── data ────────  │
    │                     │                     │                    │
    │   (双向 io.Copy 透传，直到任一方关闭)         │                    │
```

TCP 隧道不经过 Inspector，因为没有 HTTP 语义可解析。

TCP 连接的 `StreamRequest` 会携带发起该连接的 `TunnelID`（由 `serveTCPTunnel`/`handleTCPConnection` 设置，每个已注册的 TCP 隧道都有独立的监听器），因此客户端的 `resolveLocalAddr` 在多隧道模式下同样能分发到正确的本地后端——机制与上文 HTTP 的"多隧道分发"一致。

### 端口分配失败处理

`TCPPortAllocator` 从一个有界端口范围（默认 `10000-20000`，见 `--tcp-port-range`）中分配端口。如果注册请求需要 TCP 隧道而分配器已无可用端口，`handleRegister` 会**拒绝该次注册**，返回 `RegisterResponse{Success: false}` 及具体错误信息，而不会像过去那样静默"注册成功"却把 `TCPPort` 置为 `0`（这种隧道实际永远无法接受任何 TCP 连接）。如果该失败的隧道曾临时占用过某个专属子域名，也会一并回滚，避免留下"已占用但不可用"的路由。

---

## Inspector 流量捕获

### 架构

```
                    ┌──────────────────────────┐
                    │    Inspector (核心)       │
                    │                          │
  forwardHTTP ────► │  Capture(req, resp, ...) │
  WithInspect       │         │                │
                    │         ▼                │
                    │  ┌────────────────┐      │
                    │  │  Storage       │      │
                    │  │  (环形缓冲)     │      │
                    │  │  max 1000 条   │      │
                    │  └───────┬────────┘      │
                    │          │               │
                    │          ▼               │
                    │  ┌────────────────┐      │
                    │  │  WebSocket Hub │      │  ──► Browser (实时推送)
                    │  │  (广播)         │      │
                    │  └────────────────┘      │
                    │                          │
                    │  HTTP API:               │
                    │  GET  /api/inspector/records    │ ◄── 历史记录查询
                    │  GET  /api/inspector/records/:id│ ◄── 详情
                    │  GET  /api/inspector/stats      │ ◄── 统计
                    │  POST /api/inspector/clear      │ ◄── 清空
                    │  POST /api/inspector/toggle     │ ◄── 切换捕获
                    │  WS   /api/inspector/ws         │ ◄── 实时流
                    └──────────────────────────┘
```

### Record 结构

每条捕获的记录包含：

```go
type Record struct {
    ID              string        // 唯一标识
    Timestamp       time.Time     // 请求时间
    Method          string        // HTTP 方法
    URL             string        // 完整 URL
    RequestHeaders  map[string]string
    RequestBody     []byte        // 截断到 MaxBodySize
    StatusCode      int
    ResponseHeaders map[string]string
    ResponseBody    []byte        // 截断到 MaxBodySize
    Duration        time.Duration // 请求耗时
    Size            int64         // 响应大小
    Error           string        // 错误信息（如果有）
}
```

### 捕获流程

1. `forwardHTTPWithInspect` 完成 HTTP 往返后调用 `inspector.Capture()`
2. `Capture` 构造 `Record` 对象（截断 body、提取 headers）
3. 存入 `Storage`（环形缓冲，FIFO 淘汰）
4. 广播到所有 WebSocket 订阅者

---

## P2P 直连 (Phase 4 & 4.5)

### 目标

当两个 Client 需要通信时（或单 Client 暴露服务时），尝试直接 UDP 连接，跳过 Server 中继，降低延迟。

### NAT 穿透策略

```
                    STUN Server
                    (公共)
                       │
          ┌────────────┤────────────┐
          │            │            │
          ▼            ▼            ▼
     ┌─────────┐ ┌──────────┐ ┌─────────┐
     │ Client A│ │  Server  │ │ Client B│
     │ (NAT后) │ │ (信令中继)│ │ (NAT后) │
     └────┬────┘ └────┬─────┘ └────┬────┘
          │           │            │
          │ 1. STUN Discover       │
          │──────────►│            │
          │◄──────────│            │
          │ (NAT类型+公网IP:Port)   │
          │           │            │
          │           │ 1. STUN    │
          │           │◄───────────│
          │           │───────────►│
          │           │            │
          │ 2. 交换候选地址          │
          │───────────►───────────►│
          │◄───────────◄───────────│
          │           │            │
          │ 3. UDP 打洞              │
          │ ◄─────────────────────►│
          │    (同时发送 UDP 包)     │
          │                        │
          │ 4. 建立 P2P 连接        │
          │ ◄═══════════════════► │
          │    (可靠传输层)         │
```

### 实现状态（已完成）

Phase 4 提供了 P2P 的基础原语，Phase 4.5 完成了端到端集成：

| 组件 | 文件 | 状态 |
|------|------|------|
| **NAT 类型定义** | `pkg/p2p/nat.go` | ✅ 完成 — Full Cone, Restricted, Port Restricted, Symmetric |
| **STUN 客户端** | `pkg/p2p/stun.go` | ✅ 完成 — RFC 5389 Binding, 双服务器 NAT 分类 |
| **UDP 打洞** | `pkg/p2p/hole_punch.go` | ✅ 完成 — WHPP 魔数前缀的 probe/ack 协议 |
| **端口预测器** | `pkg/p2p/predictor.go` | ✅ 完成 — 基于 delta 的 Symmetric NAT 端口预测 |
| **P2P 管理器** | `pkg/p2p/manager.go` | ✅ 完成 — 协调 STUN + 打洞 + 中继降级 |
| **端到端加密** | `pkg/p2p/crypto.go` | ✅ 完成 — X25519 ECDH 密钥交换、AES-256-GCM 加密、HKDF 密钥派生 |
| **可靠 UDP 传输** | `pkg/p2p/mux.go`、`pkg/p2p/stream.go` | ✅ 完成 — `UDPMux`/`UDPStream`：多路复用 ARQ + RFC 6298 自适应 RTO、滑动窗口、可靠 SYN 握手 |
| **信令消息** | `pkg/proto/messages.go` | ✅ 完成 — P2POfferRequest/Response（支持按子域名定向）、Candidates、Result |
| **客户端集成** | `pkg/client/client.go`、`cmd/wormhole/cmd/connect.go` | ✅ 完成 — NAT 发现、P2P Offer、`wormhole connect` 直连数据面 |
| **服务端信令** | `pkg/server/server.go` | ✅ 完成 — 按子域名定向 Peer 匹配、NAT 兼容性检查 |
| **集成测试** | `pkg/p2p/integration_test.go` | ✅ 完成 — 15+ 测试用例 |

> **能力边界说明（P3-3 / DP-23）：** P2P 只能在两个都跑着 Wormhole 打洞协议的进程之间承载流量——也就是 `wormhole client` ↔ `wormhole connect` 这一种场景。公网访客通过隧道 hostname 访问时（浏览器、curl、手机 App 等）并没有在跑 Wormhole 的 P2P 协议，物理上不可能被打洞，因此这条流量始终走 Server 中继；这不是待办缺口，而是硬性物理约束。本文档早期版本描述过"任意隧道流量从中继热切换到 P2P"，但实际上从未真正接线（mux 建立了，却没有任何代码路径把真实的 HTTP/TCP 隧道字节路由进去）。下文的 `wormhole connect` 才是让 P2P 在物理可行的场景里真正承载流量的实现。

### 可靠 UDP 传输层

生产环境的 P2P 数据传输由 `UDPMux` + `UDPStream`（`pkg/p2p/mux.go`、`pkg/p2p/stream.go`）承载——这是一套基于 ARQ 协议、在单个 UDP 套接字对上实现的可靠、有序、支持多路复用的流层。它取代的旧单流实现 `pkg/p2p/transport.go` 已被删除（P3-3 / DP-16）；原来覆盖它的测试均已等价迁移到基于 `UDPMux`/`UDPStream` 的用例上。

**自适应重传（RFC 6298，P3-3 / DP-13）：** 不再使用固定 200ms 重传超时，`UDPStream` 为每条流维护 SRTT/RTTVAR 估计（`updateRTO`，增益 α=1/8、β=1/4，`RTO = SRTT + 4×RTTVAR`，取值范围钳制在 `[100ms, 10s]`），采样来自**未被重传过**的数据段的 ACK（Karn 算法——被重传过的段的 ACK 无法判断到底是确认了哪一次发送，纳入采样会污染估计值，因此排除）。每个在途数据段还会对**自己**的重传计时器做指数退避（每次重传翻倍，封顶为基础 RTO 的 32 倍），而不是所有段共用一个全局计时器，这样一个丢包严重的段不会拖累同一条流上其他段的超时判断。这让流在干净、低延迟的链路上能积极重传，在丢包/高延迟链路上能优雅退避，而不是用一个固定值应付所有场景（大概率两头都不合适）。

**降拷贝（P3-3 / DP-14）：** 发送路径的 `SessionCipher.EncryptInto` 直接把加密结果写入预先分配好容量的发送帧 buffer，不再先加密到临时 buffer 再整体拷贝进帧；接收路径（`handleData`/`deliverLocked`）不再重复拷贝 `decryptPayload` 已经返回的、本身就是独立分配的 payload。两处合计把加密发送路径的开销从每包 8 次分配 / 5200 字节降到 6 次分配 / 2640 字节（`BenchmarkMux_SendPacket` 实测），在模拟 WAN 条件下（`BenchmarkUDPMux_Throughput_SimulatedWAN`，50ms RTT / 1% 丢包）吞吐无退化。

```
┌─────────────────────────────────────────────────────────┐
│              UDPMux（每个 P2P 对端连接一个）                │
│                                                         │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐     │
│  │  序列号     │    │  ACK       │    │  重传       │     │
│  │  编号       │    │  处理      │    │  计时器     │      │
│  └────────────┘    └────────────┘    └────────────┘     │
│                                                         │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐     │
│  │  发送窗口   │    │  乱序      │    │  FIN/RST   │     │
│  │  (64 段)    │    │  缓冲(按流) │    │  关闭       │     │
│  └────────────┘    └────────────┘    └────────────┘     │
│                                                         │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
                    UDP 连接
```

mux 上的每个 `UDPStream` 都有独立的接收缓冲（`recvCh`，容量 256 段）和滑动发送窗口（64 段在途上限）。mux 只有一个 `readLoop` goroutine，负责把每个到达的包分发给目标流的 `handleData`。

**慢消费者场景下的背压**（`deliverLocked`）：当本地应用没有及时调用 `Read()` 消费数据、导致 `recvCh` 已满时，`deliverLocked` 会阻塞一个较短的、有上限的超时时间（200ms），而不是直接丢弃该数据段。超时后，该段的 ACK 会被**故意不发送**——对端自身的重传计时器会重新发送这段数据，从而对发送端形成隐式的"缩窗"限速，直到消费者跟上进度。如果消费者持续卡住，导致 `deliverLocked` 连续超时达到 `maxConsecutiveDeliverFailures` 次（25 次，约 5 秒），该流会发出 RST 并强制关闭，而不是无限重试。这保证了任何数据段都不会出现"既被丢弃又被 ACK"的情况——这正是旧实现可能导致 `recvSeq` 与应用实际收到的数据静默失配的根源。

**可靠的建流握手（SYN/SYN-ACK）：** `OpenStream()` 会把发出的 SYN 以保留序号 `0` 记录进和数据段共用的发送缓冲区（真实数据段序号总是从 `1` 开始，不会冲突），因此 `retransmitLoop` 会像对待普通数据段一样持续重传 SYN，直到收到确认或 `MaxRetransmits` 耗尽为止。接收方一旦接纳该流，就会回复一个针对序号 `0` 的普通 ACK 作为 SYN-ACK；若收到重复 SYN（说明自己上一次的 SYN-ACK 丢了），也会补发一次 ACK。没有这个机制时，只要一个 SYN 包在链路上丢失，对端就会永远不知道这个流的存在——之后所有数据段都会被 `dispatch()` 当作"未知流"直接丢弃，接收方只能在 `AcceptStream()`/`Read()` 上无限期阻塞，而不是尽快感知到连接失败。当任意数据段（包括 SYN 本身）的重传次数耗尽时，发送方现在也会先发一个 RST 通知对端再本地强制关闭，让对端能感知到流已经死亡而不是傻等。

### `wormhole connect`：client 间直连数据面（P3-3 / DP-23）

`wormhole connect <目标子域名> --local <端口>` 是 P2P 真正承载真实应用流量的场景。一个进程正常运行 `wormhole client` 暴露服务（向 Server 注册隧道 + 子域名）；另一个进程运行 `wormhole connect <该子域名>` 而不是 `wormhole client`——它**不**注册自己的隧道，只是请求 Server 把自己和拥有该子域名的对端做匹配。

```
┌──────────────────────────────────────────────────────────┐
│              wormhole connect 数据流                       │
│                                                           │
│  1. Peer A：`wormhole client --local 8080 --subdomain a`   │
│     向 Server 注册隧道 "a"（只走信令）                       │
│                                                           │
│  2. Peer B：`wormhole connect a --local 9090`               │
│     发送 P2POfferRequest{target_subdomain: "a"}             │
│     Server 通过 Router.LookupSubdomain() 查到 "a"，          │
│     返回 P2POfferResponse{peer_tunnel_id: <A 的隧道 ID>}     │
│                                                           │
│  3. 双方 STUN + 打洞（与 Phase 4/4.5 相同的原语）；成功后       │
│     双方在同一对 UDP 套接字上各持有一个 UDPMux                 │
│                                                           │
│  4. Peer B 监听 127.0.0.1:9090；每接受一个本地连接就在 mux 上    │
│     开一个 UDPStream，发送一个寻址到 A 的 peer_tunnel_id 的     │
│     StreamRequest，然后双向转发字节——Server 全程看不到这条      │
│     流量的任何一个字节，只看到最初的信令消息                     │
│                                                           │
│  5. 无中继兜底：如果打洞失败或 UDPMux 之后中断，`wormhole        │
│     connect` 会直接关闭本地监听而不是悄悄降级——Server 从未       │
│     为这个会话注册过隧道，没有可以中继的路径                     │
└──────────────────────────────────────────────────────────┘
```

服务端侧，`pkg/server/server.go` 中的 `Server.findPeerBySubdomain` 把 `target_subdomain` 解析为拥有它的 `ClientSession` 以及具体服务它的 `TunnelInfo.ID`（一个对端可能暴露多个隧道），并区分"未指定目标"（正常 `wormhole client` 注册自己的 P2P 可达信息，静默忽略）、"目标不存在"、"目标是自己"、"目标缺少可用的 P2P/NAT 信息"这四种不同的失败原因，分别体现为 `P2POfferResponse.Error` 的不同取值。

这与普通公网访客的隧道路径故意是不同的机制——参见上方的能力边界说明。

### NAT 类型分类

| NAT 类型 | 打洞难度 | 策略 |
|---------|---------|------|
| 无 NAT（开放网络） | ★☆☆☆ | 直接连接，必成功 |
| Full Cone | ★☆☆☆ | 直接连接，几乎必成功 |
| Restricted Cone | ★★☆☆ | 需要先从内部发出探测包 |
| Port Restricted Cone | ★★★☆ | 需要匹配端口的探测包 |
| Symmetric | ★★★★ | 端口预测 + 多次尝试，成功率较低 |

### 降级策略

```
尝试 P2P 直连
    │
    ├── 成功 → acceptP2PStreams() / startConnectListener()
    │          在 UDPMux 上转发数据
    │
    └── 失败 → `wormhole client`：自动降级到 Server 中继
              (fallbackToRelay() 重置 P2P 状态)
              `wormhole connect`：没有中继可回退——
              命令直接失败退出（见上文）
```

---

## 连接管理

### 重连策略

Client 使用指数退避重连：

```
初始间隔: 1s
退避倍数: 2.0
最大间隔: 60s
最大尝试: 无限制（默认）

序列: 1s → 2s → 4s → 8s → 16s → 32s → 60s → 60s → ...
```

### 心跳检测

```
Client ──── PingRequest (每30s) ──────► Server
       ◄─── PingResponse ──────────────
       
超时: 10s
连续 3 次超时: 强制关闭 mux，触发重连
```

### 连接丢失检测（`Mux.CloseNotify()`）

重连机制要真正生效，前提是连接丢失能被可靠检测到。`tunnel.Mux` 暴露了 `CloseNotify() <-chan struct{}` 通道，该通道在 `Close()` 被显式调用，或底层 TCP 连接死亡（mux 内部读写循环出错）时会被关闭一次。

`Client.handleConnection()` 使用 `select` 同时等待 `mux.CloseNotify()`、`ctx.Done()` 和客户端自身的关闭信号——**不再只等待 `ctx.Done()`**——因此 mux 一旦死亡就会立即解除阻塞，而不会让连接停留在"看起来 `connected` 但实际已无法传输数据"的半死状态。一旦被 `CloseNotify()` 唤醒，客户端会清除 `connected` 标志并把控制权交还给 `connectWithRetry()`，后者会进入上面的指数退避循环，并重新注册此前所有活跃的隧道（含多隧道模式下的每一个隧道）。

`heartbeatLoop()` 同样会 `select` 监听 `mux.CloseNotify()`，因此它会及时退出，而不是只在定时器触发时才检查 mux 健康状态。连续 **3 次** ping 失败后，它会主动调用 `mux.Close()`——这正是把"连接静默卡死（TCP 仍然"打开"但已不再响应）"转化为"可检测到的连接丢失"的关键一步，随后触发上面描述的重连路径。

---

## 认证授权

### 概述

Wormhole 支持可选的认证机制，保护服务端不被未授权客户端连接。认证模块位于 `pkg/auth/`。

### 架构

```
┌─────────────────────────────────────────────────────────────┐
│                     Auth 模块 (pkg/auth/)                    │
│                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐ │
│  │   Token    │  │   速率     │  │   审计                 │ │
│  │   管理器   │  │   限制器   │  │   日志                 │ │
│  │            │  │            │  │                        │ │
│  │ - 生成     │  │ - IsBlocked│  │ - LogAuthSuccess       │ │
│  │ - 验证     │  │ - RecordFail│ │ - LogAuthFailure       │ │
│  │ - 吊销     │  │ - Unblock  │  │ - LogIPBlocked         │ │
│  └─────┬──────┘  └─────┬──────┘  └──────────┬─────────────┘ │
│        │               │                     │               │
│        └───────────────┼─────────────────────┘               │
│                        │                                     │
│                        ▼                                     │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                  存储后端                               │ │
│  │                                                         │ │
│  │   ┌──────────────┐         ┌──────────────┐            │ │
│  │   │   内存       │   或    │   SQLite     │            │ │
│  │   │  (默认)      │         │ (持久化)     │            │ │
│  │   └──────────────┘         └──────────────┘            │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 认证模式

| 模式 | 适用场景 | 配置 |
|------|---------|------|
| **HMAC 签名 Token** | 多团队协作，精细权限控制 | `--auth-secret` |
| **简单预共享 Token** | 快速部署，单团队 | `--auth-tokens` |
| **混合模式** | 同时支持两种 Token | `--auth-secret` + `--auth-tokens` |

### HMAC Token 格式

```
<base64url(payload)>.<base64url(hmac-sha256(payload))>

payload = {
  "team":  "team-name",
  "role":  "member",
  "iat":   1711900800,
  "exp":   1711987200,
  "nonce": "random-base64"
}
```

### 角色与权限

| 角色 | connect | write | read | admin |
|------|---------|-------|------|-------|
| `admin` | ✅ | ✅ | ✅ | ✅ |
| `member` | ✅ | ✅ | ✅ | ❌ |
| `viewer` | ❌ | ❌ | ✅ | ❌ |

### 速率限制

速率限制器（`ratelimit.go`）防止暴力破解攻击：

```
┌─────────────────────────────────────────┐
│          速率限制流程                    │
│                                          │
│  认证请求                                │
│       │                                  │
│       ▼                                  │
│  ┌─────────────┐                         │
│  │ 是否被封禁？│──是──► 429 Too Many     │
│  └──────┬──────┘         Requests        │
│         │ 否                             │
│         ▼                                │
│  ┌─────────────┐                         │
│  │   验证      │                         │
│  │   Token     │                         │
│  └──────┬──────┘                         │
│         │                                │
│    ┌────┴────┐                           │
│    │         │                           │
│   成功     失败                          │
│    │         │                           │
│    ▼         ▼                           │
│ RecordSuccess  RecordFailure             │
│ (清除计数)     (增加计数)                │
│                    │                     │
│              ┌─────┴─────┐               │
│              │ >= 5 次？ │               │
│              └─────┬─────┘               │
│                    │ 是                  │
│                    ▼                     │
│              封禁 IP                     │
│              15 分钟                     │
└─────────────────────────────────────────┘

默认配置:
- MaxFailures: 5
- Window: 5 分钟
- BlockDuration: 15 分钟
```

### 审计日志

审计日志器（`audit.go`）记录安全事件，用于合规和调试：

| 事件类型 | 描述 |
|---------|------|
| `auth_success` | 认证成功 |
| `auth_failure` | 认证失败 |
| `ip_blocked` | IP 因速率限制被封禁 |
| `ip_unblocked` | IP 被手动解封 |
| `token_generated` | 新 Token 被创建 |
| `client_connected` | 客户端建立隧道 |
| `client_disconnected` | 客户端断开连接 |

日志格式（JSON）：
```json
{
  "timestamp": "2024-03-31T12:00:00Z",
  "type": "auth_success",
  "ip": "192.168.1.100",
  "team": "team-alpha",
  "role": "member",
  "session_id": "abc123",
  "subdomain": "myapp"
}
```

### 持久化存储

存储后端（`store.go`, `store_sqlite.go`）：

| 后端 | 适用场景 | 配置 |
|------|---------|------|
| **内存** | 开发、无状态部署 | 默认 |
| **SQLite** | 生产、持久化团队数据 | `--persistence sqlite` |

SQLite 存储：
- 团队信息（名称、创建时间）
- 已吊销 Token 黑名单
- Token 元数据（过期时间、吊销状态）

### 认证握手流程

```
  Client                                Server
    │                                      │
    │  ── Mux.OpenStream() ──►            │
    │                                      │  ◄── Mux.AcceptStream()
    │                                      │      (带超时，默认 10s)
    │                                      │
    │                                      │  1. rateLimiter.IsBlocked(ip)?
    │                                      │     → 是：关闭连接
    │                                      │
    │  ── AuthRequest ──────────────────► │
    │     { token: "xxx",                 │
    │       version: "1.0.0",             │
    │       subdomain: "myapp" }          │
    │                                      │  2. ValidateToken(token)
    │                                      │     → 先尝试 simple 匹配
    │                                      │     → 再尝试 HMAC 验证
    │                                      │  3. HasPermission(claims, "connect")
    │                                      │  4. rateLimiter.RecordSuccess/Failure
    │                                      │  5. auditLogger.LogAuthSuccess/Failure
    │                                      │
    │  ◄── AuthResponse ────────────────  │
    │     { success: true,                │
    │       subdomain: "myapp",           │
    │       session_id: "abc123" }        │
    │                                      │
    │  (继续 RegisterRequest 流程)         │
```

### Admin API 认证

- `/health` 端点始终公开
- `/stats`、`/clients`、`/tunnels`、`/teams` 受 `--admin-token` 保护
- 使用 `Authorization: Bearer <token>` 头
- Token 比较使用 `crypto/subtle.ConstantTimeCompare` 防止时序攻击
- 未设置 `--admin-token` 时，仅允许回环地址请求（`127.0.0.1` / `::1`）；非回环请求返回 403 Forbidden
- Admin API 默认绑定 `127.0.0.1`（通过 `--admin-host` 标志覆盖）

### 团队管理 API

| 端点 | 方法 | 描述 |
|-----|------|------|
| `/teams` | GET | 列出所有团队 |
| `/teams` | POST | 创建新团队 |
| `/teams/{name}` | GET | 获取团队详情 |
| `/tokens/generate` | POST | 为团队生成 Token |
| `/tokens/revoke` | POST | 吊销 Token |

### 客户端 Token 持久化

客户端将认证 Token 存储在本地（`~/.wormhole/config.yaml`）：

```yaml
server_addr: "tunnel.example.com:7000"
token: "eyJ0ZWFtIjoiYWxwaGEiLCJyb2xlIjoibWVtYmVyIi4uLn0.xxx"
subdomain: "myapp"
tls_enabled: true
tls_insecure: false
p2p_enabled: true
```

- Token 以限制性权限保存（0600）
- 命令行标志覆盖持久化配置
- `--save-token` 标志在成功认证后持久化 Token

---

## 安全模型

### 传输加密

- Server 支持 TLS 终止（Let's Encrypt 自动证书 或 手动证书）
- Client-Server 隧道控制链路支持 TLS 加密（客户端 `--tls` / `--tls-insecure` / `--tls-ca` 标志）
- Server 隧道监听器可通过 `--tunnel-tls` 标志独立开启 TLS

### P2P 端到端加密

P2P 直连使用端到端加密保护数据的机密性和完整性，即使信令服务器不可信也无法窃取数据：

```
  Client A                    Server (信令)                    Client B
    │                              │                              │
    │  1. 生成 X25519 密钥对         │                              │
    │     (privA, pubA)            │                              │
    │                              │  2. 生成 X25519 密钥对         │
    │                              │     (privB, pubB)            │
    │                              │                              │
    │  ── P2POfferRequest ──────►  │  ── P2POfferResponse ──────► │
    │     { public_key: pubA }     │     { peer_public_key: pubA }│
    │                              │                              │
    │  ◄── P2POfferResponse ─────  │  ◄── P2POfferRequest ─────   │
    │     { peer_public_key: pubB }│     { public_key: pubB }     │
    │                              │                              │
    │  3. ECDH(privA, pubB)        │                              │
    │     → 共享密钥                 │  3. ECDH(privB, pubA)       │
    │     → HKDF 派生:              │     → 相同共享密钥             │
    │       - AES-256 加密密钥      │     → HKDF 派生:              │
    │       - HMAC 打洞密钥         │       - AES-256 加密密钥       │
    │                              │       - HMAC 打洞密钥         │
    │                              │                              │
    │  4. HMAC 认证的 UDP 打洞 ◄════════════════════════════►       │
    │                              │                              │
    │  5. AES-256-GCM 加密数据传输 ◄═══════════════════════════►    │
```

关键组件：

| 组件 | 说明 |
|------|------|
| **密钥交换** | X25519 ECDH — 每个 peer 每次会话生成临时密钥对 |
| **密钥派生** | HKDF-SHA256，使用不同的 info 标签：`"wormhole-p2p-encryption"` 用于 AES 密钥，`"wormhole-p2p-punch-hmac"` 用于探测包 HMAC 密钥 |
| **数据加密** | AES-256-GCM，使用单调递增 nonce 计数器（8 字节计数器 + 4 字节零填充） |
| **探测包认证** | HMAC-SHA256 对打洞探测包进行认证，防止伪造探测包注入 |
| **前向安全** | 每次会话使用临时密钥 — 泄露一次会话密钥不影响其他会话 |
| **服务器盲化** | 服务器仅中继公钥，无法推导共享密钥或解密数据 |

### 认证

- **多模式 Token 认证**：
  1. 简单预共享 Token（快速部署）
  2. HMAC-SHA256 签名的团队 Token（带过期时间 + 吊销）
  3. OIDC JWT Token —— 当配置了 `OIDCValidator` 且 token 形如 JWT 时，`ValidateToken` 会尝试走 OIDC 校验
- 角色权限控制（RBAC）：admin、member、viewer 三级角色
- 连接握手时强制认证（`--require-auth`），viewer 角色无法建立隧道连接——在服务端"使用点"处强制（`handleRegister`/`handleClose` 调用 `requireWritePermission`），而不只是客户端菜单隐藏入口——在服务端"使用点"强制校验（`handleRegister`/`handleClose` 调用 `requireWritePermission`），而不只是客户端菜单里隐藏入口
- Admin API 独立 Token 保护，使用 `crypto/subtle.ConstantTimeCompare` 防时序攻击
- Token 吊销支持：单个 Token 黑名单（SQLite 后端持久化）

#### OIDC / SSO 集成

```
Auth.ValidateToken(token)
  ├── 1. 简单预共享 Token 匹配
  ├── 2. 是否形如 JWT？+ 是否配置了 OIDCValidator？
  │       └── OIDCValidator.ValidateToken(jwt)
  │               ├── OIDC 发现（issuer/.well-known/openid-configuration）
  │               ├── JWKS 密钥拉取 + 缓存（TTL 1 小时）
  │               ├── JWT 签名校验（RS256 / ES256）
  │               ├── Claims 校验：iss、aud、exp
  │               └── OIDCClaimMapping → Claims{TeamName, Role}
  └── 3. HMAC-SHA256 签名 Token 校验
```

`OIDCValidator` 以 1 小时 TTL 缓存 JWKS 密钥，遇到未知 `kid` 时自动刷新。支持算法：`RS256`、`RS384`、`RS512`、`ES256`、`ES384`、`ES512`。

#### OAuth2 设备码流程（`wormhole login`）

```
wormhole login --issuer <url> --client-id <id>
  │
  ├── 1. OIDC 发现 → device_authorization_endpoint、token_endpoint
  ├── 2. POST /device/auth → { device_code, user_code, verification_uri, interval }
  ├── 3. 打印："Open <url> and enter code: XXXX-YYYY"
  ├── 4. 每隔 <interval> 秒轮询一次 token endpoint（请求体已按 RFC 8628 §3.4
  │       补上 client_id，Keycloak 等严格校验的 IdP 需要这个字段）
  └── 5. 成功后：SaveCredentialsFull(~/.wormhole/credentials.json, {
            token、expires_at（优先解析 JWT 自身的 exp claim，取不到再回退
            到 expires_in）、refresh_token、oidc_issuer、client_id、
            token_endpoint })
```

**端到端使用（全程无需手动操作 token）：** `wormhole client`（通过 `cmd/wormhole/cmd/client.go` 里的 `resolveClientCredentials`）在没有显式传 `--token` 时，会按 `--server` 自动加载已保存的凭证。如果保存的 token 已过期但凭证信息足够发起刷新（`Credentials.CanRefresh()`：需要同时具备 `refresh_token` + `client_id` + `token_endpoint`），会通过 OAuth2 `refresh_token` 授权（`auth.RefreshAccessToken`）静默续期，并把续期后的凭证重新写回磁盘——完全不需要重新运行 `wormhole login`。同一套刷新逻辑也接到了 `Config.OnAuthFailure` 上，因此即便 token 在**会话中途**过期（例如因为 `Mux.CloseNotify()` 触发了重连），`authenticateWithRefresh()` 也会自动刷新后重试一次，而不是直接断连失败。

### 速率限制

- 按 IP 地址追踪认证失败
- 可配置阈值：5 分钟内 5 次失败 → 封禁 15 分钟
- 自动过期和清理速率限制记录
- 可通过 Admin API 手动解封
- 被封禁的 IP 无法进行认证尝试

### 审计日志

- 结构化 JSON 日志记录安全和生命周期事件
- 事件类型：认证成功/失败、IP 封禁/解封、Token 生成/吊销、隧道创建/关闭、P2P 建立/降级、客户端连接/断开
- 可插拔的 `AuditStore`：内存环形缓冲区（默认）或 SQLite（持久化）
- Admin API：`GET /audit`（支持过滤）+ `GET /audit/export`（CSV/JSON 批量导出）
- 保留策略：`--audit-retention-days`（默认 90 天）+ 周期清理任务，避免长期运行的服务器审计日志无限增长

### 输入验证

- Host header 路由时做 HTML 转义（防 XSS）
- 子域名只允许单级标签（无点号）
- 路径前缀规范化（首尾 `/`）

### 安全加固（P3-4）

一次专项审查（`docs/personal/review-v0.6.md`）复核了 v0.6.0 中所有安全相关的代码路径并修复了以下缺口，每一项都有专项单测覆盖：

| 领域 | 修复前 | 修复后 |
|------|--------|--------|
| **RBAC 生效位置** | 只有 CLI 端隐藏了写操作入口，服务端对任何已认证客户端发来的 `RegisterRequest`/`CloseRequest` 都照常处理 | `handleRegister`/`handleClose` 一开始就调用 `requireWritePermission(client)`；`viewer` token 会被明确拒绝并生成一条审计事件，不管请求实际从哪个客户端发出 |
| **隧道控制链路 TLS** | 隧道监听器复用与 HTTP 监听器相同的 `TLSConfig()`，只要 `Config.TLSEnabled` 为 false 就必然拿到"无 TLS"结果——单独设置 `TunnelTLSEnabled=true` 形同虚设 | `TLSManager.TunnelTLSConfig()`/`WrapTunnelListenerStrict()` 与 HTTP 侧 TLS 配置完全解耦；`--require-auth` + 真实域名现在默认把 `TunnelTLSEnabled` 打开；开启认证场景下，TLS *配置本身*出错（而不只是"没配证书"）会直接让服务端启动失败，而不是退回明文 |
| **子域名申请** | 无论是内存路由表还是 Redis 集群状态，`RegisterRoute` 都是"后写覆盖前写"：两个客户端（或两个节点）竞争同一个子域名时会互相覆盖，输的一方还以为自己拥有这条路由 | 原子申请，定义了四种明确结果：空闲 → 保留；同一客户端重复注册 → 幂等续期 TTL；被另一个*存活*的所有者持有 → 返回 `ErrSubdomainConflict`（拒绝连接）；被一个*陈旧*（已过期）的所有者持有 → 回收。Redis 实现使用 `SetArgs{Mode: "NX"}`（`SetNX` 的官方推荐替代） |
| **Token 过期计算** | `ExtendTokenExpiry` 为了复用生成 token 的代码路径，临时改写共享的 `Auth.config.TokenExpiry` 字段再改回去——并发请求下是真实数据竞争 | `generateTeamToken(teamName, role, expiry)` 把 `expiry` 作为显式参数传入，不再有任何地方改写共享 config |
| **吊销 token 清理** | `Auth.CleanupRevokedTokens()` 早已实现且能正常工作，但从未被调用——吊销黑名单（如果开启了持久化，还有对应的 SQLite 表）只增不减 | `Server.Start()` 调度 `runRevokedTokenCleanup()` goroutine，每 10 分钟清理一次过期的黑名单条目 |
| **OIDC `alg: none`** | `alg: none` / 空 `alg` 的 JWT 会落到通用的"不支持的算法"分支被间接拒绝——功能上是拒绝的，但没有一个专门、有测试锁定的防御，对付经典的签名绕过攻击 | `verifyJWTSignature` 新增专门的 `case "none", ""` 立即拒绝，并配有回归测试 |
| **OIDC issuer/`nbf`** | issuer 比较是裸字符串匹配（IdP 的 discovery 文档和实际签发的 token 之间尾部斜杠不一致就会误判为不匹配）；`nbf` 从未被校验 | `normalizeIssuer()` 比较前先去掉尾部斜杠；`nbf` 校验复用既有 `exp` 校验的 60 秒 `clockSkewLeeway` |
| **Inspector 采集** | `Authorization`/`Cookie` 等头会原样存进采集记录（可通过 inspector UI/API 看到）；默认正文捕获上限为 1MB | `captureHeaders()` 在请求和响应两侧都会把一组敏感头名（不区分大小写）替换为固定的打码占位符；默认 `MaxBodySize` 下调到 256KB |
| **`/metrics`** | 与其余 Admin API 路由不同，完全未鉴权即可访问 | 套上与 `/stats`、`/audit` 等相同的 `requireAdminAuth` 中间件 |
| **审计漏报** | 只有失败被记录（`LogAuthFailure`）；认证成功、IP 封禁、Token 生成、IP 解封都没有留下审计痕迹；`RefreshAndRevokeToken` 吊销旧 token 失败时会静默吞掉这个错误 | 在对应调用处补上 `LogAuthSuccess`/`LogIPBlocked`/`LogTokenGenerated`/`LogIPUnblocked`；`RefreshAndRevokeToken` 现在会同时返回新 token *和* 一个说明吊销失败的 wrapped error，通过响应里的 `Warning` 字段传给调用方，而不是被悄悄丢弃 |
| **审计保留** | 没有办法限制长期运行服务器的审计日志增长 | `AuditStore.DeleteOlderThan(cutoff)`（内存和 SQLite 两种实现均支持）+ `--audit-retention-days`（默认 90）+ 周期性的 `runAuditRetention()` 清理任务 |
| **审计存储写入失败** | `AuditLogger.Log()` 直接吞掉 `l.store.Store(event)` 的错误（`_ = ...`）——持久化后端故障（比如磁盘写满或 SQLite 文件被锁）时事件静默丢失，完全没有可观测信号 | 新增 `atomic.Uint64` 类型的 `storeErrors` 计数器，每次 `Store()` 失败都会累加；`AuditLogger.StoreErrors()` 暴露该计数，`GET /stats` 将其作为 `audit_store_errors` 字段返回（未启用审计时省略该字段），使这类故障可被监控告警，而不是悄无声息地丢数据 |
| **连接时的子域名冲突** | 本地或集群级子域名冲突只会被记日志；连接照常放行，客户端还被（通过 `AuthResponse`）告知自己拥有这个子域名，而实际流量始终路由到真正持有该条目的那个 session | `registerClientRoute()` 在本地或集群任一层面冲突时都会拒绝并关闭连接，客户端自身的重连逻辑会接管重试，而不是让它带着一个悄悄损坏的状态继续运行 |
| **节点间代理信任（S1，P3-5）** | `proxyToNode` 在集群节点之间转发请求时没有任何认证——任何能访问某个节点 HTTP 端口的主机都能伪造 `X-Wormhole-*` 代理头，冒充一个合法的对端节点 | 新增 `--cluster-secret` 共享密钥；`proxyToNode` 转发时附带 `X-Wormhole-Cluster-Secret` 头，`verifyClusterSecret` 在路由逻辑生效前校验并剥除该头，配置了密钥后缺失/不匹配的请求会被拒绝 |
| **跨节点 token 吊销（H5，P3-5）** | 在 `--persistence sqlite` 或默认的内存模式下，节点 A 吊销的 token 在节点 B 上依然有效，要等到节点 B 自身的存储恰好收敛（而两个独立的 SQLite 文件永远不会收敛） | `--persistence redis`（`auth.RedisStore`）把团队和吊销状态存进集群本就在用的同一个 Redis；写入完成的那一刻，吊销就已经在整个集群内可见，并用 TTL 自动过期取代周期性清理任务 |

---

## 多隧道配置与热重载

### 配置文件（`pkg/client/config_file.go`）

基于 YAML 的客户端配置，可以声明式地定义多个隧道：

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
    subdomain: myapi
  - name: db
    local_port: 5432
    protocol: tcp
```

### 多隧道启动流程

```
Client.connect()
  └── config.Tunnels 非空？
        ├── 是 → registerAllTunnels()
        │           └── 每个 TunnelDef → registerOneTunnel() → activeTunnels[name]
        └── 否 → registerTunnel()（兼容旧的单隧道模式）
```

### SIGHUP 热重载

```
收到 SIGHUP
  └── LoadFileConfig(path) → 新的 FileConfig
        └── c.ReloadTunnels(newDefs)
              ├── 差量比较：找出被删除的隧道 → 各自 CloseTunnel()
              └── 差量比较：找出新增的隧道 → 各自 registerOneTunnel()
```

无需重启进程；隧道连接本身始终保持打开。

### 本地控制 API（`pkg/client/control.go`）

```
GET http://localhost:<ctrl-port>/tunnels
→ 返回 TunnelInfo { Name, LocalPort, Protocol, PublicURL, CreatedAt } 的 JSON 数组
```

供 `wormhole tunnels list` 展示当前活跃的隧道。

---

## HA / 多节点控制面

### StateStore 接口（`pkg/server/state.go`）

```go
type StateStore interface {
    RegisterRoute(entry RouteEntry) error
    UnregisterRoute(clientID string) error
    UnregisterRouteEntry(routeID string) error
    LookupBySubdomain(subdomain string) (*RouteEntry, error)
    LookupByHostname(hostname string) (*RouteEntry, error)
    LookupByPathPrefix(path string) (*RouteEntry, error)
    ListRoutes() ([]RouteEntry, error)
    NodeHeartbeat(info NodeInfo) error
    GetNodes() ([]NodeInfo, error)
    EvictDeadNodes(olderThan time.Duration) error
    Close() error
}
```

`RouteEntry` 携带 `{RouteID, ClientID, Subdomain, Hostname, PathPrefix, NodeID, NodeAddr, RegisteredAt}`——同一个客户端可以同时持有多条 `RouteEntry`（一个隧道的子域名、另一个隧道的自定义 hostname、第三个隧道的 path 前缀），每条都能通过独立的 `RouteID` 精确注销（H3）。`NodeInfo` 携带 `{NodeID, NodeAddr, LastHeartbeat}`。

`RegisterRoute` 必须原子地占用该 entry 对应的路由键（子域名 / hostname / path，取决于设置了哪个字段，S3/H6）：空闲 → 保留；同一 `ClientID` 重复注册 → 幂等续期 TTL；被另一个*存活*的所有者持有 → 返回 `ErrSubdomainConflict`；被一个*陈旧*（已过期）的持有者占用 → 回收。`RedisStateStore` 在对应的 `wormhole:sub:*`/`wormhole:host:*`/`wormhole:path:*` key 上用 `SetArgs{Mode: "NX"}` 实现，冲突时再对 `wormhole:route:<routeID>` 做一次存活性检查；`MemoryStateStore` 在自己的锁下通过共享的 `conflictsWith` 辅助函数实现同样的四态语义。

### 后端实现

| 后端 | 类 | 适用场景 |
|------|-----|---------|
| `nil`（默认） | — | 单节点；无分布式状态 |
| `MemoryStateStore` | `state_memory.go` | 单节点；无需 Redis 即可验证集群逻辑 |
| `RedisStateStore` | `state_redis.go` | 多节点；生产级集群 |

Redis key 结构：

| Key | TTL | 内容 |
|-----|-----|------|
| `wormhole:route:<routeID>` | 5 分钟 | `RouteEntry` JSON |
| `wormhole:sub:<subdomain>` | 5 分钟 | 指向 `routeID` |
| `wormhole:host:<hostname>` | 5 分钟 | 指向 `routeID` |
| `wormhole:path:<prefix>` | 5 分钟 | 指向 `routeID` |
| `wormhole:clientroutes:<clientID>` | 5 分钟 | 该客户端名下所有 `routeID` 组成的 SET，用于断连时批量清理 |
| `wormhole:node:<nodeID>` | 90 秒 | `NodeInfo` JSON |

`ListRoutes`/`GetNodes`（以及 auth store 的 `ListTeams`/`CountRevokedTokens`）全部使用 `SCAN` 游标而非 `KEYS`，避免大 key 空间下阻塞共享的 Redis 实例（H7）。

### 路由 TTL 刷新（H1）

一条路由只在注册那一刻写入 Redis、之后再也不刷新的话，即使客户端仍然在线，也会在 5 分钟后静默过期——这是 v0.6 审查中发现的最致命的 HA 缺口。`ClientSession.clusterRoutes` 记录该会话在集群侧注册过的每一条 `RouteEntry`（主子域名，以及 `registerTunnelRoutes` 注册的额外子域名/hostname/path 前缀），`startClusterHeartbeat` 每 30 秒的心跳周期都会调用 `refreshClusterRoutes`，对这些路由逐一重新执行 `RegisterRoute`——这本质上是一次可批量/管道化的 `EXPIRE`/TTL 刷新，而不是重新申请，因为这些条目本来就属于当前客户端。

### 集群心跳（`pkg/server/cluster.go`）

```
startClusterHeartbeat(ctx)
  ├── 每 30 秒 → NodeHeartbeat(NodeInfo{NodeID, NodeAddr})
  │              sendHeartbeat 同时记录 StateStore 是否可达 → Server.stateStoreHealthy（H9）
  ├── 每 30 秒 → 对每个在线会话执行 refreshClusterRoutes(client)（H1）
  └── 每 60 秒 → EvictDeadNodes(90 秒阈值)
                    └── MemoryStateStore：扫描并删除失效节点及其名下的路由
                        RedisStateStore：no-op——驱逐完全由 Redis TTL 负责（H8）
```

### 跨节点 HTTP 路由

```
HTTPHandler.ServeHTTP(r)
  ├── verifyClusterSecret(r) → 若配置了 --cluster-secret 且请求头缺失/不匹配则拒绝（S1）
  ├── router.Route(host, path) → 本地是否存在 ClientSession？
  │     └── 是 → forwardHTTP / handleWebSocket（正常路径）
  └── 否 → server.lookupRemoteRoute(host, path, subdomain)   [hostname → 最长匹配 path → subdomain]
              └── 找到远端 RouteEntry？
                    ├── 是本节点？→ 走向 404（陈旧条目）
                    └── 否 → proxyToNode(route.NodeAddr, w, r)
                                  └── 附加 X-Wormhole-Cluster-Secret 头（S1）
                                  └── httputil.ReverseProxy → 转发到目标节点
```

hostname 和 path 前缀路由现在与子域名一样会被索引进 Redis（H3），因此在节点 A 上通过 `--hostname`/`--path` 注册的隧道，也能通过节点 B 访问，不再局限于自己的子域名。

**节点身份（H4）**：`applyClusterNodeIDDefault` 在配置了集群后端但没有显式设置 `ClusterNodeID` 时，会用 `os.Hostname()` 兜底，避免两个节点意外共用一个空字符串 NodeID。

**陈旧持有者回收（H10）**：`router.go` 的 `RegisterSubdomain`/`RegisterHostname`/`RegisterPath` 在返回冲突之前会先检查 `isStaleOwner`（原持有者的 `Mux.IsClosed()`）；`registerClientRoute` 在集群侧做同样的处理，主动注销失效会话在 `StateStore` 中残留的条目。客户端网络抖动后重连，能立即拿回原来的子域名/hostname/path，而不是先收到一次瞬时的冲突错误。

**健康状态暴露（H9）**：`GET /health` 新增 `cluster: {node_id, state_store_healthy}` 字段；一旦状态存储不可达，整体 `status` 会从 `"ok"` 降级为 `"degraded"`，监控系统无需再单独探测 Redis。

### 节点间认证（S1）

`--cluster-secret` 是集群内所有节点共享的密钥。`proxyToNode` 在每次代理转发时都会附带 `X-Wormhole-Cluster-Secret` 头；`verifyClusterSecret`（在 `HTTPHandler.ServeHTTP` 最前面调用）会拒绝头缺失或不匹配的请求，并在放行前剥除该头，确保它永远不会被转发给本地隧道客户端。如果没有配置密钥，则不做任何校验（向后兼容 S1 之前的单节点/未加固部署）——运行真实集群的用户应当始终配置它，否则网络中的其他节点可以伪造 `X-Wormhole-*` 代理头。

### 共享的鉴权/吊销状态（H5）

`--persistence redis`（`pkg/auth/store_redis.go`，`auth.RedisStore`）把团队信息存在 `wormhole:auth:team:<name>`，吊销的 token 存在 `wormhole:auth:revoked:<tokenID>`，并用与 token 剩余有效期匹配的 Redis TTL——节点 A 上吊销的 token，写入完成的那一刻在节点 B 上就已经失效，没有传播延迟，也不需要周期性清理任务（该后端下 `CleanupExpiredRevocations` 是 no-op，因为 TTL 早就自动删除了 key）。`--auth-redis-addr/-password/-db` 未显式设置时会回退到 `--cluster-redis-*`，一套 Redis 配置即可同时支撑集群路由状态和鉴权/吊销状态。

### HA 下的 TCP 隧道（H2）

TCP 隧道**仅限节点本地**：TCP 隧道的监听器运行在客户端当前连接的那个节点上，不存在跨节点的 TCP 代理（与 HTTP/WebSocket 路径不同，`StateStore` 并不追踪跨节点的 TCP 端口归属）。需要 TCP 隧道 HA 能力的用户，需要自行在各节点地址/端口前面放一个支持 TCP 的负载均衡器（例如 HAProxy 的 `mode tcp`，或 L4 DNS/anycast 方案）；Wormhole 本身不会尝试隐藏这个限制。完整的边缘端口代理方案不在本期范围内，另行在路线图 P3-6 及之后跟踪。

### 连接限制

- `MaxClients` 限制同时在线客户端数
- TCP 端口分配范围限制（默认 10000-20000）
- 按 IP 追踪连接用于速率限制

---

## 健壮性与协议加固 (P3-6 批次 A)

P3-6 架构重构阶段的第一个子批次，收尾了 `review-v0.6.md` 审查中发现的一批正确性缺口并清理了死代码，不涉及留给批次 B/C 的热路径分配/context 贯通工作，也不涉及留给批次 D 的上帝对象拆分。

### 优雅关闭（DP-26）

`Server` 现在持有为 HTTP 和 admin 监听器构造的 `*http.Server` 引用（此前这些值只传给 `ListenAndServe`/`ListenAndServeTLS` 后就被丢弃）。`Server.Shutdown()` 会先对两者调用带超时（`ShutdownTimeout`，默认 10s）的 `http.Server.Shutdown(ctx)`，再关闭隧道监听器，使 `SIGTERM` 时在途的 HTTP/admin 请求有机会正常完成，而不是连接被直接掐断。

### 双向代理首错收尾（DP-04）

WebSocket 和 TCP 隧道代理路径都用 `io.Copy` 并发泵送两个方向（client→local 和 local→client）。此前如果一个方向先遇到 EOF/错误，另一个方向只有等自己读超时或对端各自关闭才会解除阻塞——对于大部分单向的会话（例如长轮询或空闲的 keep-alive），这会让流的收尾卡住整整一个读超时周期。现在先结束的那个方向会显式触发对面连接的 close/`CloseWrite`，两个方向无论谁先出错都会立刻一起收尾。

### 并发流上限（DP-03 / DP-27）

新增两个服务端参数，限制同时打开的数据面流数量（HTTP/WebSocket/TCP 代理流，不包括控制通道的流）：

- `--max-concurrent-streams`（默认 10000）：进程级全局计数器。触顶后新的建流请求直接拒绝（不排队），使流量突增时表现可预测（快速拒绝），而不是无限制地增长 goroutine/内存占用。
- `--max-streams-per-client`（默认 500）：同样的思路，但作用范围收窄到单个客户端连接，避免某一个异常活跃或行为异常的租户独占全局额度，饿死其他客户端。

两者都用 `atomic.Int64` 计数器实现，在分发流之前递增、流结束时递减；获取名额是非阻塞的（check-then-increment），与"快速拒绝"的设计取向一致，而不是引入一个阻塞式 semaphore（那本身可能成为新的排队瓶颈）。

### 控制帧校验（DP-17）

此前 `DecodeControlMessage` 会接受任何能被 protobuf 反序列化成功的字节序列——包括全零或垂直解码到 `MessageType_MESSAGE_TYPE_UNKNOWN` 且所有 oneof 字段都为空的垃圾输入。现在这类输入会被显式拒绝（`errUnknownEmptyMessage`），因为它只可能是畸形/损坏的输入，不会是合法消息。校验条件刻意设计得很窄：如果一条 `Type == UNKNOWN` 的消息**确实**携带了可识别的 payload（session 或 P2P），仍会被接受，为将来某个更新的 client 向较旧 server 发送新消息类型保留前向兼容性。

### 协议版本门禁与真实能力广播（DP-30 / DP-33）

- **版本门禁**：`pkg/version` 新增了一个极简的 semver 解析器/比较器（`ParseSemver`、`Compare`）——刻意不用完整的 semver 库，因为 Wormhole 只需要 `MAJOR.MINOR.PATCH` 比较，不需要预发布/构建元数据排序。服务端新增的 `--min-client-version` 参数会拒绝声明版本过旧的 `AuthRequest`，并给出明确的认证失败原因。非正式发布构建（例如 `dev`、空字符串）的 client 在 semver 解析阶段就会失败，这类 client 刻意**永远不会**被拒绝——版本门禁是运维方的可选开关，不是运行未发布构建的硬性门槛。
- **真实能力集**：`AuthResponse.Capabilities` 此前不存在/始终为空。服务端现在从 `Server.capabilities()` 填充该字段，该方法根据服务端的实际运行时配置（而非硬编码的理想列表）推导出能力列表（`p2p`、`multi-tunnel`、`cluster`、`audit` 等）。客户端保存服务端广播的能力集，并据此决定是否尝试可选行为——例如 `sendP2POffer` 现在会在服务端没有广播 `"p2p"` 时直接跳过整个发送逻辑，而不是照常发送一个 offer 靠服务端静默忽略。缺失/为空的能力列表（例如来自一个早于此字段的旧版 server）会被视为"未知，默认全部支持"以保持向后兼容。

### 死代码清理（DP-15）

`pkg/tunnel/pool.go` 实现了一个连接池抽象，但从未被任何调用方接线——`Client`/`Server` 始终是每个连接新建一个 `Mux`，而不是从池里取。既然它和它的测试从未被真正使用，与其作为不可达代码继续增加维护负担和覆盖率噪音，不如直接删除。

### UDP 协议清理（V1）

此前客户端 CLI 和配置文件都把 `udp` 列为 `--protocol` 的可选值，但服务端从未实现 UDP 数据面（只有 P2P 子系统使用 UDP，且是作为可靠 `UDPMux`/`UDPStream` 层下面的**传输层**，从未作为原始隧道协议对外暴露）。`ValidateProtocolString` 现在会在客户端/配置文件层显式拒绝 `udp` 并给出可操作的错误信息，而不是静默降级为 HTTP 语义，或者让一个令人困惑的失败深埋在服务端某处才暴露出来。`parseProtocol`（用于更底层场景，例如已持久化的状态）仍然把未识别的字符串兜底为 HTTP 而不报错，以保持对已有持久化配置的向后兼容。

### CLI 能力补全（U1 / U4）

- **`wormhole tunnels create/delete`（U1）**：客户端控制 API（`pkg/client/control.go`，与现有的 `list` 接口一样需要 `--ctrl-port`）新增了 `POST /tunnels` 和 `DELETE /tunnels/{name}`，背后由新增的 `Client.CreateTunnel`/`Client.DeleteTunnel` 方法支撑，可以在一个已经运行的 client 进程上注册/注销隧道。这是"编辑 YAML 配置再发 `SIGHUP`"的命令式替代方案——适合脚本化操作或临时隧道，完全不需要触碰 client 的持久化配置。以这种方式新增的隧道不会被持久化，除非同时也写进配置文件，否则不会在 client 重启后保留。
- **`wormhole server -c server.yml`（U4）**：`pkg/server/config_file.go` 沿用了客户端现有的 `FileConfig`/`LoadClientFileConfig` 模式——用一个 `FileConfig` 结构体把 YAML schema 映射到服务端配置（包括自定义的 `time.Duration` 字符串解析），`validate()` 在加载时就捕获畸形取值（错误的时长字符串、未知的持久化/后端枚举值），而不是让错误在深入到 `Config` 消费者内部时才以令人困惑的方式暴露；`ToServerConfig(base)` 只把文件里明确设置的字段合并到一个 base 配置（通常是 `DefaultConfig()`）上，其余字段保持不变。需要真三态（未设置 / 明确 false / 明确 true）的布尔字段——例如 `EnableMetrics`——用 `*bool` 而不是 `bool`，因为普通 `bool` 无法区分"文件里没提到"和"文件里写了 false"。

---

## 热路径分配池化 (P3-6 批次 B)

P3-6 第二个子批次针对 `review-v0.6.md` 中标出的、影响面最大的热路径分配问题（DP-09/DP-11/DP-12），全部集中在数据转发路径而非控制路径——这正是负载上升时按字节/按连接的成本会真正累积起来的地方。context 贯通（批次 C）和上帝对象拆分（批次 D）是独立的、更靠后的子批次；这一批刻意只聚焦在分配削减，外加一个在审查同一批代码时顺带发现的正确性问题。

### Mux 数据发送缓冲池 (DP-09)

`Stream.Write` 把待发出的数据切成不超过 32KB（`DefaultFramePayloadSize`）的分片，逐个交给 `Mux.sendData`——此前每次调用都会执行 `payload := make([]byte, len(data)); copy(payload, data)`，即每次写入都有一次全新的堆分配，之所以需要拷贝是因为帧要经 `sendCh` 异步传给 `sendLoop`，调用方（往往是 `io.CopyBuffer`）可能在这次写入真正发生之前就复用了自己的缓冲区。

`Mux` 现在持有一个 `dataBufPool`（`sync.Pool`，元素是指向 `DefaultFramePayloadSize` 大小切片的 `*[]byte`）。`sendData` 从池里借一个够大的缓冲区而不是重新分配；`writeFrame`（运行在 `sendLoop` 里）在 `FrameCodec.Encode` 把它写进连接之后立刻归还——这是安全的，因为 `Encode` 调用返回后从不再持有该 payload 的引用。不是从池里来的帧（目前不会出现，因为唯一的调用方 `Stream.Write` 每次请求都不超过 32KB）会退回普通的 `make`，所以这个实现并不依赖"`sendData` 只有这一条调用路径"这个假设。

用 `BenchmarkMux_SendData` 测得（该基准隔离了 `sendData` 本身，绕开 `Stream` 的 Read/Write 和帧解码开销，对端只是排水式读取原始字节而不解析）：

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| B/op | 32817 | 85 | **-99.7%** |
| allocs/op | 2 | 2 | 不变 |
| ns/op | 7333 | 4274 | **-42%** |
| MB/s | 4468 | 7667 | **+72%** |

端到端测试（`BenchmarkMux_Throughput`，32KB 写入，经过完整的收发栈）：B/op 65733 → 34308（**-47.8%**），ns/op 14525 → 10026（**-31%**），MB/s 2256 → 3268（**+45%**）。用 `go tool pprof -diff_base` 对比同一基准两次运行的 heap profile，`(*Mux).sendData` 的 flat 分配减少了 **3.01GB**（100000 次迭代样本），扣除池本身新增的少量开销（`sync.Pool.Get`/`newMux` 的池初始化，+0.13GB）后净减少 **2.88GB**。

### 池化转发缓冲区 (DP-11)

此前每条双向代理循环都直接调用裸 `io.Copy`，只要源/目标没有实现 `io.WriterTo`/`io.ReaderFrom`（这里涉及的真实 `net.Conn`/`tunnel.Stream` 类型都没有），它就会在每次调用时分配自己的 32KB 内部临时缓冲区。对于短生命周期的代理连接——这是最常见的场景，也正是 `MaxConcurrentStreams`/`MaxStreamsPerClient`（DP-03/27）所限制的连接规模——这意味着每条连接仅仅为了搭建拷贝循环就要付出整整 32KB 的分配代价。

`copyWithPooledBuffer(dst, src)` 是 `io.Copy` 的直接替代品，它从一个包级 `copyBufPool`（`pkg/server` 和 `pkg/client` 各有一个——不同包所以是各自独立的池）借一个临时缓冲区，通过 `io.CopyBuffer` 完成拷贝后再归还。它替换了所有转发用途的 `io.Copy` 调用：

- **服务端**（`pkg/server/handler.go`）：`forwardHTTP` 里的 HTTP 响应体拷贝，以及 `handleWebSocket` 里 WebSocket 代理的两个方向。
- **服务端**（`pkg/server/server.go`）：`handleTCPConnection` 手写的 Read/Write 循环现在从同一个 `copyBufPool` 取每个 goroutine 用的缓冲区，而不是本地 `make([]byte, 32*1024)`——这里此前就已经是整条连接生命周期内复用同一个缓冲区（不是每次迭代都分配），但池化之后可以把总内存限制住，而不是 `2 × 32KB × MaxConcurrentStreams` 同时全部存活。
- **客户端**（`pkg/client/client.go`）：`dialAndProxy`（中继模式 HTTP/TCP 转发）和 `proxyConnectConn`（`wormhole connect` 的直连 P2P 数据路径）的两个方向。

这些拷贝产生的错误此前直接丢弃（`_, _ = io.Copy(...)`），现在会以 `Debug` 级别记录下来（不用 `Error`，因为客户端在拷贝中途断开是预期内、不需要处理的事件，不是故障）。

用一对基准测试（`BenchmarkIOCopy_Baseline` 对 `BenchmarkCopyWithPooledBuffer`）测得，测试中故意用包装类型隐藏了 `WriterTo`/`ReaderFrom`，强制 `io.Copy` 走它的通用缓冲路径，以匹配真实连接的行为：

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| B/op | 36992 | 4244 | **-88.5%** |
| allocs/op | 6 | 5 | -1 |
| ns/op | 3938 | 821.8 | **-79%** |

### Inspector 读取 OOM 修复 (DP-12)

这不是性能改动，而是在审查同一批转发代码时顺带发现的问题：`forwardHTTPWithInspect` 的注释声称请求/响应正文"受 MaxBodySize 限制"，但实际的读取（`io.ReadAll(httpReq.Body)`、`io.ReadAll(resp.Body)`）根本没有任何限制——只要开启 `--inspector` 并收到一次足够大的上传/下载，就会无视配置的上限把它整个缓冲进内存。现在两处读取都包了一层 `io.LimitReader(body, MaxBodySize+1)`（这个 `+1` 让下游的截断检测逻辑能区分"刚好等于上限"和"超过上限"，与 `Inspector.Wrap` 已经在用的约定一致）。`Inspector` 新增了 `MaxBodySize()` 访问器，方便 `inspector` 包外的调用方按 `Capture` 实际会存储的口径来限定自己的读取。

这也意味着超过 `MaxBodySize` 的正文会在转发给本地服务**之前**就被截断，而不只是在记录之前——这和 `Inspector.Wrap` 早就在做的取舍一样，而且只影响开启了检查器的这条代码路径：不带检查的中继/P2P 转发（`forwardRawTCP`、`dialAndProxy`，见上面的 DP-11）未受影响，仍然完全不设上限，因为 Inspector 本身的定位是调试辅助工具，而不是给生产环境大流量场景开启的东西。

---

## context 贯通 (P3-6 批次 C)

P3-6 第三个子批次收尾了 `review-v0.6.md` 中的 DP-05/DP-06：服务端调用树深处的若干操作直接使用 `context.Background()`，导致进行中的 `Shutdown()` 完全无法打断它们——每一个都只会在自身的固定超时（例如 `AuthTimeout`）耗尽之后才返回，不管那需要多久。上帝对象拆分（批次 D）仍是独立的、更靠后的子批次。

### 服务端根 context (DP-05)

`Server.Start(ctx)` 现在把 `s.rootCtx, s.rootCancel = context.WithCancel(ctx)` 作为第一步执行。`Shutdown()` 在 `close(s.closeCh)` 之后立刻调用 `s.rootCancel()`——发生在优雅关闭 HTTP/管理监听、关闭其他附属资源**之前**——这样任何仍在监听这个 context 的 goroutine 都能尽早看到取消信号。

新增的 `serverCtx()` 访问器：已设置 `s.rootCtx` 时返回它，否则返回 `context.Background()`。这个兜底在实践中很重要：`pkg/server` 的大量单测都是直接调用 handler 方法（`authenticateClient`、`handleRegister`、`handleTCPConnection` 等），从未经过 `Start`，`serverCtx()` 能让这些测试原样继续工作，而不需要每个测试都先伪造一个根 context。

此前硬编码 `context.Background()` 的 4 处调用点现在改用 `s.serverCtx()`：

| 调用点 | 控制的操作 |
|--------|-----------|
| `authenticateClient` | 认证握手初始流的 `AcceptStreamContext` 超时 |
| `handleRegister` | 为 TCP 隧道分配监听端口时的 `portAllocator.Allocate` |
| `notifyPeerOfP2P` | 打开通知 P2P 对端的流时的 `OpenStreamContext` |
| `handleTCPConnection` | 打开到 client 的每连接流时的 `OpenStreamContext` |

这些改动在正常运行期间不改变任何行为——`s.serverCtx()` 在 `Shutdown` 取消它之前，行为与 `context.Background()` 完全一致。影响只体现在关闭路径上：一个卡在握手中途的 client，或一个正等待端口分配的 TCP 隧道连接，不再需要拖着优雅关闭等到自身超时耗尽。

### 感知 ctx 取消的流 I/O (DP-06)

`OpenStreamContext(ctx)` 本身只在发送握手帧之前检查过一次 `ctx`——它从不阻塞等待回复，这部分本来就没问题。DP-06 指出的缺口在下游：调用方一旦拿到返回的 `*Stream`，普通的 `Read`/`Write` 方法就完全无法感知任何 context 了。它们只能通过 `SetDeadline`/`SetReadDeadline`/`SetWriteDeadline`，或者流/mux 直接关闭来打断——如果调用方是用一个可取消的 `ctx` 打开流的，这个取消能力在 `OpenStreamContext` 返回的那一刻就丢失了。

`pkg/tunnel/stream.go` 现在暴露 `ReadContext(ctx, p)` 和 `WriteContext(ctx, p)`；`Read`/`Write` 变成薄封装，把 `context.Background()` 传给它们。这里的关键设计约束是：数据面热路径（`io.CopyBuffer` 之类，永远调用不带 ctx 的 `Read`/`Write`）不能因此多付出任何代价。这正是为什么 ctx 感知能力是按调用逐次选择加入的，而不是直接砌进阻塞等待本身：

- 如果 `ctx.Done()` 为 `nil`（`context.Background()` 就是这样），不会启动任何 watcher goroutine，方法行为与改动前完全一致——热路径零额外开销。
- 如果 `ctx` 是可取消的，一个短生命周期的 goroutine 会在这次调用期间监听 `ctx.Done()`，一旦触发就对相应的 `sync.Cond`（`readCond`/`sendCond`）调用 `Broadcast()`，提前唤醒被阻塞的等待者；读/写循环在每次被唤醒时都会检查 `ctx.Err()`（在既有的超时/关闭/窗口检查之外），一旦设置就立刻返回。

`waitForSendWindow` 是从 `WriteContext` 中拆出来的，纯粹是为了让其圈复杂度落在项目 `golangci-lint`（`gocyclo`）的阈值以内——不包含任何新行为，只是既有的发送窗口等待循环。

`authenticateClient` 读取传入的 `AuthRequest` 时现在调用 `stream.ReadContext(ctx, buf)`，用的正是前面 DP-05 派生自 `s.serverCtx()` 的同一个 `ctx`，把 DP-05 和 DP-06 串联到了审查报告特别指出的这一个调用点上：`TestServer_AuthenticateClient_ServerCtxCancelUnblocks` 把 `AuthTimeout` 设为 30 秒，在握手阻塞等待 client 的 `AuthRequest` 期间取消服务端根 context，断言该调用在几十毫秒内以 `context.Canceled` 返回，而不是等满 30 秒。

`ReadContext`/`WriteContext` 出现之后，`golangci-lint` 的 `contextcheck` 分析器在 `pkg/client/client.go` 里发现了 14 处同样的模式——每一个控制面 RPC（`authenticate`、`registerTunnel`、`registerOneTunnel`、`sendPing`、`sendP2POffer`、`sendP2PResult`、`RequestStats`、`CloseTunnel`）都已经接收了 `ctx` 参数，却仍然调用不带 ctx 的 `Read`/`Write`。这些正是 DP-06 同一个缺口在客户端侧的镜像——一个被取消的 `ctx`（比如来自 `Client.Close()` 或调用方指定的 deadline）此前一样无法打断进行中的控制面 RPC，跟服务端的情况一样。这 14 处全部改为对应的 `*Context` 变体，用的就是各自函数体里已经有的那个 `ctx`。

---

## 数据流总结

### HTTP 请求完整路径

```
Browser → DNS → Server:80/443
  → TLS 终止
  → Router.Route(Host, Path) → 找到 ClientSession
  → resolveTunnelID(client, Host, Path) → 判定具体是哪个已注册的隧道（多隧道场景）
  → Mux.OpenStream() → 新 Stream
  → sendStreamRequest(metadata，含 TunnelID)
  → r.Write(stream) [原始 HTTP 请求]
  ─── 经 Mux 帧编码 → TCP 连接 → 到达 Client ───
  → handleStream() → 读取 StreamRequest 元数据
  → resolveLocalAddr(TunnelID) → 得到该隧道的 LocalHost:LocalPort
  → forwardToLocal()
    → (Inspector 启用?) forwardHTTPWithInspect()
      → http.ReadRequest() 解析
      → http.Transport.RoundTrip(localService)
      → inspector.Capture() 记录
      → resp.Write(stream) 写回
    → (Inspector 未启用?) forwardRawTCP()
      → io.Copy 双向透传
  ─── 响应经 Mux 帧编码 → TCP 连接 → 到达 Server ───
  → http.ReadResponse()
  → copyHeaders() + X-Wormhole-* headers
  → w.WriteHeader() + io.Copy(w, resp.Body)
  → Browser 收到响应
```
