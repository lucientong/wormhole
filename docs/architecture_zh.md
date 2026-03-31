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
- [P2P 直连](#p2p-直连)
- [连接管理](#连接管理)
- [安全模型](#安全模型)

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
         │ Browser  │  │  curl   │  │  gRPC   │
         │  用户    │  │  客户端  │  │  客户端  │
         └────┬─────┘  └────┬────┘  └────┬────┘
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
| `Server` | `cmd/server/server.go` | 核心控制器，管理客户端会话、协调各组件 |
| `HTTPHandler` | `cmd/server/handler.go` | HTTP 反向代理，将请求通过隧道转发给 Client |
| `Router` | `cmd/server/router.go` | Host/Path 路由表，支持子域名、自定义域名和路径前缀 |
| `TLSManager` | `cmd/server/tls.go` | TLS 终止，支持 Let's Encrypt 自动证书和手动证书 |
| `AdminAPI` | `cmd/server/admin.go` | RESTful 管理 API |
| `TCPPortAllocator` | `cmd/server/handler.go` | 为 TCP 隧道分配端口 |

### Client 端组件

| 组件 | 位置 | 职责 |
|------|------|------|
| `Client` | `cmd/client/client.go` | 核心控制器，管理连接、转发、重连 |
| `Inspector` | `pkg/inspector/inspector.go` | HTTP 流量捕获和记录 |
| `Handler` | `pkg/inspector/handler.go` | Inspector HTTP API + WebSocket 推送 |
| `Storage` | `pkg/inspector/storage.go` | 请求记录环形缓冲存储 |
| `WebSocket Hub` | `pkg/inspector/websocket.go` | 实时推送新请求到浏览器 |
| `Web Server` | `pkg/web/handler.go` | 嵌入式静态文件服务（Inspector UI） |

### 核心库

| 包 | 位置 | 职责 |
|---|------|------|
| `tunnel` | `pkg/tunnel/` | 多路复用器、帧编解码、流管理、连接池 |
| `proto` | `pkg/proto/` | 控制协议消息定义（JSON 编码） |
| `auth` | `pkg/auth/` | 认证授权（HMAC Token、角色权限） |
| `p2p` | `pkg/p2p/` | STUN 客户端、NAT 发现、UDP 打洞、端口预测 |
| `version` | `pkg/version/` | 构建版本信息 |

---

## 隧道多路复用协议

### 设计目标

在 **单个 TCP 连接** 上运行多个逻辑 Stream，避免为每个请求建立新连接。

### 架构

```
┌─────────────────────────────────────────────────┐
│              Single TCP Connection               │
│                                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ Stream 1 │ │ Stream 2 │ │ Stream 3 │   ...   │
│  │ (Control)│ │ (HTTP #1)│ │ (HTTP #2)│         │
│  └──────────┘ └──────────┘ └──────────┘         │
│       │             │             │               │
│       ▼             ▼             ▼               │
│  ┌───────────────────────────────────────────┐   │
│  │               Mux (多路复用器)              │   │
│  │                                           │   │
│  │  • Stream 创建/销毁                        │   │
│  │  • 帧分发 (根据 StreamID)                   │   │
│  │  • 流量控制 (WINDOW_UPDATE)                 │   │
│  │  • 心跳检测 (PING/PONG)                     │   │
│  └───────────────────────────────────────────┘   │
│       │                                           │
│       ▼                                           │
│  ┌───────────────────────────────────────────┐   │
│  │            Frame Codec (帧编解码)           │   │
│  │                                           │   │
│  │  [Version][Type][StreamID][Length][Payload]│   │
│  └───────────────────────────────────────────┘   │
│       │                                           │
│       ▼                                           │
│  ┌───────────────────────────────────────────┐   │
│  │               net.Conn (TCP)               │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### Stream 生命周期

```
  Client                                Server
    │                                      │
    │  ── OpenStream() ──►                 │
    │     (发送 HANDSHAKE 帧)              │
    │                                      │  ◄── AcceptStream()
    │                                      │
    │  ◄── DATA 帧 (StreamID=N) ──        │
    │  ── DATA 帧 (StreamID=N) ──►        │
    │  ── WINDOW_UPDATE (StreamID=N) ──►   │
    │                                      │
    │  ── CLOSE 帧 (StreamID=N) ──►       │
    │     (stream 关闭)                    │
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

控制消息使用 JSON 编码，通过 Mux Stream 传输（每条消息使用独立的 Stream）。

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
    │ ◄──── Mux Handshake ──────────────►   │  (隧道层握手)
    │                                        │
    │ ── [Stream 1] AuthRequest ──────────► │  (若启用认证)
    │     { token: "xxx",                   │
    │       version: "1.0",                 │
    │       subdomain: "myapp" }            │
    │                                        │  → 验证 Token
    │                                        │  → 检查 connect 权限
    │ ◄── [Stream 1] AuthResponse ──────── │
    │     { success: true,                  │
    │       subdomain: "myapp",             │
    │       session_id: "abc123" }          │
    │                                        │
    │ ── [Stream 2] RegisterRequest ──────► │
    │     { local_port: 8080,               │
    │       protocol: "HTTP",               │
    │       subdomain: "myapp" }            │
    │                                        │  → 分配子域名
    │                                        │  → 注册路由
    │ ◄── [Stream 2] RegisterResponse ──── │
    │     { success: true,                  │
    │       tunnel_id: "abc123",            │
    │       public_url: "http://myapp.ex.." }│
    │                                        │
    │ ── [Stream 3] PingRequest ──────────► │  (定时心跳)
    │ ◄── [Stream 3] PingResponse ──────── │
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
    │                     │ ──────────────────► │ 5. ReadRequest()  │
    │                     │  (原始 HTTP 请求)    │    解析 HTTP       │
    │                     │                     │                    │
    │                     │                     │ 6. RoundTrip()    │
    │                     │                     │ ──────────────────►│
    │                     │                     │                    │
    │                     │                     │ ◄── HTTP Response ─│
    │                     │                     │                    │
    │                     │                     │ 7. Capture()       │
    │                     │                     │    (Inspector 记录) │
    │                     │                     │                    │
    │                     │ ◄── resp.Write() ── │ 8. 写回 stream     │
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
    │ ── data ──────────► │ ── stream ────────► │ ── data ─────────►│
    │ ◄── data ────────── │ ◄── stream ──────── │ ◄── data ──────── │
    │                     │                     │                    │
    │   (双向 io.Copy 透传，直到任一方关闭)       │                    │
```

TCP 隧道不经过 Inspector，因为没有 HTTP 语义可解析。

---

## Inspector 流量捕获

### 架构

```
                    ┌──────────────────────────┐
                    │    Inspector (核心)       │
                    │                          │
  forwardHTTP ────► │  Capture(req, resp, ...)  │
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
                    │  GET /api/requests       │ ◄── 历史记录查询
                    │  GET /api/requests/:id   │ ◄── 详情
                    │  WS  /api/ws             │ ◄── 实时流
                    │  DELETE /api/requests     │ ◄── 清空
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

## P2P 直连

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

### 当前实现状态

Phase 4 提供了 P2P 的基础原语：

| 组件 | 文件 | 状态 |
|------|------|------|
| **NAT 类型定义** | `pkg/p2p/nat.go` | ✅ 完成 — Full Cone, Restricted, Port Restricted, Symmetric |
| **STUN 客户端** | `pkg/p2p/stun.go` | ✅ 完成 — RFC 5389 Binding, 双服务器 NAT 分类 |
| **UDP 打洞** | `pkg/p2p/hole_punch.go` | ✅ 完成 — WHPP 魔数前缀的 probe/ack 协议 |
| **端口预测器** | `pkg/p2p/predictor.go` | ✅ 完成 — 基于 delta 的 Symmetric NAT 端口预测 |
| **P2P 管理器** | `pkg/p2p/manager.go` | ✅ 完成 — 协调 STUN + 打洞 + 中继降级 |
| **信令消息** | `pkg/proto/messages.go` | ✅ 完成 — P2POfferRequest/Response, Candidates, Result |
| **客户端集成** | `cmd/client/client.go` | ✅ 部分 — 启动时 NAT 发现，发送 P2P Offer |
| **服务端信令** | `cmd/server/server.go` | ✅ 部分 — 接收 P2P Offer，存储 NAT 信息 |

### NAT 类型分类

| NAT 类型 | 打洞难度 | 策略 |
|---------|---------|------|
| Full Cone | ★☆☆☆ | 直接连接，几乎必成功 |
| Restricted Cone | ★★☆☆ | 需要先从内部发出探测包 |
| Port Restricted Cone | ★★★☆ | 需要匹配端口的探测包 |
| Symmetric | ★★★★ | 端口预测 + 多次尝试，成功率较低 |

### 降级策略

```
尝试 P2P 直连
    │
    ├── 成功 → 使用 P2P 通道传输
    │
    └── 失败 → 自动降级到 Server 中继（当前架构）
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
超时动作: 标记连接异常，触发重连
```

### 连接池

`pkg/tunnel/pool.go` 提供连接池管理：

- 复用已有 Mux 连接
- 健康检查（定期 Ping）
- 自动清理过期连接
- 预建立连接降低首次请求延迟

---

## 认证授权

### 概述

Wormhole 支持可选的认证机制，保护服务端不被未授权客户端连接。认证模块位于 `pkg/auth/`。

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

### 认证握手流程

```
  Client                                Server
    │                                      │
    │  ── Mux.OpenStream() ──►            │
    │                                      │  ◄── Mux.AcceptStream()
    │                                      │      (带超时，默认 10s)
    │                                      │
    │  ── AuthRequest ──────────────────► │
    │     { token: "xxx",                 │
    │       version: "1.0.0",             │
    │       subdomain: "myapp" }          │
    │                                      │  1. ValidateToken(token)
    │                                      │     → 先尝试 simple 匹配
    │                                      │     → 再尝试 HMAC 验证
    │                                      │  2. HasPermission(claims, "connect")
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
- `/stats`、`/clients`、`/tunnels` 受 `--admin-token` 保护
- 使用 `Authorization: Bearer <token>` 头
- Token 比较使用 `crypto/subtle.ConstantTimeCompare` 防止时序攻击

---

## 安全模型

### 传输加密

- Server 支持 TLS 终止（Let's Encrypt 自动证书 或 手动证书）
- Client-Server 隧道连接可选 TLS 加密

### 认证

- 双模式 Token 认证：HMAC-SHA256 签名 Token（团队管理） + 简单预共享 Token（快速部署）
- 基于 HMAC-SHA256 的 Token 生成/验证，nonce 防重放
- 角色权限控制（RBAC）：admin、member、viewer 三级角色
- 连接握手时强制认证（`--require-auth`），viewer 角色无法建立隧道连接
- Admin API 独立 Token 保护，使用常量时间比较防时序攻击

### 输入验证

- Host header 路由时做 HTML 转义（防 XSS）
- 子域名只允许单级标签（无点号）
- 路径前缀规范化（首尾 `/`）

### 速率限制

- `MaxClients` 限制同时在线客户端数
- TCP 端口分配范围限制（默认 10000-20000）

---

## 数据流总结

### HTTP 请求完整路径

```
Browser → DNS → Server:80/443
  → TLS 终止
  → Router.Route(Host, Path) → 找到 ClientSession
  → Mux.OpenStream() → 新 Stream
  → sendStreamRequest(metadata)
  → r.Write(stream) [原始 HTTP 请求]
  ─── 经 Mux 帧编码 → TCP 连接 → 到达 Client ───
  → handleStream() → 读取 StreamRequest 元数据
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
