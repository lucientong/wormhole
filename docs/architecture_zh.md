# Wormhole 架构指南

> 本文档详细描述 Wormhole 的系统架构、网络协议设计和数据流。它同时也是一篇学习指南：如果你是第一次接触本项目，请从[如何阅读本文档与代码](#如何阅读本文档与代码)开始。

**[English](architecture.md)**

## 目录

- [如何阅读本文档与代码](#如何阅读本文档与代码)
- [系统概览](#系统概览)
- [组件架构](#组件架构)
- [设计决策与权衡](#设计决策与权衡)
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
- [多隧道配置与热重载](#多隧道配置与热重载)
- [HA / 多节点控制面](#ha--多节点控制面)
- [Server 与 Client 组合](#server-与-client-组合)
- [可靠性与协议保障](#可靠性与协议保障)
- [热路径性能](#热路径性能)
- [调试与运维手册](#调试与运维手册)
- [本项目使用的 Go 模式](#本项目使用的-go-模式)
- [测试策略](#测试策略)
- [数据流总结](#数据流总结)

---

## 如何阅读本文档与代码

Wormhole 刻意保持极小的依赖面——多路复用器、可靠 UDP 传输、控制协议都在本仓库内自行实现而非引入第三方库。这使它非常适合用来端到端地学习一个内网穿透系统是如何工作的。下面按可投入的时间给出三条阅读路径。

### 30 分钟——先跑起来，认识各个组成部分

1. 构建并运行三终端演示：一个终端跑 `wormhole server`，另一个跑本地 HTTP 服务（`python3 -m http.server 8080`），第三个跑 `wormhole 8080`，然后 `curl` 公网 URL。
2. 阅读[系统概览](#系统概览)与[组件架构](#组件架构)，把刚才跑起来的进程对应到图中的方块上。
3. 打开 Inspector UI（client 启动时会打印地址），观察一个请求的完整流转。

### 2 小时——理解 relay 转发路径

按以下顺序读代码，每一步建立在前一步之上：

1. `pkg/tunnel/frame.go`——9 字节帧头。线上传输的一切都是这样一个个帧。
2. `pkg/tunnel/mux.go` 与 `pkg/tunnel/stream.go`——多个逻辑 Stream 如何共享一条 TCP 连接，流控如何防止一个 Stream 饿死其他 Stream。配合[隧道多路复用协议](#隧道多路复用协议)阅读。
3. `pkg/proto/messages.go`——跑在 stream 1 上的控制消息（注册、鉴权、心跳）。配合[控制协议](#控制协议)阅读。
4. `pkg/server/server.go`（组合根）→ `pkg/server/proxy_service.go`（`ServeHTTP` 是公网请求与隧道 Stream 交汇的地方）。
5. `pkg/client/relay_client.go`——client 侧的镜像：拨号、鉴权、注册、接收流、重连。

配套命令：`go test -run TestMux ./pkg/tunnel/...`、`go test -run TestHandler ./pkg/server/...`。

### 1 天——P2P、HA 与安全层

6. `pkg/p2p/nat.go` → `hole_punch.go` → `stream.go` → `crypto.go`——NAT 探测、打洞、自研可靠 UDP ARQ、端到端加密。配合 [P2P 直连](#p2p-直连)阅读；ARQ 部分是全仓库密度最高的代码。
7. `pkg/client/p2p_session.go` 与 `pkg/server/p2p_broker.go`——直连建立之前，`wormhole connect` 的信令如何经由 relay 流转。
8. `pkg/server/state_redis.go` 与 `pkg/server/tunnel_registry.go`——集群路由、TTL 心跳、跨节点代理。配合 [HA / 多节点控制面](#ha--多节点控制面)阅读。
9. `pkg/auth/`——HMAC token、OIDC 验证、OAuth Device Flow、RBAC、审计日志。

之后有两个章节把整个设计串起来：[设计决策与权衡](#设计决策与权衡)解释各主要组件*为什么*这样设计，[本项目使用的 Go 模式](#本项目使用的-go-模式)则整理了值得借鉴的语言技巧。

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
| `Server` | `pkg/server/server.go` | 组合根（composition root），装配 `TunnelRegistry`/`ProxyService`/`P2PBroker` 并持有监听器生命周期（详见[Server 与 Client 组合](#server-与-client-组合)） |
| `TunnelRegistry` | `pkg/server/tunnel_registry.go` | 客户端会话生命周期；本地与集群路由（子域名/hostname/path）；TCP 端口分配；集群心跳与状态存储健康度 |
| `ProxyService` | `pkg/server/proxy_service.go` | HTTP/WebSocket/TCP 数据面转发（即 `http.Handler`）；全局/单客户端并发流预算；跨节点代理兜底。替代原来的 `HTTPHandler` |
| `P2PBroker` | `pkg/server/p2p_broker.go` | `wormhole connect` 信令：offer 匹配、NAT 兼容性判断、端口预测候选生成 |
| `Router` | `pkg/server/router.go` | Host/Path 路由表，支持子域名、自定义域名和路径前缀 |
| `TLSManager` | `pkg/server/tls.go` | TLS 终止，支持 Let's Encrypt 自动证书和手动证书 |
| `AdminAPI` | `pkg/server/admin.go` | RESTful 管理 API |
| `TCPPortAllocator` | `pkg/server/tunnel_registry.go` | 为 TCP 隧道分配端口 |
| `StateStore` | `pkg/server/state*.go` | 集群共享状态（子域名/hostname/path 路由 + 节点信息）；内存或 Redis 后端 |
| 集群心跳 | `pkg/server/tunnel_registry.go` | 周期心跳 + 路由 TTL 刷新、失效节点驱逐、跨节点 HTTP 代理、共享密钥校验 |

### Client 端组件

| 组件 | 位置 | 职责 |
|------|------|------|
| `Client` | `pkg/client/client.go` | 组合根（composition root），装配 `RelayClient`/`P2PSession`，汇总 `Stats`，持有 inspector 及本地控制/inspector HTTP 服务，并实现两者共用的 `localForwarder`/`statsRecorder` 回调接口（详见[Server 与 Client 组合](#server-与-client-组合)） |
| `RelayClient` | `pkg/client/relay_client.go` | 控制面连接生命周期：拨号（+TLS）、鉴权（含 token 刷新）、单/多隧道注册、心跳、接收入站流、重连循环 |
| `P2PSession` | `pkg/client/p2p_session.go` | `wormhole connect` / P2P 打洞生命周期：NAT 探测、ECDH 密钥交换、打洞、复用的 P2P 传输层、connect 模式本地监听器 |
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

## 设计决策与权衡

本节记录主要的"自研 vs 引库"与设计取舍背后的理由，让读者可以评判这些选择，而不是把它们当成既定事实。

### 自研多路复用器，而非 yamux / QUIC

隧道 mux（`pkg/tunnel`）从零实现，没有使用 `hashicorp/yamux` 或 QUIC 库。

- **为什么**：完全掌控帧格式，使控制信道（stream 1）、协议版本协商、capability 交换可以直接内嵌在同一条连接里而无需适配层；Inspector 可以原生感知 Stream 边界；帧编解码器还可复用为 P2P 的分帧层。QUIC 能免费带来 stream 与流控，但引入巨大依赖，且只有 UDP 传输（在只放行 TCP:443 的受限网络里，relay 存在的意义恰恰是走 TCP），教学价值也远不如自研。
- **代价**：流控和 keep-alive 逻辑需要自己维护和测试——这也是 `pkg/tunnel` 拥有全仓库最高测试覆盖率（>90%）的原因。
- **设计呼应**：API 刻意模仿 `net.Listener`/`net.Conn`（`mux.Accept()`、`stream.Read/Write/Close`），消费 Stream 的代码不需要知道自己面对的不是普通 TCP 连接。

### P2P 自研可靠 UDP，而非 KCP / QUIC

P2P 数据面（`pkg/p2p/stream.go`）实现了自己的 ARQ：滑动窗口、RFC 6298 RTO 估计（SRTT/RTTVAR + Karn 算法）、快速重传、以及通过扣留 ACK 实现背压。

- **为什么**：打洞出来的 UDP 路径需要一个从"同时打开"握手起步、并在数据报之上直接叠加端到端加密（X25519 + AES-256-GCM）的会话。KCP 用带宽换延迟（激进重传），对隧道大流量场景是错误的取舍。QUIC 同样可行，但会把本项目想展示的机制全部藏进黑盒。
- **代价**：除 ARQ 窗口外没有拥塞控制；在高丢包长肥管道上，成熟库的表现会更好。

### Protobuf + JSON 兜底

控制消息用 Protobuf 编码，但所有解码器先尝试 Protobuf、失败后回退 JSON（`pkg/proto/messages.go`）。

- **为什么**：项目最初用 JSON；Protobuf 迁移期间通过双格式保持了与旧 client 的线上兼容。双解码也便于用脚本手工调试。
- **护栏**：长度前缀 + 硬性 `maxControlMessageSize` 上限；空 payload / 未知消息直接拒绝，而不是静默解出零值。

### Redis 作为唯一的分布式状态存储

HA 模式（`pkg/server/state_redis.go`）使用 Redis 存 TTL 刷新的路由键，没有 etcd/共识方案。

- **为什么**：路由是软状态——每条记录都由持有节点的心跳周期性重新宣告，所以存储只需要快速查找 + TTL 过期，不需要共识。Redis 挂掉退化为单节点行为，而不是把数据面拖垮。
- **取舍**：注册没有线性一致性保证（冲突处理规则见 [HA 章节](#ha--多节点控制面)），且 Redis 本身成为*新增*跨节点路由的可用性瓶颈。

### 其余选择：刻意的"无聊"

CLI 用 Cobra，日志用 zerolog，测试用 testify + miniredis，Web UI 用 `go:embed` 内嵌。这些都是刻意选择的主流方案，让有趣的代码集中在协议层。

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

### 控制帧与数据帧的优先级

`Mux` 用两个独立的 channel 排队发送帧，而不是共用一个：`ctrlCh` 承载 `WINDOW_UPDATE`/`PING`/`PONG`/`HANDSHAKE`/`ERROR`，`sendCh` 承载 `DATA` 与 `CLOSE`。`sendLoop` 总是优先排空 `ctrlCh`。这一点很关键，因为 `WINDOW_UPDATE`/`PONG` 正是用来解除对端阻塞的信号：在一条双向都被数据打满的连接上，`recvLoop` 收到 `PING` 后会同步调用 `sendPong`——如果这次发送和大量积压的 `DATA` 帧共用一个队列，它就会被阻塞，`recvLoop` 也随之停止从 socket 读取数据，进而通过 TCP 反压让对端的写入同样卡住，这正是单队列 mux 的经典死锁路径。`CLOSE` 帧则刻意留在 `sendCh` 与 `DATA` 同队列，而不加入优先通道：它标记的是一个 stream 数据的结束，因此绝不能抢在该 stream 自己尚未发出的数据前被投递——一旦插队，对端就会在数据全部到达之前先看到 EOF。

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

1. **Server 端**（`proxy_service.go: forwardHTTP`）：
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

4. **多隧道分发**（`proxy_service.go: resolveTunnelID` / `client.go: resolveLocalAddr`）：
   - 第 1 步 `Route(Host)` 只能把请求解析到某个 `ClientSession`——同一个客户端连接可能注册了**多个**隧道（多隧道 YAML 配置），每个隧道有自己的本地后端。
   - 服务端的 `resolveTunnelID(client, host, path)` 会进一步判断请求究竟对应客户端的哪个隧道，匹配优先级为：自定义 hostname → 该隧道专属 subdomain → 最长路径前缀。匹配结果会填充到 `StreamRequest.TunnelID`。
   - 客户端的 `resolveLocalAddr(tunnelID)` 会用该 `TunnelID` 在 `activeTunnels` 中查找对应隧道的 `LocalHost`/`LocalPort`；只有当 `TunnelID` 为空或未识别时才回退到客户端顶层配置（用于单隧道场景的向后兼容）。
   - 这保证了多隧道模式下，各子域名/hostname/路径的流量会分别转发到各自配置的本地端口，而不会全部汇聚到最先注册的那个隧道。

### WebSocket 代理

WebSocket 升级请求特殊处理（`proxy_service.go: handleWebSocket`）：

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

`captureHeaders()` 会把一组固定的敏感请求头名称（`Authorization`、`Cookie`、`Set-Cookie`、`Proxy-Authorization`、`X-Api-Key` 等，大小写不敏感匹配）在请求和响应捕获时都脱敏为固定占位符，确保 token 或会话 cookie 永远不会落入存储的记录，也不会被推送到 Inspector UI。

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

### 实现状态（已完成）

以下这些组件共同提供了 NAT 探测、打洞，以及构建在其之上的可靠传输层：

| 组件 | 文件 | 状态 |
|------|------|------|
| **NAT 类型定义** | `pkg/p2p/nat.go` | ✅ 完成 — Full Cone, Restricted, Port Restricted, Symmetric |
| **STUN 客户端** | `pkg/p2p/stun.go` | ✅ 完成 — RFC 5389 Binding, 双服务器 NAT 分类 |
| **UDP 打洞** | `pkg/p2p/hole_punch.go` | ✅ 完成 — WHPP 魔数前缀的 probe/ack 协议；同一个 UDP socket 会同时探测主 endpoint 与预测候选 endpoints |
| **端口预测器** | `pkg/p2p/predictor.go` | ✅ 完成 — 基于 delta 的 Symmetric NAT 端口预测 |
| **P2P 管理器** | `pkg/p2p/manager.go` | ✅ 完成 — 协调 STUN + 候选感知的打洞 + 中继降级 |
| **端到端加密** | `pkg/p2p/crypto.go` | ✅ 完成 — X25519 ECDH 密钥交换、AES-256-GCM 加密、HKDF 密钥派生 |
| **可靠 UDP 传输** | `pkg/p2p/mux.go`、`pkg/p2p/stream.go` | ✅ 完成 — `UDPMux`/`UDPStream`：多路复用 ARQ + RFC 6298 自适应 RTO、滑动窗口、可靠 SYN 握手 |
| **信令消息** | `pkg/proto/messages.go` | ✅ 完成 — P2POfferRequest/Response（支持按子域名定向）、Candidates、Result |
| **客户端集成** | `pkg/client/client.go`、`cmd/wormhole/cmd/connect.go` | ✅ 完成 — NAT 发现、P2P Offer、`wormhole connect` 直连数据面 |
| **服务端信令** | `pkg/server/server.go` | ✅ 完成 — 按子域名定向 Peer 匹配、NAT 兼容性检查 |
| **集成测试** | `pkg/p2p/integration_test.go` | ✅ 完成 — 15+ 测试用例 |

> **能力边界说明：** P2P 只能在两个都跑着 Wormhole 打洞协议的进程之间承载流量——也就是 `wormhole client` ↔ `wormhole connect` 这一种场景。公网访客通过隧道 hostname 访问时（浏览器、curl、手机 App 等）并没有在跑 Wormhole 的 P2P 协议，物理上不可能被打洞，因此这条流量始终走 Server 中继；这不是缺口，而是硬性物理约束。下文的 `wormhole connect` 才是让 P2P 在物理可行的场景里真正承载流量的实现。

### 可靠 UDP 传输层

生产环境的 P2P 数据传输由 `UDPMux` + `UDPStream`（`pkg/p2p/mux.go`、`pkg/p2p/stream.go`）承载——这是一套基于 ARQ 协议、在单个 UDP 套接字对上实现的可靠、有序、支持多路复用的流层。

**自适应重传（RFC 6298）：** 不再使用固定重传超时，`UDPStream` 为每条流维护 SRTT/RTTVAR 估计（`updateRTO`，增益 α=1/8、β=1/4，`RTO = SRTT + 4×RTTVAR`，取值范围钳制在 `[100ms, 10s]`），采样来自**未被重传过**的数据段的 ACK（Karn 算法——被重传过的段的 ACK 无法判断到底是确认了哪一次发送，纳入采样会污染估计值，因此排除）。每个在途数据段还会对**自己**的重传计时器做指数退避（每次重传翻倍，封顶为基础 RTO 的 32 倍），而不是所有段共用一个全局计时器，这样一个丢包严重的段不会拖累同一条流上其他段的超时判断。这让流在干净、低延迟的链路上能积极重传，在丢包/高延迟链路上能优雅退避，而不是用一个固定值应付所有场景（大概率两头都不合适）。

**发送路径降拷贝：** `SessionCipher.EncryptInto` 直接把加密结果写入预先分配好容量的发送帧 buffer，不再先加密到临时 buffer 再整体拷贝进帧；接收路径（`handleData`/`deliverLocked`）不再重复拷贝 `decryptPayload` 已经返回的、本身就是独立分配的 payload。

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

### `wormhole connect`：client 间直连数据面

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
│  3. 双方 STUN + 打洞（与上文相同的原语）；成功后              │
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

服务端侧，`pkg/server/tunnel_registry.go` 中的 `TunnelRegistry.FindPeerBySubdomain` 把 `target_subdomain` 解析为拥有它的 `ClientSession` 以及具体服务它的 `TunnelInfo.ID`（一个对端可能暴露多个隧道），并区分"未指定目标"（正常 `wormhole client` 注册自己的 P2P 可达信息，静默忽略）、"目标不存在"、"目标是自己"、"目标缺少可用的 P2P/NAT 信息"这四种不同的失败原因，分别体现为 `P2POfferResponse.Error` 的不同取值。

这与普通公网访客的隧道路径故意是不同的机制——参见上方的能力边界说明。

**集群模式下，P2P 信令只能在同一节点内完成。** `FindPeerBySubdomain` 只对连接在*本节点*的客户端持有 `ClientSession`（其中带着对端的 NAT 类型、地址、ECDH 密钥）——这部分状态从未同步进 `StateStore`，`StateStore` 只记录路由元信息（`NodeID`/`NodeAddr`），不记录 P2P 可达性信息。本地查找未命中时，`FindPeerBySubdomain` 会回退查一次 `StateStore`，唯一目的是给出一个诚实的答案：如果发现该子域名归属于*另一个*节点，会返回专门的 `errP2PTargetOnOtherNode`（"目标连接在其他集群节点，回退至 relay"），而不是容易让人误判的"未找到"。无论哪种情况，`wormhole connect` 都无法直连到该对端——offer 会失败，且不同于 `wormhole client`，这里没有中继兜底（参见上方的降级策略）。真正实现跨节点 P2P 信令意味着要把每个会话的 NAT/地址/密钥信息同步进 `StateStore`，并把 offer/result 交换代理到目标节点——考虑到 `wormhole connect` 本身就没有中继兜底，这部分复杂度被判定不值得引入；需要在多节点部署下稳定使用 P2P 的用户，应该通过一致性哈希等方式把两个对端固定到同一节点，而不是依赖跨节点信令。

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
- 隧道**控制**监听器（认证 token 走的那条链路）拥有自己独立的 TLS 设置（`--tunnel-tls`，通过 `TLSManager.TunnelTLSConfig()`/`WrapTunnelListenerStrict()` 实现），而不是继承 HTTP 数据面监听器的 TLS 配置——它默认跟随 `--tls` 的取值，并且在 `--require-auth` 配合真实 `--domain` 时额外默认开启，因为要求认证却让承载这些 token 的链路保持未加密，会直接违背认证本身的意义。当认证是必需项时，TLS *配置*错误（例如证书路径不对）会直接导致服务端启动失败，而不是静默退回明文

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
| **反重放** | `SessionCipher` 维护已见过的最高计数器，外加一个 1024 位的滑动窗口位图；`Decrypt` 在真正解密前会先拒绝已经出现过或已经落在窗口之外的计数器。窗口内的乱序投递（UDP 上的正常现象）仍会被接受。一个伪造包（GCM tag 校验失败）永远不会把自己的计数器标记为"已见过"，因此不可能被用来抢占合法发送方的窗口位 |
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
- **吊销检查 fail-closed**：如果校验期间无法访问后端存储（如 Redis/SQLite 故障），`validatePayload` 返回 `ErrRevocationCheckUnavailable`，token 被拒绝，而不是在无法确认吊销状态时放行——存储抖动绝不会让已吊销的凭证复活。若团队记录确实不存在（`ErrTeamNotFound`），仍视为"无吊销规则适用"并正常校验通过
- **不泄露认证状态**：无论底层原因是什么（过期/已吊销/格式错误/存储不可用），握手对客户端统一返回笼统的 `authentication failed`。具体原因只写入服务端日志，攻击者无法据此探测某个 token 的确切状态

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

`OIDCValidator` 以 1 小时 TTL 缓存 JWKS 密钥，遇到未知 `kid` 时自动刷新。支持算法：`RS256`、`RS384`、`RS512`、`ES256`、`ES384`、`ES512`；`verifyJWTSignature` 对 `alg: none` / 空 `alg` 有专门的 `case "none", ""` 立即拒绝，堵住经典的签名绕过攻击。issuer 比较（`normalizeIssuer`）会先去掉尾部斜杠再匹配，因此 `https://issuer.example.com` 和 `https://issuer.example.com/` 被视为相等；`nbf`（not-before）校验复用与 `exp` 相同的 60 秒时钟容差。

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
- `--audit-retention-days`（默认 90 天）通过周期性的 `AuditStore.DeleteOlderThan(cutoff)` 清理任务限制日志无限增长
- `AuditStore.Store()` 调用失败（例如磁盘写满或 SQLite 文件被锁）时不会静默丢弃事件，而是累加一个 `atomic.Uint64` 计数器；`GET /stats` 将其作为 `audit_store_errors` 字段返回，使持久化故障可被监控而非无声无息
- `/metrics` 需要和其余 Admin API 一样的管理员鉴权，从不裸露给未认证访问
- `Server.Start()` 会调度一个每 10 分钟运行一次的后台任务，清理吊销黑名单中的过期条目，避免其无限增长

### 输入验证

- Host header 路由时做 HTML 转义（防 XSS）
- 客户端自选的子域名会按 DNS label 规则校验（`isValidSubdomainLabel`：1–63 字符，仅字母/数字/连字符，不以连字符开头或结尾），在鉴权握手和动态隧道注册两处都会校验，早于该值到达路由表、集群状态存储或任何日志行——拒绝点号、路径分隔符、`..` 以及控制字符注入
- 自定义 hostname 会按点分 DNS label 校验（不接受端口、通配符、尾随点、空 label 或控制字符），通过后才进入路由表/状态存储；同时会直接拒绝落在服务器自身基础域名内的 hostname（等于该域名，或形如 `"<label>.<域名>"`）——`Router.Route` 匹配顺序是 hostname 表优先于 subdomain 表，若不做这层拒绝，任何客户端都能靠注册一个落在基础域名内的自定义 hostname 劫持别的租户的子域名（甚至是保留字子域名），完全绕过 `RegisterSubdomain` 的归属校验和 `isReservedSubdomain` 的保护
- path-prefix 路由必须是以 `/` 开头的纯 URL path；拒绝遍历片段（`..`）、query/fragment 分隔符、反斜杠与控制字符

### 子域名申请语义

`RegisterRoute`（无论是内存路由表还是 Redis 集群状态）是一次原子申请，定义了四种明确结果：空闲 → 保留；同一客户端重复注册 → 幂等续期 TTL；被另一个*存活*的所有者持有 → 返回 `ErrSubdomainConflict`（拒绝连接）；被一个*陈旧*（已过期）的所有者持有 → 回收。Redis 实现把这次申请封装为一条 Lua 脚本（`registerRouteScript`），让路由索引 key、route record 与 client route set 在同一个原子操作里更新，而不是拆成 `SETNX` + `SET` 两次往返。本地或集群级的子域名冲突会直接拒绝并关闭连接，而不只是记一条日志、让客户端以为（通过 `AuthResponse`）自己拥有一个实际上并不受控的子域名；客户端自身的重连逻辑会在之后接管重试。

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

`RouteEntry` 携带 `{RouteID, ClientID, TeamName, Subdomain, Hostname, PathPrefix, NodeID, NodeAddr, RegisteredAt}`——同一个客户端可以同时持有多条 `RouteEntry`（一个隧道的子域名、另一个隧道的自定义 hostname、第三个隧道的 path 前缀），每条都能通过独立的 `RouteID` 精确注销。`NodeInfo` 携带 `{NodeID, NodeAddr, LastHeartbeat}`。

`RegisterRoute` 必须原子地占用该 entry 对应的路由键（子域名 / hostname / path，取决于设置了哪个字段）：空闲 → 保留；同一 `ClientID` 重复注册 → 幂等续期 TTL；被另一个*存活*的所有者持有 → 返回 `ErrSubdomainConflict`；被一个*陈旧*（已过期）的持有者占用 → 回收。`MemoryStateStore` 在自己的锁下通过共享的 `conflictsWith` 辅助函数实现这四态语义。`RedisStateStore` 把整个保留过程——冲突检查、索引 key 的 `SET`、路由记录的 `SET`、客户端路由 ID 集合的 `SADD`——合并成一条通过 `EVAL` 执行的 Lua 脚本（`registerRouteScript`），而不是先 `SETNX` 再单独跑一次 pipeline `SET`。旧的两步实现在两次往返之间存在一个真实（虽然很窄）的窗口：索引 key 已经指向某个 `routeID`，但对应记录还没写入——恰好落在这个窗口里的查询会看到"未找到"，即便保留操作从技术上已经成功；如果进程在两次调用之间崩溃，这段破损的中间状态会一直留着，直到客户端自身的重试（见下文）把它盖过去。合并成一条 `EVAL` 彻底消除了这个窗口：任何并发查询现在只会看到完整成型的保留状态，或者完全没有。

### 路由注册的可用性与一致性权衡

`TunnelRegistry.registerClusterRoute` 在状态存储不可达、或因非 `ErrSubdomainConflict` 原因报错时，明确选择了可用性优先于严格一致性：它仍然返回成功（不拒绝这次连接），而不是 fail-closed。每次 Redis 抽风就拒绝所有新连接，会让整个集群的接入能力因为一次往往是短暂的抖动而瘫痪——比下面这种处理方式更糟。

这个权衡之所以成立，前提是失败不能是"静默"的。一条注册失败的路由仍会被追加进 `client.clusterRoutes`（此前的实现会直接丢弃它，这意味着客户端会对集群其余部分永久不可见，即便 Redis 后来恢复了，也得等客户端自己重连才能补上）。既有的 30 秒心跳周期驱动的 `refreshClusterRoutes` 会无条件重试 `clusterRoutes` 里的每一条——于是注册时失败的路由，会被并入原本只是"续期 TTL"的同一条重试循环里，不需要额外的"待注册队列"或重试策略。最终效果是：一次短暂的状态存储中断，会在 Redis 恢复后的一个心跳周期内自愈，客户端完全不需要任何动作。

这确实打开了一个较窄的裂脑窗口：当本节点认为自己拥有某条路由时（它正待在 `clusterRoutes` 里，尚未同步成功），*另一个*节点可能已经真的抢到了同一个 key。下一次 `refreshClusterRoutes` 重试会在这一刻立即发现——`RegisterRoute` 对一条本节点自认为已经拥有的条目返回 `ErrSubdomainConflict`，说明集群的共享状态已经和本节点的认知不一致了。这会以 `Error` 级别记录（而不是常规同步失败用的 `Warn`），并计入 `ClusterRouteConflictsTotal`；从机制上看是另一个节点的注册获胜，本节点会立即从本地内存 `Router` 和 `client.clusterRoutes` 中摘除这条陈旧路由，停止继续为一个集群其余部分已经路由到别处的 key 提供流量服务。`ClusterRouteSyncFailuresTotal` 单独统计更常见、能自行恢复的那类情况——任何非冲突的注册/刷新失败，无论它最终是否演变成真实冲突。运维仍然应该对 `ClusterRouteConflictsTotal` 非零告警，因为自动摘除本地路由解决的是一致性问题，并不会解释为什么两个节点一度都认为自己拥有同一个 key；`ClusterRouteSyncFailuresTotal` 在 Redis 抖动期间波动是预期行为，只有持续非零才值得关注。摘除本地路由的同时也会同步修正该客户端自己的 `TunnelInfo` 记录（`client.Tunnels`）——清掉发生冲突的那一个路由维度，若该隧道已没有任何路由维度存活则整条记录一并移除——否则 `client.Tunnels` 会继续声称一条本节点已不再服务、也永远不会再重试的路由，形成一个"看起来活着、实际零流量"的半死隧道。

### 多租户：team 级路由隔离

两套独立机制防止某个 team 的路由被共享同一集群的其他 team 干扰：

- **陈旧持有者回收按 team 隔离。** 一个因会话异常退出（网络抖动、崩溃）而未走正常断连流程遗留下来的 subdomain/hostname/path，一旦其 `Mux.IsClosed()` 即可被回收——见下方[跨节点 HTTP 路由](#跨节点-http-路由)中的"陈旧持有者回收"——但 `isStaleOwner`（`pkg/server/router.go`）额外要求回收方与原持有者的 `TeamName` 相同（或双方任一方压根没有 team，例如未启用鉴权，或单租户部署）。没有这层校验的话，team B 的客户端就可能在 team A 自己的重连落地之前，抢先在极短的窗口期内占用 team A 客户端刚掉线的那个子域名。`TeamName` 之所以要从 `ClientSession` 一路带进每条 `RouteEntry` 的注册请求里，就是为了让这个校验能在集群范围内比较，而不只是对着本节点的本地 `Router`。
- **保留字子域名把运营方专用的名字挡在 team 之外。** `Config.ReservedSubdomains`（默认来自 `DefaultReservedSubdomains()`：`admin`/`api`/`www`/`status`/`metrics`/`health`；可用 `--reserved-subdomains` 覆盖，传 `[]` 可关闭）会拒绝任何非 admin 角色的客户端占用这些标签，这样无论哪个 team 的客户端先注册，都不会意外（或蓄意）抢占运营方留给自己基础设施用的名字。`isReservedSubdomain`（`pkg/server/server.go`）在鉴权阶段（连接级子域名）与逐隧道注册阶段（`handleRegister`）都会执行，大小写不敏感，且在 `RequireAuth` 关闭时是空操作（没有角色可查，也没有 team 需要隔离）。`auth.RoleAdmin` 的 token 始终不受此限制。

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

`ListRoutes`/`GetNodes`（以及 auth store 的 `ListTeams`/`CountRevokedTokens`）全部使用 `SCAN` 游标而非 `KEYS`，避免大 key 空间下阻塞共享的 Redis 实例。

### 路由 TTL 刷新

一条路由只在注册那一刻写入 Redis、之后再也不刷新的话，即使客户端仍然在线，也会在 5 分钟后静默过期。为此，`ClientSession.clusterRoutes` 记录该会话在集群侧注册过的每一条 `RouteEntry`（主子域名，以及 `RegisterTunnel` 注册的额外子域名/hostname/path 前缀），`TunnelRegistry.StartHeartbeat` 每 30 秒的心跳周期都会调用 `refreshClusterRoutes`，对这些路由逐一重新执行 `RegisterRoute`——这本质上是一次可批量/管道化的 `EXPIRE`/TTL 刷新，而不是重新申请，因为这些条目本来就属于当前客户端。

### 集群心跳（`pkg/server/tunnel_registry.go`）

集群相关的簿记（心跳、路由、端口分配）全部收拢进 `TunnelRegistry`——`Server` 组合的三个组件之一（见[组件架构](#组件架构)）——从不直接访问 `Server` 的字段。

```
TunnelRegistry.StartHeartbeat(ctx)
  ├── 每 30 秒 → NodeHeartbeat(NodeInfo{NodeID, NodeAddr})
  │              sendHeartbeat 同时记录 StateStore 是否可达 → tunnelRegistry.stateStoreHealthy
  ├── 每 30 秒 → 对每个在线会话执行 refreshClusterRoutes(client)
  └── 每 60 秒 → EvictDeadNodes(90 秒阈值)
                    └── MemoryStateStore：扫描并删除失效节点及其名下的路由
                        RedisStateStore：no-op——驱逐完全由 Redis TTL 负责
```

### 跨节点 HTTP 路由

```
ProxyService.ServeHTTP(r)
  ├── verifyClusterSecret(r) → 若配置了 --cluster-secret 且请求头存在但不匹配则拒绝；
  │                            放行时始终剥除该头（外部流量本就没有此头）
  ├── router.Route(host, path) → 本地是否存在 ClientSession？
  │     └── 是 → forwardHTTP / handleWebSocket（正常路径）
  └── 否 → registry.ResolveRemote(host, path)   [hostname → 最长匹配 path → subdomain]
              └── 找到远端 RouteEntry？
                    ├── registry.IsLocalNode？→ 走向 404（陈旧条目）
                    └── 否 → proxyToNode(route.NodeAddr, w, r)
                                  └── 附加 X-Wormhole-Cluster-Secret 头
                                  └── validateClusterNodeAddr 先校验必须是纯 host:port
                                  └── httputil.ReverseProxy → 转发到目标节点
```

hostname 和 path 前缀路由现在与子域名一样会被索引进 Redis，因此在节点 A 上通过 `--hostname`/`--path` 注册的隧道，也能通过节点 B 访问，不再局限于自己的子域名。

**节点身份**：`applyClusterNodeIDDefault` 在配置了集群后端但没有显式设置 `ClusterNodeID` 时，会用 `os.Hostname()` 兜底，避免两个节点意外共用一个空字符串 NodeID。

**陈旧持有者回收**：`router.go` 的 `RegisterSubdomain`/`RegisterHostname`/`RegisterPath` 在返回冲突之前会先检查 `isStaleOwner`（原持有者的 `Mux.IsClosed()`，以及——见[多租户：team 级路由隔离](#多租户team-级路由隔离)——是否同 `TeamName`）；`TunnelRegistry.registerClientRoute` 在集群侧做同样的处理，主动注销失效会话在 `StateStore` 中残留的条目。客户端网络抖动后重连，能立即拿回原来的子域名/hostname/path，而不是先收到一次瞬时的冲突错误；换了 team 的客户端也无法抢先占用。

**健康状态暴露**：`GET /health` 新增 `cluster: {node_id, state_store_healthy}` 字段（来自 `TunnelRegistry.StateStoreHealth()`）；一旦状态存储不可达，整体 `status` 会从 `"ok"` 降级为 `"degraded"`，监控系统无需再单独探测 Redis。

### 节点间认证

`--cluster-secret` 是集群内所有节点共享的密钥。`proxyToNode`（`pkg/server/proxy_service.go`）在自己的出站克隆请求上附带 `X-Wormhole-Cluster-Secret` 头；`verifyClusterSecret`（在 `ProxyService.ServeHTTP` 最前面调用）会拒绝那些*头存在但不匹配*的请求，并且**在每一条放行路径上都剥除该头**——无论该功能开启与否、无论请求是真实的 peer hop 还是普通外部流量——确保该密钥永远不会被转发进隧道客户端的本地服务（及其日志）。仅仅缺少该头的请求属于普通外部流量，正常放行。启动 Redis 集群时现在要求同时配置 `--cluster-node-addr` 与 `--cluster-secret`；缺少任意一个都会快速失败，因为其他节点需要前者访问本节点，也需要后者校验节点间代理请求。

在拼接转发目标之前，`proxyToNode` 还会用 `validateClusterNodeAddr` 校验目标必须是纯粹的 `host:port`。这是一层纵深防御，防止状态存储中被篡改的条目把 scheme、用户信息、path 或 query 混入代理目标——请求始终基于校验过的 `host`/`port` 组件重新拼装（`net.JoinHostPort`），而不是直接使用原始字符串。

### 共享的鉴权/吊销状态

`--persistence redis`（`pkg/auth/store_redis.go`，`auth.RedisStore`）把团队信息存在 `wormhole:auth:team:<name>`，吊销的 token 存在 `wormhole:auth:revoked:<tokenID>`，并用与 token 剩余有效期匹配的 Redis TTL——节点 A 上吊销的 token，写入完成的那一刻在节点 B 上就已经失效，没有传播延迟，也不需要周期性清理任务（该后端下 `CleanupExpiredRevocations` 是 no-op，因为 TTL 早就自动删除了 key）。`--auth-redis-addr/-password/-db` 未显式设置时会回退到 `--cluster-redis-*`，一套 Redis 配置即可同时支撑集群路由状态和鉴权/吊销状态。

### HA 下的 TCP 隧道

TCP 隧道**仅限节点本地**：TCP 隧道的监听器运行在客户端当前连接的那个节点上，不存在跨节点的 TCP 代理（与 HTTP/WebSocket 路径不同，`StateStore` 并不追踪跨节点的 TCP 端口归属）。需要 TCP 隧道 HA 能力的用户，需要自行在各节点地址/端口前面放一个支持 TCP 的负载均衡器（例如 HAProxy 的 `mode tcp`，或 L4 DNS/anycast 方案）；Wormhole 本身不会尝试隐藏这个限制。

### 连接限制

- `MaxClients` 限制同时在线客户端数
- TCP 端口分配范围限制（默认 10000-20000）
- 按 IP 追踪连接用于速率限制

---

## Server 与 Client 组合

`Server` 和 `Client` 都是组合根（composition root）：各自构造一组小而专注、可独立测试的组件并把它们接线在一起，而不是把所有职责都堆在同一个结构体上。

### Server

`NewServer` 构造三个组件，每个组件只拿到自己需要的依赖：

```
NewServer(config)
  ├── registry := newTunnelRegistry(config)                                    // TunnelRegistry
  ├── metrics, auditLogger, authenticator, rateLimiter, tlsManager, adminAPI
  ├── proxy  := newProxyService(registry.router, registry, config, metrics,
  │                             &stats, server.serverCtx)                       // ProxyService
  └── broker := newP2PBroker(registry, metrics, auditLogger, server.serverCtx)  // P2PBroker
```

| 组件 | 文件 | 持有 |
|------|------|------|
| `TunnelRegistry` | `pkg/server/tunnel_registry.go` | `*Router`、`clients` map 及其锁、`TCPPortAllocator`、`StateStore` 及其健康标记、集群心跳 goroutine |
| `ProxyService` | `pkg/server/proxy_service.go` | HTTP/WebSocket/TCP 转发（即 `http.Handler`）及并发流预算 |
| `P2PBroker` | `pkg/server/p2p_broker.go` | `wormhole connect` 的 offer/result 处理、NAT 兼容性判断、端口预测候选生成 |

`ProxyService`/`P2PBroker` 依赖 `TunnelRegistry` 时用的是它的一个小接口而非具体结构体——只暴露转发/信令调用方真正需要的方法（`ResolveLocal`、`ResolveRemote`、`IsLocalNode`、`FindPeerBySubdomain`、`AllocatePort` 等），不是 registry 的全部内部接口。`admin.go` 的 `/health`、`/stats`、`/clients`、`/tunnels` 也走的是同一套接口（`registry.StateStoreHealth()`、`registry.AllocatedPorts()`、`registry.ActiveRoutes()`、`registry.Snapshot()`），而不是伸手进 `Server` 内部——管理 API 的读取路径完全不需要知道 registry 的内部加锁方式。

### Client

`NewClient` 构造两个组件，并通过少量回调把它们接在一起：

```
NewClient(config)
  ├── p2p   := newP2PSession(config, manager, forwarder, stats, closeCh)   // P2PSession
  └── relay := newRelayClient(config, forwarder, stats, p2p.Manager(),
                               closeCh, &closeWg)                          // RelayClient
       relay.setAfterConnect(p2p.MaybeSendOffer)                          // 接上回调
       relay.setNotificationHandler(p2p.HandleNotification)
```

| 组件 | 文件 | 持有 |
|------|------|------|
| `RelayClient` | `pkg/client/relay_client.go` | 控制面的 `net.Conn`/`tunnel.Mux`、鉴权与 token 刷新、单/多隧道注册及 `activeTunnels` map、心跳 goroutine、重连循环（`Run`） |
| `P2PSession` | `pkg/client/p2p_session.go` | P2P 的 `net.PacketConn`/`*p2p.UDPMux`、ECDH `KeyPair`/`SessionCipher`、打洞尝试（`attemptP2P`）、`wormhole connect` 本地监听器（`startConnectListener`/`proxyConnectConn`） |

两个组件都只通过 `Client` 实现的两个小型消费者侧接口依赖它——`localForwarder`（把一条流交给上层去转发到本地服务）和 `statsRecorder`（把字节数/连接数上报到汇总的 `Stats`）——因此 `RelayClient`、`P2PSession` 都不需要知道 `Client` 这个具体类型的存在。`P2PSession` 回调 `RelayClient` 时也只经过最小化的 `RelayChannel` 接口（通过控制连接发送一次 P2P 结果），而不是 `RelayClient` 的完整接口。`Client` 自己保留的锁只保护它直接持有的状态（本地控制/inspector HTTP 服务）；连接状态位于 `RelayClient` 自己的锁之下，P2P 会话状态位于 `P2PSession` 自己的锁之下。

**会话替换与 singleflight。** 同一个 peer 的 P2P offer/通知完全可能触发多次（重试、双方各自发起的竞态 offer），每一次成功打洞都会替换 `P2PSession` 当前持有的 `conn`/`udpMux`/`sessionCloseCh`。这里有两处保护，都在 `P2PSession.mu` 之内：一个 `attempting atomic.Bool` 让 `attemptP2P` 具备 singleflight 语义——第二个并发尝试发现该标志已被置位就直接返回，而不会和第一个尝试互相竞争；一个 `sessionGen` 计数器给每次安装的会话打上版本号。`installSession` 在安装新会话之前，总会先关闭它要替换的旧会话（关闭旧的 `conn`/`udpMux`，通知旧的 accept 循环退出），因此一个被取代的会话永远不会作为孤儿 goroutine + UDP socket 继续存在。由于 `acceptP2PStreams` 是每个会话各自的一条独立 goroutine，某个**过期**会话的 accept 循环报错时绝不能被允许去关闭已经取代它的新会话——`fallbackFromStaleSession` 会记录该 goroutine 启动时的 `sessionGen`，报错时先与当前的 generation 比较，再决定是否真的需要执行 fallback。

---

## 可靠性与协议保障

### 优雅关闭

`Server` 持有为 HTTP 和 admin 监听器构造的 `*http.Server` 引用。`Server.Shutdown()` 会先对两者调用带超时（`ShutdownTimeout`，默认 10s）的 `http.Server.Shutdown(ctx)`，再关闭隧道监听器，使 `SIGTERM` 时在途的 HTTP/admin 请求有机会正常完成，而不是连接被直接掐断。

`Start(ctx)` 同时会派生一个根 context（`s.rootCtx`/`s.rootCancel`），`Shutdown()` 会在第一步就取消它，发生在优雅关闭 HTTP/管理监听**之前**。服务端调用树深处的若干操作——认证握手的流接受、TCP 端口分配、打开 P2P 对端通知流、打开 TCP 隧道流——都使用这个根 context 而不是 `context.Background()`，因此进行中的关闭能立即打断它们，不需要等自身的固定超时（例如 `AuthTimeout`）耗尽。`tunnel.Stream` 同样暴露了 `ReadContext`/`WriteContext`：持有可取消 context 的调用方能够打断正在阻塞的读/写。普通的 `Read`/`Write` 方法仍以 `context.Background()` 委托给它们，因此数据面热路径（`io.CopyBuffer` 之类）不会有任何额外开销——永远不会触发的 context 不会启动 watcher goroutine。服务端和客户端的每一个控制面 RPC（认证、隧道注册、心跳、统计、关闭、P2P offer/result）都用的是感知 context 的变体，因此 `Client.Close()` 或调用方指定的 deadline 同样能打断一次进行中的控制面 RPC。

### 双向代理首错收尾

WebSocket 和 TCP 隧道代理路径并发泵送两个方向（client→local 和 local→client）。先结束的那个方向会显式关闭（或 `CloseWrite`）对面连接，两个方向无论谁先出错都会立刻一起收尾——对于大部分单向的会话（例如长轮询或空闲的 keep-alive），不会再拖到对面自己的读超时才收尾。

### 并发流上限

两个服务端参数限制同时打开的数据面流数量（HTTP/WebSocket/TCP 代理流，不包括控制通道的流）：`--max-concurrent-streams`（默认 10000，进程级全局上限）和 `--max-streams-per-client`（默认 500，作用范围收窄到单个客户端连接，避免某个异常活跃的租户独占全局额度）。两者都是非阻塞的 `atomic.Int64` 计数器——超出上限的建流请求直接拒绝而不是排队，使流量突增时表现为可预测的快速拒绝，而不是无限制地增长 goroutine/内存占用。

服务端控制面与客户端自身也各有一道对应的上限，因为双方都可能被对端塞入无限量的入站流：`Server.Config.MaxControlStreamsPerClient`（默认 128，对应 `--max-control-streams-per-client`）限制单个客户端连接同时在处理的控制通道流（register/ping/stats/close/P2P-offer，不含数据面流量）数量；`client.Config.MaxConcurrentStreams`（默认 1000）限制 `RelayClient.acceptStreams` 与 `P2PSession.acceptP2PStreams` 会同时处理的入站流数量——这道限制的意义在于，一个被攻破或行为异常的服务端本可以对客户端开出无限量的流。四个限制共用同一套无锁模式：`tryIncrementBounded32`/`64` 用 CAS 循环让计数器只在低于上限时才递增，流处理结束后再通过 deferred 递减释放这个名额。

### 控制帧校验

`DecodeControlMessage` 会拒绝全零/垂直解码到 `MessageType_MESSAGE_TYPE_UNKNOWN` 且所有 oneof 字段都为空的垃圾输入，因为这种形态只可能是畸形/损坏的输入，不会是合法消息。校验条件刻意设计得很窄：如果一条 `Type == UNKNOWN` 的消息**确实**携带了可识别的 payload（session 或 P2P），仍会被接受，为将来某个更新的 client 向较旧 server 发送新消息类型保留前向兼容性。

### 版本门禁与能力广播

`pkg/version` 实现了一个极简的 semver 解析器/比较器（`ParseSemver`、`Compare`）——刻意不用完整的 semver 库，因为 Wormhole 只需要 `MAJOR.MINOR.PATCH` 比较。服务端的 `--min-client-version` 参数会拒绝声明版本过旧的 `AuthRequest`，并给出明确的认证失败原因；非正式发布构建（例如 `dev`、空字符串）的 client 在 semver 解析阶段就会失败，这类 client 刻意**永远不会**被拒绝，因为版本门禁是运维方的可选开关，不是运行未发布构建的硬性门槛。

`AuthResponse.Capabilities` 由 `Server.capabilities()` 填充，该方法根据服务端的实际运行时配置推导出能力列表（`p2p`、`multi-tunnel`、`cluster`、`audit` 等）。客户端保存服务端广播的能力集，并据此决定是否尝试可选行为——例如服务端没有广播 `"p2p"` 时会直接跳过发送 P2P offer，而不是照常发送一个 offer 靠服务端静默忽略。缺失/为空的能力列表（例如来自一个早于此字段的旧版 server）会被视为"未知，默认全部支持"以保持向后兼容。

---

## 热路径性能

隧道多路复用器的数据发送路径，以及每一条双向代理循环，都复用池化的临时缓冲区，而不是每次写入/每条连接都重新分配，这明显降低了负载下单次操作的分配量和 GC 压力：

- `Mux` 持有一个 `dataBufPool`（`sync.Pool`），`sendData` 从池里借一个缓冲区，代替每次 `Stream.Write` 都执行 `make([]byte, len(data)); copy(...)`；帧写入连接后立刻归还该缓冲区。
- `copyWithPooledBuffer(dst, src)` 是 `io.Copy` 的直接替代品（通过 `io.CopyBuffer` 实现），背后是一个包级池（`pkg/server` 和 `pkg/client` 各有自己的一份），被每一条转发循环使用：服务端的 HTTP 响应体拷贝、WebSocket 代理、TCP 隧道代理，以及客户端的中继模式 `dialAndProxy` 和 `wormhole connect` 的 `proxyConnectConn`。

`forwardHTTPWithInspect` 用 `io.LimitReader(body, MaxBodySize+1)` 限定了请求/响应正文的读取——开启 `--inspector` 后，无论上传/下载多大，都不会无限制地缓冲进内存。`Inspector.MaxBodySize()` 暴露了配置的上限，方便 `inspector` 包外的调用方按 `Capture` 实际会存储的口径来限定自己的读取。这只影响开启了检查器的代码路径；不带检查的中继/P2P 转发仍然完全不设上限，因为 Inspector 本身的定位是调试辅助工具，而不是给生产环境大流量场景开启的东西。

---

## 调试与运维手册

本节写给"东西不工作了"的那一刻——无论你是在运维一台 server，还是在改代码时想看清楚线上到底发生了什么。

### 调高日志级别

所有命令共享同一套全局 flag（`cmd/wormhole/cmd/root.go` 的 `configureLogging`）：默认是 `zerolog.InfoLevel`，`-v`/`--verbose` 降到 `DebugLevel`，`--debug` 再降到 `TraceLevel`。这里没有按包过滤日志的机制——就是一个全局级别——所以排查连接问题时，先在 server 和 client 两端都加上 `-v`；`--debug` 噪音更大（连帧级别的隧道追踪都会打出来），留给和时序/顺序强相关的问题排查时再用。

### 不动手就能看清一台正在运行的 server

Admin API（默认仅本机可访问，除非设置了 `--admin-token`）是第一站，不用翻日志：

| 端点 | 告诉你什么 |
|------|------------|
| `GET /health` | `status` 是 `"healthy"` 还是 `"degraded"`；后者意味着 `cluster.state_store_healthy` 为 `false`——是你的 Redis `StateStore` 连不上了，不是整台 server 挂了 |
| `GET /stats` | 活跃/累计 client 数、活跃隧道与路由数、累计字节/请求数、已分配的 TCP 端口——回答"到底有没有在真的处理流量"的那组数字 |
| `GET /clients` | 每个已连接的 `ClientSession`：subdomain、角色、team、连接时长、已知的 P2P 公网地址 |
| `GET /tunnels` | 同样的信息，但按已注册隧道逐行列出（支持多隧道，`/clients` 做不到这点） |
| `GET /ratelimit` | 当前被封禁的 IP（`RateLimiter.GetBlockedIPs`）；`POST /ratelimit/unblock {"ip":"..."}` 可以在真实用户被误封时提前解封（比如某个 client 拿着过期 token 一直重试触发了限流） |
| `GET /audit?type=auth_failure&limit=50` | 最近的安全相关事件——区分"鉴权配置错了"和"网络本身有问题"最快的办法 |
| `GET /metrics` | Prometheus 指标（鉴权方式和 Admin API 其余部分一致，参见[安全特性](../README_zh.md#安全特性)）；下面列出值得盯的几个系列 |

客户端一侧，`--ctrl-port` 暴露了一个功能小得多但思路一致的 `/tunnels` 端点，服务于 `wormhole tunnels list/create/delete`——用来确认一次 SIGHUP 热重载是否真的应用了你以为它应用了的配置。

### 值得配置告警的 Prometheus 指标

定义在 `pkg/server/metrics.go`，统一挂在 `wormhole_` 前缀下，标准 Go runtime/process 采集器之外额外提供：

- `wormhole_active_clients` / `wormhole_active_tunnels`——稳态 gauge；没有对应发布事件却突然掉到零，是进程崩溃循环的第一个信号。
- `wormhole_auth_attempts_total{result="failure"}` 持续爬升（不是一次性的突刺）通常说明是某批 client 配置错了（密钥/issuer 不对），而不是遭到了攻击。
- `wormhole_p2p_connections_total{result="fallback"}` 相对 `{result="success"}` 的比例——健康的 P2P 部署应该有一定的成功比例；如果几乎全是 fallback，大概率是你的 client 群体大多在 Symmetric NAT 后面（用 `wormhole nat-check` 抽样确认），而不是 P2P 代码本身出了问题。
- `wormhole_cluster_route_sync_failures_total`——非零但*不再增长*是一次瞬时的 Redis 抖动，下一次心跳会自愈（路由每个周期都会重新注册）；持续增长则说明这个节点访问不到状态存储。
- `wormhole_cluster_route_conflicts_total`——理论上应该始终为零。任何增量都意味着两个节点在一次状态存储故障窗口期内都认为自己拥有同一条路由；失败的一方会自动摘除本地陈旧路由，但这个指标仍应直接触发告警，因为真实的裂脑窗口已经发生过。

### 常见故障特征

| 现象 | 可能原因 | 去哪里看 |
|------|----------|----------|
| server 一启动就退出，报 `listen tunnel: ... bind: address already in use`（默认端口 7000） | 端口被别的东西占了——在 macOS 上这经常是系统自带的 AirPlay Receiver / ControlCenter，不是残留的 Wormhole 进程 | `lsof -i :7000`；换一个 `--port`，或者在系统设置里关掉 AirPlay Receiver |
| client 注册失败，报 `subdomain "x" already in use` / `already registered` | 另一个活跃会话已经占用了这个 subdomain（`ErrSubdomainConflict`，`router.go` 的注册检查）——这是刻意强制的行为，参见[路由注册的可用性与一致性权衡](#路由注册的可用性与一致性权衡) | `GET /clients` 看看现在是谁占着；一个因死会话残留的条目应该在其 mux 关闭后自动清理（HA 下则是等集群 TTL 过期） |
| 鉴权本来是好的，突然一直失败 | HMAC token 过期或被撤销；OIDC issuer/JWKS 暂时不可达；来源 IP 因不相关的失败被限流封禁 | `GET /audit?type=auth_failure`，`GET /ratelimit` |
| `wormhole connect`（或 P2P 加速的中继）总是降级，从来打不通直连 | 一方或双方在 Symmetric NAT 后面——这是[NAT 穿透策略](#nat-穿透策略)下预期内、不算 bug 的结果 | 两端都跑一下 `wormhole nat-check`；观察 `p2p_connections_total{result="fallback"}` 是否在增长 |
| server 启动时打出一条很显眼的 TLS 告警，但仍然启动了 | `--require-auth` + 真实的 `--domain` 会默认隐含开启 `--tunnel-tls`，但当时凑不出可用的证书材料（见[隧道控制链路 TLS](../README_zh.md#隧道控制链路-tls)） | 提供 `--cert`/`--key`，或确认 ACME 用的域名真的能在 80/443 上被访问到 |
| client 被拒绝，报 `client version "x" rejected: ...` | server 的 `--min-client-version` 比正在连接的 client 版本更新 | 升级 client，或者调低/去掉 `--min-client-version` |
| HA 模式下 `/health` 报 `"degraded"` | 这个节点连不上 Redis 支撑的 `StateStore` | 单独检查这台节点的 Redis 连通性——其他节点可能是健康的，互不影响 |
| 某条路由本来在某个节点本地可用，但 `wormhole_cluster_route_conflicts_total` 增加后在该节点消失 | 该节点发现 Redis 已经把同一个 route key 映射给另一个存活持有者，因此自动摘除了自己的本地陈旧路由以维持集群一致性 | 查日志里的 `dropped this node's local split-brain route`，再看 `/clients`；让受影响 client 重连或注册一个不冲突的路由 |

### 不依赖真实网络复现线上行为

大多数协议层面的 bug，在单元测试里排查比在真实部署上排查容易得多——参见[测试策略](#测试策略)里的 *mux-pair* 模式：在一条 `net.Pipe` 的一端挂一个真实的 `tunnel.Mux`，另一端用手写脚本模拟对端，这样就能直接断言"线上到底传了哪些帧/消息"，而不是靠猜时序去反推行为。

---

## 本项目使用的 Go 模式

如果你把 Wormhole 当作学习 Go 的材料，以下是全仓库反复出现的技巧，以及各自的典型出处。

### 组合根 + 消费方侧窄接口

`Server` 和 `Client` 是组合根：它们构造并装配各组件，但把实际工作全部委托出去（见 [Server 与 Client 组合](#server-与-client-组合)）。组件之间的接口定义在*消费方*一侧并保持最小——`P2PSession` 眼中的 `RelayClient` 只是 `RelayChannel`（发送信令消息的一组方法），两个 client 组件眼中的 `Client` 只是 `localForwarder` + `statsRecorder`。这是 Go 的接口惯用法（"accept interfaces, return structs"）在架构层面的应用：组件可以用极小的 fake 做单元测试，依赖方向在类型系统里一目了然。

### 每条连接一个写 goroutine

`tunnel.Mux` 把所有出站帧汇聚到由 `sendLock` 保护的单一写路径，无论多少 Stream 并发写入，帧都不会写到一半被交错。P2P 的 `UDPMux` 是同一模式。这是 Go 对"多生产者、单一有序出口"的标准解法——在边界处序列化，而不是在每个生产者内部加锁。

### 锁粒度跟随所有权

没有全局锁。每个组件只保护自己拥有的状态：`RelayClient.mu` 管连接/隧道状态，`P2PSession.mu` 管会话状态，`Stream.mu` 管每流缓冲区，registry/router 各有各的锁。热路径上检查的简单标记（`connected`、P2P `mode`）用 `sync/atomic` 而非互斥锁。读代码时可靠的规则是：找到拥有该字段的 struct，它的 mutex 就是保护该字段的那把锁。

### `context.Context` 用于取消，但不进数据路径

控制面 RPC（鉴权、注册、心跳、P2P 信令）全部接收 context，并使用 `Stream.ReadContext`/`WriteContext`，所以 shutdown 或调用方 deadline 能立即打断它们。数据路径（`io.CopyBuffer` 循环）刻意*不*用 context 感知的读写——普通 `Read`/`Write` 以 `context.Background()` 委托、不派生 watcher goroutine，保持热路径零额外分配。那里的取消靠关闭底层 Stream 实现。这种切分——响应性优先处用 context、吞吐优先处用关连接——值得内化。

### `sync.Pool` 池化热路径缓冲区

mux 里的 `dataBufPool` 和 `pkg/server`/`pkg/client` 各自的 `copyWithPooledBuffer` 池（见[热路径性能](#热路径性能)）展示了标准模式：只池化缓冲区、不池化对象图；在 `defer` 中归还；绝不让池化的缓冲区逃逸出函数返回之后。

### 基于 channel 的生命周期：`closeCh` + `sync.WaitGroup` + `sync.Once`

长期运行的 goroutine（心跳循环、accept 循环、TTL 刷新器）到处都是同一形状：一个只关闭一次的 `closeCh`（由 `sync.Once` 或原子 CAS 保证），`select` 让工作与 `<-closeCh` 竞争，`WaitGroup` 让 `Close()` 阻塞到每个 goroutine 真正退出。`Mux.CloseNotify()` 把该模式延伸到组件边界之外——client 的重连循环直接等这个 channel，而不是轮询连接健康度。

### 表驱动测试与行为级集成测试

输入可枚举的地方用表驱动测试（帧编解码、配置校验）。更有意思的是贯穿 `pkg/client` 和 `pkg/server` 的 *mux-pair* 测试模式：用 `net.Pipe` 造出两端，各包一个真实的 `tunnel.Mux`，一端作为脚本化的假对端来驱动。这在不开 socket 的前提下测到了真实的线上行为（分帧、流控、消息顺序），也是组合根拆分这类重构能依靠测试套件抓出真实 bug 的主要原因。见[测试策略](#测试策略)。

### 其他值得留意的

- `go:embed` 把整个 Inspector Web UI 打进二进制（`pkg/web`），保持单二进制部署。
- 所有涉密比较都用 `crypto/subtle.ConstantTimeCompare` / `hmac.Equal`——凭证绝不用 `==`。
- 通过 CAS 循环实现的有界原子计数器（`tryIncrementBounded`），无锁完成带上限检查的自增。
- 自定义错误遵循 `errors.Is`/`errors.As` 约定：哨兵值（`ErrSubdomainConflict`、`ErrTokenExpired`）配合 `%w` 包装。

## 测试策略

测试套件约 2.7 万行，超过生产代码。测试分层明确，知道一个测试属于哪一层，就知道新测试该怎么写。

| 层级 | 位置 | 手法 |
|------|------|------|
| 单元 | `pkg/tunnel`、`pkg/proto`、`pkg/auth` | 编解码/校验/token 逻辑的表驱动测试，附带 benchmark |
| 组件集成 | `pkg/client/client_test.go`、`pkg/server/*_test.go` | 基于 `net.Pipe` 的 mux-pair：被测侧用真实 mux，另一侧是脚本化的假对端 |
| 集群集成 | `pkg/server/cluster_test.go` | 两个完整 server 实例共享一个 `miniredis`，跨节点真实 HTTP 往返 |
| 全链路端到端 | `pkg/server/e2e_test.go` | 真实的 `Server` + 真实的 `Client`（真实 TCP socket，不用假件），代理到一个 echo 服务——金字塔顶端，一次性打通拨号→鉴权→注册→代理的全流程 |
| P2P 信令端到端 | `pkg/server/p2p_e2e_test.go` | 两个真实的 `Client` + 一个真实的 `Server`，配一个进程内的假 STUN server 顶替公网，验证完整的 `wormhole connect` offer/匹配/通知链路，以及通过 `p2p_connections_total` 指标断言的降级中继路径 |
| P2P 压力 | `pkg/p2p/stress_test.go` | loopback UDP + 模拟丢包，锤炼 ARQ 重传路径 |
| Fuzz | `pkg/tunnel/frame_fuzz_test.go`、`pkg/proto/messages_fuzz_test.go` | 用 `go test -fuzz` 对帧解码器和控制消息解码器做变异测试，确保畸形/对抗性输入不会让解析器 panic 或死循环；CI 里跑一个带种子的短程版本，本地可按需跑更久 |
| 竞态检测 | CI | 每次 push 全量 `go test -race` |

维持套件健康的准则：

- **测行为，不测字段。**优先驱动公开 API、断言可观察的协议效果（假对端收到了什么帧），而不是伸进未导出状态。
- **每个 bug 修复都附带回归测试**，放在能复现它的最低层级。
- **安全相关代码路径要有显式的负面测试**——错误的 HMAC、过期 token、无效集群密钥、超大控制消息。

本地运行：`go test -race ./...`；分包覆盖率：`go test -cover ./pkg/...`；短程 fuzz：`go test ./pkg/tunnel/ -run=^$ -fuzz=FuzzDecodeFrame -fuzztime=30s`（换成 `./pkg/proto/ -fuzz=FuzzDecodeControlMessage` 跑另一个目标——CI 里两个目标每次 push 各跑 20 秒）。lint 与安全门禁和 CI 一致：`golangci-lint run ./...`、`gosec -exclude=G115 -exclude-dir=web -exclude-dir=pkg/proto/pb ./...`。

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
