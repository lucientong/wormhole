# Wormhole Evolution Roadmap

> 本文档基于 2026-04 的竞品对标 Review 结论，将所有已识别的能力缺口按 **P0（必须优先）→ P1（核心竞争力）→ P2（企业级能力）** 三个阶段拆解为具体开发项。
>
> 每个开发项包含：**目标描述 / 当前状态 / 涉及文件 / 具体任务 / 预估工作量 / 验收标准**。
>
> _2026-04-11 更新：根据代码审查反馈，补充了 NewRegisterRequest 辅助函数扩展、Admin 地址解耦逻辑、P2P 工作量调整、Protobuf 迁移（P1-5）、连接重连增强、测试覆盖率目标等内容。_

---

## 目录

- [P0 — 安全与基础能力闭环](#p0--安全与基础能力闭环)
  - [P0-1: Client ↔ Server 控制链路 TLS 闭环](#p0-1-client--server-控制链路-tls-闭环)
  - [P0-2: 多协议 CLI 用户入口补齐](#p0-2-多协议-cli-用户入口补齐)
  - [P0-3: Admin / Inspector 默认安全加固](#p0-3-admin--inspector-默认安全加固)
  - [P0-4: 文档与实现一致性修正](#p0-4-文档与实现一致性修正)
- [P1 — 核心竞争力补强](#p1--核心竞争力补强)
  - [P1-1: P2P 数据面完善](#p1-1-p2p-数据面完善)
  - [P1-2: 控制协议闭环](#p1-2-控制协议闭环)
  - [P1-3: MaxClients 及配额 Enforcement](#p1-3-maxclients-及配额-enforcement)
  - [P1-4: Prometheus Metrics & Tracing](#p1-4-prometheus-metrics--tracing)
  - [P1-5: 控制协议迁移到 Protobuf](#p1-5-控制协议迁移到-protobuf)
- [P2 — 企业级能力](#p2--企业级能力)
  - [P2-1: OIDC / OAuth / SSO 认证集成](#p2-1-oidc--oauth--sso-认证集成)
  - [P2-2: 审计日志增强](#p2-2-审计日志增强)
  - [P2-3: HA / 多节点控制面](#p2-3-ha--多节点控制面)
  - [P2-4: Tunnel 生命周期与动态配置管理](#p2-4-tunnel-生命周期与动态配置管理)
- [时间规划概览](#时间规划概览)

---

## P0 — 安全与基础能力闭环

> P0 阶段的目标是：**让现有功能真正闭环、默认安全、文档可信**。
> 这是项目从 "demo 可用" 迈向 "可信赖产品" 的第一步。

---

### P0-1: Client ↔ Server 控制链路 TLS 闭环

| 属性 | 描述 |
|------|------|
| **目标** | 当服务端开启 TLS 时，客户端控制链路应自动升级为 TLS 连接，而非明文 TCP |
| **当前状态** | `pkg/client/client.go` 的 `connect()` 使用 `dialer.DialContext(ctx, "tcp", ...)` 明文连接。`Config` 有 `TLSEnabled / TLSInsecure` 字段但从未在 dial 逻辑中使用。CLI 也没有 `--tls` / `--tls-insecure` flag |
| **预估工作量** | **2-3 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/client/client.go` | 修改 `connect()` 方法，根据 `Config.TLSEnabled` 决定使用 `tls.DialWithDialer` 还是 `net.Dialer` |
| `pkg/client/config.go` | 确认 `TLSEnabled` / `TLSInsecure` / `TLSCACert` 字段存在且语义清晰 |
| `cmd/wormhole/cmd/client.go` | 新增 `--tls` / `--tls-insecure` / `--tls-ca` CLI flag |
| `cmd/client/main.go` | 同步更新独立入口 |

**具体任务：**

1. **修改 `connect()` 方法**
   ```go
   // 当 TLSEnabled = true 时
   tlsConfig := &tls.Config{
       InsecureSkipVerify: c.config.TLSInsecure,
   }
   if c.config.TLSCACert != "" {
       // 加载自定义 CA
   }
   conn, err = tls.DialWithDialer(dialer, "tcp", c.config.ServerAddr, tlsConfig)
   ```

2. **新增 CLI flag**
   - `--tls`：启用 TLS 连接（默认 false）
   - `--tls-insecure`：跳过证书验证（开发环境用）
   - `--tls-ca`：自定义 CA 证书路径

3. **Server 侧确认**
   - 确认 `pkg/server/tls.go` 的 TLS listener 同时服务控制链路（tunnel listener）和 HTTP 链路
   - 如果 tunnel listener 尚未 TLS 化，需要在 `server.go` 的 `startTunnelListener()` 中加上 TLS wrapping

4. **编写测试**
   - TLS 连接成功测试
   - TLS 证书验证失败测试
   - `--tls-insecure` 跳过验证测试
   - 非 TLS 模式向后兼容测试

**验收标准：**

- [ ] `wormhole client --tls --server tunnel.example.com:7000 --local 8080` 可建立 TLS 隧道
- [ ] Server 未开 TLS 时，Client 带 `--tls` 报明确错误
- [ ] `--tls-insecure` 可连接自签证书 Server
- [ ] 不带 `--tls` 时行为不变（向后兼容）
- [ ] `go test -race ./pkg/client/...` 通过
- [ ] `golangci-lint run ./pkg/client/...` 0 issues

---

### P0-2: 多协议 CLI 用户入口补齐

| 属性 | 描述 |
|------|------|
| **目标** | 将底层已支持的多协议能力（HTTP/HTTPS/TCP/UDP/WebSocket/gRPC）和路由能力（subdomain/hostname/path-prefix）暴露给用户 |
| **当前状态** | `pkg/proto/messages.go` 定义了 6 种协议；`pkg/server/router.go` 支持 hostname/path-prefix 路由；`proto.RegisterRequest` 有 `Protocol / Hostname` 字段。但 `pkg/client/client.go` 的 `registerTunnel()` 写死 `proto.ProtocolHTTP`；CLI 只有 `--subdomain`。另外 `NewRegisterRequest()` 辅助函数未接收 `Hostname` 参数，需扩展 |
| **预估工作量** | **3-4 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/client/client.go` | 修改 `registerTunnel()` 使用 `Config.Protocol`、支持 `Hostname` |
| `pkg/client/config.go` | 新增 `Protocol` / `Hostname` / `PathPrefix` 配置字段 |
| `cmd/wormhole/cmd/client.go` | 新增 `--protocol` / `--hostname` / `--path-prefix` flag |
| `cmd/client/main.go` | 同步更新 |
| `pkg/server/server.go` | `handleRegister()` 中根据 `req.Hostname` 调用 `router.RegisterHostname()` |
| `pkg/proto/messages.go` | `RegisterRequest` 新增 `PathPrefix` 字段（如需要） |

**具体任务：**

1. **Client Config 扩展**
   ```go
   type Config struct {
       // ... existing fields ...
       Protocol   string // "http" (default), "https", "tcp", "udp", "ws", "grpc"
       Hostname   string // Custom hostname for routing
       PathPrefix string // Path-based routing prefix
   }
   ```

2. **扩展 `NewRegisterRequest()` 辅助函数**
   - 当前 `NewRegisterRequest()` 签名不接收 `Hostname` / `PathPrefix` 参数
   - 扩展签名或新增 `NewRegisterRequestFull()` 以支持所有路由字段
   - 确保 `RegisterRequest` 结构体中 `Hostname`、`PathPrefix` 字段被正确填充

3. **修改 `registerTunnel()`**
   ```go
   // 把 protocol 字符串转为 proto.Protocol
   p := parseProtocol(c.config.Protocol) // "http" -> proto.ProtocolHTTP, "tcp" -> proto.ProtocolTCP, etc.
   req := proto.NewRegisterRequest(uint32(c.config.LocalPort), p, c.config.Subdomain)
   req.RegisterRequest.Hostname = c.config.Hostname
   req.RegisterRequest.PathPrefix = c.config.PathPrefix
   ```

3. **新增 CLI flag**
   - `--protocol / -P`：隧道协议类型，默认 `http`，可选 `http / https / tcp / udp / ws / grpc`
   - `--hostname`：自定义域名路由
   - `--path-prefix`：路径前缀路由

4. **Server 侧完善**
   - 确认 `handleRegister()` 正确处理 `req.Hostname` → `router.RegisterHostname()`
   - 确认 `req.PathPrefix`（如新增）→ `router.RegisterPath()`
   - TCP 隧道已有端口分配逻辑，确认 UDP 是否需要类似处理

5. **编写测试**
   - TCP 隧道注册与转发测试
   - Hostname 路由测试
   - Protocol 参数验证测试

**验收标准：**

- [ ] `wormhole client --protocol tcp --local 3306` 可注册 TCP 隧道并分配公网端口
- [ ] `wormhole client --protocol http --hostname api.example.com --local 8080` 可注册 hostname 路由
- [ ] 不传 `--protocol` 时默认 HTTP（向后兼容）
- [ ] 无效 protocol 值报清晰错误
- [ ] 全量 lint + test 通过

---

### P0-3: Admin / Inspector 默认安全加固

| 属性 | 描述 |
|------|------|
| **目标** | 消除默认部署下的安全暴露风险：Admin API 未授权访问、Inspector 绑定所有网卡、CORS 过于宽松 |
| **当前状态** | ① `admin.go` 中 `adminToken == ""` 时完全放行；② `client.go` 的 `StartInspector` 监听 `":port"` (所有网卡)；③ `inspector/handler.go` 设置 `Access-Control-Allow-Origin: *` |
| **预估工作量** | **2 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/server/admin.go` | `requireAdminAuth` 中增加非 loopback 保护 |
| `cmd/wormhole/cmd/server.go` | Admin 监听默认改为 `127.0.0.1:7001` |
| `pkg/client/client.go` | Inspector 默认绑定 `127.0.0.1` |
| `cmd/wormhole/cmd/client.go` | 新增 `--inspector-host` flag |
| `pkg/inspector/handler.go` | CORS 改为可配置，默认只允许 localhost |
| `pkg/inspector/config.go`（新建）| Inspector 配置结构 |

**具体任务：**

1. **Admin API 安全加固**
   - 当 `AdminToken` 为空时：
     - 如果 Admin 监听地址**不是** loopback（`127.0.0.1` / `[::1]`），**拒绝启动并打印警告**
     - 如果是 loopback 则允许免 token 访问（本机开发场景）
   - 启动时如果绑定 `0.0.0.0` 且无 admin token，打印 **WARNING 日志**

2. **Admin 默认绑定地址**
   - 当前 `cmd/wormhole/cmd/server.go` 中 `AdminAddr` 复用全局 `--host` flag，需要解耦
   - 新增独立的 `--admin-host` flag（默认 `127.0.0.1`），不再共享 `--host`
   - `AdminAddr` 组装逻辑改为：`net.JoinHostPort(adminHost, strconv.Itoa(serverAdminPort))`
   - 如果用户只设置了 `--host` 未设置 `--admin-host`，Admin 仍默认 `127.0.0.1`

3. **Inspector 绑定地址**
   - `StartInspector` 改为默认绑定 `127.0.0.1`
   - `--inspector-host` flag 允许覆盖（如需要外部访问）

4. **CORS 收紧**
   - `handler.go` 中 `Access-Control-Allow-Origin` 默认改为与 Inspector 监听地址一致
   - 新增 `--inspector-cors-origin` 配置项

5. **编写测试**
   - Admin API 在非 loopback + 无 token 时拒绝请求
   - Inspector 默认只能 localhost 访问

**验收标准：**

- [ ] 默认部署：Admin API 只在 `127.0.0.1:7001` 监听
- [ ] 明确配置 `--admin-host 0.0.0.0` 且无 `--admin-token` 时，启动打印 WARNING
- [ ] Inspector 默认绑定 `127.0.0.1`
- [ ] CORS 默认不再是 `*`
- [ ] 老命令行参数向后兼容
- [ ] 全量 lint + test 通过

---

### P0-4: 文档与实现一致性修正

| 属性 | 描述 |
|------|------|
| **目标** | 消除 README / 架构文档中"文档领先实现"或"文档过时"的问题，确保每句话都有代码对应 |
| **当前状态** | ① README 中 Inspector API 示例路径与实际 `/api/inspector/records` 不一致；② README 提到 Inspector 绑定 localhost，但代码绑定 `:port`；③ TLS 相关表述不完全准确；④ CLI flag 表格需更新 |
| **预估工作量** | **1 天** |

> **分批执行策略**：
> - **第一批（无依赖，可立即执行）**：修正与现有实现不一致的错误（Inspector API 路径、绑定地址描述、TLS 当前状态等）
> - **第二批（P0-1/2/3 完成后）**：补充新增 flag/功能的文档（`--tls`、`--protocol`、`--admin-host` 等）

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `README.md` | 全面核对并修正 |
| `README_zh.md` | 同步修正 |
| `docs/architecture.md` | 核对并修正 |
| `docs/architecture_zh.md` | 同步修正 |

**具体任务：**

1. **Inspector API 路径修正**
   - 将文档中所有 Inspector 路径对齐到实际实现：
     - `/api/inspector/records` — 请求列表
     - `/api/inspector/records/{id}` — 请求详情
     - `/api/inspector/stats` — 统计
     - `/api/inspector/clear` — 清空
     - `/api/inspector/toggle` — 开关采集
     - `/api/inspector/ws` — WebSocket 实时流

2. **TLS 表述核对**
   - 区分 "HTTP listener TLS"（已实现）和 "tunnel control TLS"（P0-1 实现后更新）
   - 在 P0-1 完成前，先标注为 "HTTP TLS via Let's Encrypt / manual cert"

3. **CLI 参数表格更新**
   - 在 P0-1/P0-2/P0-3 完成后，补充新增的所有 flag
   - 标注每个 flag 的默认值和可选值

4. **支持协议表述收口**
   - README 中关于 "supports HTTP, WebSocket, gRPC, raw TCP" 的表述，需要对齐到实际 CLI 已暴露的能力
   - 在 P0-2 完成前，先标注为 "底层支持 / CLI 当前默认 HTTP"

**验收标准：**

- [ ] README 中每个 API 路径、CLI flag、默认值都有代码对应
- [ ] `grep -n "localhost:4040" README.md` 返回空（旧路径已清理）
- [ ] TLS 描述不再造成误解
- [ ] 中英文文档完全同步

---

## P1 — 核心竞争力补强

> P1 阶段的目标是：**让 Wormhole 有资格和 frp / ngrok 正面比较**。
> 重点是 P2P 数据面成熟度、协议完整度、运维可观测性。

---

### P1-1: P2P 数据面完善

| 属性 | 描述 |
|------|------|
| **目标** | 将 P2P 数据面从 "simplified implementation" 升级为产品级：支持多连接多路复用、更稳定的 streaming、优雅降级 |
| **当前状态** | `pkg/p2p/transport.go` 实现了 ARQ（seq/ack/重传/FIN/乱序缓冲），但**无多路复用**。`pkg/client/client.go` 源码注释："This is a simplified implementation - full implementation would need proper stream multiplexing over UDP"。`FindPeerForP2P` 只匹配第一个候选 |
| **预估工作量** | **10-15 天**（建议分两期：第一期 7d 基本多路复用 + stream 隔离；第二期 5d 流控 + 背压 + 性能调优） |

> **架构决策点**：需要明确是否集成现有 UDP 多路复用库（如 `xtaci/smux` over KCP、`pion/sctp`），还是完全自研。集成现有库可以显著降低开发风险和工作量，但会引入外部依赖。建议在 P1-1 启动前做一次技术评审。

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/p2p/transport.go` | 核心改造：新增多路复用层 |
| `pkg/p2p/mux.go`（新建）| UDP 多路复用器 |
| `pkg/p2p/stream.go`（新建）| 基于复用器的虚拟 Stream |
| `pkg/p2p/manager.go` | 改进 peer matching 策略 |
| `pkg/client/client.go` | P2P 数据面使用新 mux |
| `pkg/p2p/*_test.go` | 新增测试 |

**具体任务：**

1. **设计 UDP 多路复用协议**
   - 在现有 ARQ 之上加 Stream ID 层
   - 帧格式：`[StreamID(4B)][Type(1B)][Seq(4B)][Payload]`
   - 支持 `Open / Data / ACK / FIN / RST` 帧类型

2. **实现 `UDPMux`**
   ```
   UDPMux
   ├── OpenStream() → *UDPStream
   ├── AcceptStream() → *UDPStream
   ├── Close()
   └── 内部：dispatch 循环，按 StreamID 分发到各 UDPStream
   ```

3. **实现 `UDPStream`**
   - 实现 `io.ReadWriteCloser` 接口
   - 内部复用现有 ARQ 的 seq/ack/重传逻辑
   - 支持背压 / 流控（基于窗口大小）

4. **改进 Peer Matching**
   - `FindPeerForP2P` 增加多因素匹配：
     - 优先选择 NAT 类型互补的 peer（如 Full Cone 优先）
     - 支持指定 peer ID / tunnel ID 的精准匹配

5. **Client 侧集成**
   - 将 P2P 数据面从单 stream 切换到 mux stream
   - 删除 "simplified implementation" 注释

6. **质量保证**
   - 高并发多 stream 压力测试
   - 丢包/乱序模拟测试
   - P2P → relay 降级测试

**验收标准：**

- [ ] 单个 P2P 连接可同时传输多条独立 stream
- [ ] 单 stream 断开不影响其他 stream
- [ ] 10 并发 stream × 1MB 数据传输成功率 > 99%
- [ ] P2P 失败时自动降级到 relay，对上层透明
- [ ] 全量 lint + test 通过

---

### P1-2: 控制协议闭环

| 属性 | 描述 |
|------|------|
| **目标** | 服务端实现对所有已定义协议消息的处理，补全 StatsRequest / CloseRequest |
| **当前状态** | `pkg/proto/messages.go` 定义了 16 种消息类型，但 `pkg/server/server.go` 的 `handleClientStream` 只处理 RegisterRequest / PingRequest / P2POfferRequest / P2PResult 四种 |
| **预估工作量** | **3-4 天**（含重连机制增强） |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/server/server.go` | `handleClientStream` 增加 case 分支 |
| `pkg/client/client.go` | 新增 `RequestStats()` / `CloseTunnel()` 客户端方法；增强重连后 tunnel 恢复逻辑 |
| `cmd/wormhole/cmd/client.go` | 可选：新增 `--stats` subcommand 或 signal handler |

**具体任务：**

1. **Server 端实现 `handleStats()`**
   ```go
   case proto.MessageTypeStatsRequest:
       s.handleStats(client, stream, msg.StatsRequest)
   ```
   - 返回该 client session 的活跃 tunnel 数、连接数、字节统计、运行时间

2. **Server 端实现 `handleClose()`**
   ```go
   case proto.MessageTypeCloseRequest:
       s.handleClose(client, stream, msg.CloseRequest)
   ```
   - 根据 `TunnelID` 找到对应 tunnel，清理路由、释放 TCP 端口、关闭 session
   - 返回 `CloseResponse`

3. **Client 端新增方法**
   - `RequestStats(ctx) (*proto.StatsResponse, error)` — 获取 session 统计
   - `CloseTunnel(ctx, tunnelID, reason) error` — 优雅关闭隧道

4. **Graceful Shutdown 改进**
   - Client 收到 SIGTERM 时，先发 `CloseRequest` 再断开
   - Server 收到 `CloseRequest` 后先排空活跃连接再清理

5. **连接重连机制增强**
   - 当前 `client.go` 有基本的 backoff 重连，但重连后是全新连接，不会恢复 tunnel 注册状态
   - 重连时应自动重新注册之前的 tunnel（从本地状态恢复）
   - 重连期间 Inspector 数据的保持策略（至少不丢失已采集的历史数据）
   - 为 P2-3 HA 场景预留：支持跨节点重连（通过 StateStore 查找可用节点）

6. **编写测试**
   - Stats 请求/响应完整链路测试
   - Close 请求后 tunnel 确实被清理的测试
   - Graceful shutdown 测试

**验收标准：**

- [ ] Client 可成功获取 server 端的 session 统计
- [ ] Client 优雅关闭时 server 端 tunnel 被清理
- [ ] `handleClientStream` 的 `default` 分支只对真正未知类型报警
- [ ] 全量 lint + test 通过

---

### P1-3: MaxClients 及配额 Enforcement

| 属性 | 描述 |
|------|------|
| **目标** | 让 `MaxClients`、`TCPPortRange` 等配额配置真正生效 |
| **当前状态** | `pkg/server/config.go` 中 `MaxClients` 默认 1000，但代码中找不到 enforcement 逻辑 |
| **预估工作量** | **1-2 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/server/server.go` | `handleNewClient()` / `acceptClient()` 中加入客户端数检查 |
| `pkg/server/admin.go` | 新增 Admin API 动态调整配额（可选） |
| `pkg/server/config.go` | 新增更多配额字段（可选：MaxTunnelsPerClient 等） |

**具体任务：**

1. **MaxClients Enforcement**
   ```go
   func (s *Server) acceptClient(...) error {
       s.clientLock.RLock()
       count := len(s.clients)
       s.clientLock.RUnlock()
       if s.config.MaxClients > 0 && count >= s.config.MaxClients {
           // 发送 AuthResponse{Success: false, Error: "server at capacity"}
           return ErrServerAtCapacity
       }
       // ... proceed
   }
   ```

2. **可选：MaxTunnelsPerClient**
   - 限制单个 client session 可注册的 tunnel 数量
   - 在 `handleRegister()` 中检查

3. **可选：Admin API 动态配额**
   - `PUT /config/max-clients` — 动态调整 MaxClients
   - `GET /config` — 查看当前运行配置

4. **编写测试**
   - 达到 MaxClients 后新连接被拒绝
   - 已有 client 断开后可以接受新连接
   - MaxClients=0 表示不限制

**验收标准：**

- [ ] 当活跃 client 数 >= MaxClients 时，新连接收到 "server at capacity" 错误
- [ ] Admin `/stats` 中可见当前活跃 client 数和 MaxClients 配置
- [ ] 全量 lint + test 通过

---

### P1-4: Prometheus Metrics & Tracing

| 属性 | 描述 |
|------|------|
| **目标** | 提供标准化的可观测性输出，支持 Prometheus 指标采集和可选的 OpenTelemetry tracing |
| **当前状态** | 无 metrics endpoint，无 tracing |
| **预估工作量** | **3-4 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/server/metrics.go`（新建）| Prometheus metrics 定义与注册 |
| `pkg/server/admin.go` | 新增 `/metrics` endpoint |
| `pkg/server/server.go` | 在关键路径埋点 |
| `pkg/client/metrics.go`（新建）| Client 侧 metrics（可选） |
| `go.mod` | 新增 `prometheus/client_golang` 依赖 |

**具体任务：**

1. **定义核心指标**

   | 指标名 | 类型 | 描述 |
   |--------|------|------|
   | `wormhole_active_clients` | Gauge | 当前活跃 client 数 |
   | `wormhole_active_tunnels` | Gauge | 当前活跃 tunnel 数 |
   | `wormhole_connections_total` | Counter | 总连接数 |
   | `wormhole_bytes_transferred_total` | Counter | 总传输字节数（label: direction=in/out） |
   | `wormhole_requests_total` | Counter | 总请求数（label: protocol, status） |
   | `wormhole_request_duration_seconds` | Histogram | 请求延迟分布 |
   | `wormhole_auth_attempts_total` | Counter | 认证尝试数（label: result=success/failure） |
   | `wormhole_p2p_connections_total` | Counter | P2P 连接尝试数（label: result=success/fallback） |
   | `wormhole_tunnel_duration_seconds` | Histogram | Tunnel 存活时长 |

2. **暴露 `/metrics` endpoint**
   - 挂在 Admin API 下
   - 使用 `promhttp.Handler()`
   - ⚠️ **部署注意**：如果按 P0-3 安全加固将 Admin 默认绑定 `127.0.0.1`，Prometheus 从外部采集时需要显式 `--admin-host 0.0.0.0 --admin-token <token>`，或考虑单独暴露 `/metrics` endpoint（独立端口，无需 admin token）

3. **关键路径埋点**
   - `acceptClient` → `wormhole_active_clients.Inc()`
   - `removeClient` → `wormhole_active_clients.Dec()`
   - `handleRegister` → `wormhole_active_tunnels.Inc()`
   - `forwardHTTP` → `wormhole_requests_total.Inc()`, `wormhole_request_duration_seconds.Observe()`
   - `authenticate` → `wormhole_auth_attempts_total.Inc()`
   - P2P result → `wormhole_p2p_connections_total.Inc()`

4. **可选：OpenTelemetry Tracing**
   - 在 HTTP handler 和 tunnel 转发路径注入 span
   - 支持 `--otel-endpoint` 配置导出地址

**验收标准：**

- [ ] `curl http://localhost:7001/metrics` 返回 Prometheus 格式指标
- [ ] Grafana 可直接导入 metrics 并生成面板
- [ ] 无 metrics 依赖时不影响正常运行（graceful degradation）
- [ ] 全量 lint + test 通过

---

### P1-5: 控制协议迁移到 Protobuf

| 属性 | 描述 |
|------|------|
| **目标** | 将控制协议从简化 JSON 实现迁移到 Protobuf，提升编解码性能和二进制兼容性，为 P2 阶段的 HA、多 stream、Metrics 等功能奠定基础 |
| **当前状态** | `pkg/proto/messages.go:5` 注释："For now, we use a simplified JSON-based implementation"。项目中已有 `control.proto` protobuf 定义但未使用。随着 P1/P2 功能增加，JSON 编解码的性能和二进制兼容性将成为瓶颈 |
| **预估工作量** | **3-4 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/proto/control.proto` | 完善 protobuf 定义，补全所有消息类型 |
| `pkg/proto/messages.go` | 迁移到 protobuf 生成代码，保留 JSON 兼容（过渡期） |
| `scripts/gen-proto.sh` | 更新 protobuf 代码生成脚本 |
| `pkg/server/server.go` | 适配新的消息编解码 |
| `pkg/client/client.go` | 适配新的消息编解码 |

**具体任务：**

1. **完善 `control.proto`**
   - 确保所有 16 种消息类型都有对应的 protobuf 定义
   - 定义版本协商机制（`ProtocolVersion` 字段）

2. **生成代码与适配**
   - 运行 `gen-proto.sh` 生成 Go 代码
   - 在 `messages.go` 中实现 protobuf 与现有接口的适配层

3. **协议版本协商**
   - 连接建立时协商协议版本（v1=JSON, v2=Protobuf）
   - 服务端同时支持两种协议（向后兼容）
   - 客户端优先使用 Protobuf，降级到 JSON

4. **编写测试**
   - Protobuf 编解码正确性测试
   - JSON ↔ Protobuf 兼容性测试
   - 编解码性能基准测试

**验收标准：**

- [ ] 新版 client 和 server 默认使用 Protobuf 通信
- [ ] 旧版 JSON client 仍可连接新版 server（向后兼容）
- [ ] 编解码性能对比 JSON 有显著提升（benchmark 验证）
- [ ] 全量 lint + test 通过

---

## P2 — 企业级能力

> P2 阶段的目标是：**让 Wormhole 可以在团队/企业环境中生产使用**。
> 重点是身份集成、审计合规、高可用、运维自动化。

---

### P2-1: OIDC / OAuth / SSO 认证集成

| 属性 | 描述 |
|------|------|
| **目标** | 支持企业标准身份提供商（IdP）接入，减少手动 token 管理负担 |
| **当前状态** | 仅支持 HMAC 自签 token 和静态 token 列表。无外部 IdP 集成 |
| **预估工作量** | **5-7 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/auth/oidc.go`（新建）| OIDC Discovery + Token 验证 |
| `pkg/auth/oauth.go`（新建）| OAuth2 Device Code Flow（CLI 场景） |
| `pkg/auth/token.go` | 扩展 `Validate` 支持 JWT / OIDC token |
| `pkg/server/config.go` | 新增 OIDC 配置段 |
| `cmd/wormhole/cmd/client.go` | 新增 `wormhole login` 子命令 |
| `cmd/wormhole/cmd/login.go`（新建）| OAuth Device Code Flow 交互 |

**具体任务：**

1. **OIDC Token 验证**
   - 实现 `.well-known/openid-configuration` 自动发现
   - JWKS 验证 + 缓存
   - claim mapping：`sub` → 用户 ID，自定义 claim → team/role

2. **OAuth2 Device Code Flow**
   - 实现 `wormhole login` 命令
   - 打开浏览器 → 输入 device code → 换取 access token
   - Token 本地持久化到 `~/.wormhole/credentials`

3. **Server 配置**
   ```yaml
   auth:
     oidc:
       issuer: https://accounts.google.com
       client_id: xxx
       audience: wormhole
       claim_mapping:
         team: "custom:team"
         role: "custom:role"
   ```

4. **与现有 HMAC token 共存**
   - 优先检查 OIDC / JWT
   - 如果不是有效 JWT，降级到 HMAC token 验证
   - 保持向后兼容

**验收标准：**

- [ ] 配置 OIDC issuer 后，可用 IdP 签发的 JWT 认证
- [ ] `wormhole login` 完成 OAuth 流程并持久化 token
- [ ] OIDC 与 HMAC token 可同时工作
- [ ] 无 OIDC 配置时行为不变
- [ ] 全量 lint + test 通过

---

### P2-2: 审计日志增强

| 属性 | 描述 |
|------|------|
| **目标** | 将审计日志从简单 JSON stdout 输出，升级为可查询、可导出、可过滤的企业级审计系统 |
| **当前状态** | `pkg/auth/audit.go` 已实现基础审计框架：7 种事件类型、JSON 输出、sync.Mutex 保护。但只写 stdout，无持久化、无查询、无导出 |
| **预估工作量** | **3-4 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/auth/audit.go` | 扩展事件类型、支持多 writer |
| `pkg/auth/audit_store.go`（新建）| 审计日志持久化（SQLite / file） |
| `pkg/server/admin.go` | 新增 `/audit` 查询 API |
| `pkg/server/config.go` | 新增审计配置 |

**具体任务：**

1. **新增事件类型**
   - `EventTokenRevoked` — token 吊销
   - `EventTeamTokensRevoked` — 团队级吊销
   - `EventTunnelCreated` — tunnel 创建
   - `EventTunnelClosed` — tunnel 关闭
   - `EventP2PEstablished` — P2P 连接建立
   - `EventP2PFallback` — P2P 降级到 relay
   - `EventConfigChanged` — 配置变更（如动态配额调整）

2. **审计存储后端**
   - SQLite 模式：写入 `audit_events` 表
   - 文件模式：写入 JSONL 文件，支持 rotation
   - 内存模式：ring buffer 保留最近 N 条
   - ⚠️ **HA 注意**：SQLite 为单机方案，P2-3 HA 多节点场景下需要替换为分布式存储（如 PostgreSQL / ClickHouse / S3 JSON），建议在审计存储接口设计时预留可扩展性

3. **Admin API 查询**
   - `GET /audit?type=auth_failure&from=2026-04-01&limit=100`
   - 支持按时间范围、事件类型、团队名、IP 过滤
   - 支持分页

4. **审计日志导出**
   - `GET /audit/export?format=csv` — CSV 导出
   - `GET /audit/export?format=json` — JSON 批量导出

**验收标准：**

- [ ] 所有关键操作都有审计事件
- [ ] `/audit` API 可按条件查询
- [ ] SQLite 模式下审计日志持久化且可重启恢复
- [ ] 全量 lint + test 通过

---

### P2-3: HA / 多节点控制面

| 属性 | 描述 |
|------|------|
| **目标** | 支持多 server 节点部署，实现高可用和水平扩展 |
| **当前状态** | 单节点架构，所有 client session / tunnel / route 状态在内存中 |
| **预估工作量** | **10-15 天**（最大开发项） |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/server/cluster.go`（新建）| 集群成员发现与心跳 |
| `pkg/server/state.go`（新建）| 共享状态存储接口 |
| `pkg/server/state_redis.go`（新建）| Redis 状态后端 |
| `pkg/server/router.go` | 路由查找支持跨节点 |
| `pkg/server/server.go` | 连接转发到正确节点 |
| `pkg/server/config.go` | 集群配置 |

**具体任务：**

1. **共享状态存储**
   - 定义 `StateStore` 接口：`RegisterTunnel / RemoveTunnel / LookupTunnel / ListNodes`
   - Redis 实现：tunnel → node 映射、node 心跳
   - 本地模式：单节点行为不变

2. **集群成员管理**
   - 节点启动时注册到 Redis（`wormhole:nodes:{id}`，TTL 心跳）
   - 定期更新心跳、清理过期节点
   - 节点退出时主动反注册

3. **跨节点路由**
   - HTTP 请求到达节点 A，但 tunnel 在节点 B：
     - 节点 A 从 `StateStore` 查找 tunnel 所在节点
     - 通过节点间 gRPC / HTTP 转发请求到节点 B
   - 或：使用共享 LB（如 Nginx）根据 subdomain 路由到正确节点

4. **一致性保证**
   - tunnel 注册/注销使用 Redis 事务
   - 节点崩溃后 TTL 过期自动清理残留 tunnel

5. **Client 连接故障转移策略**
   - Client 的 tunnel control connection（长连接）如何在多节点间分配和故障转移
   - 当 client 连接的节点挂掉后，client 需要重连到其他可用节点
   - 重连策略：依赖 client 侧自动重连 + 通过 StateStore 恢复 tunnel 元数据
   - 或 client 重连后自动重新注册（利用 P1-2 的重连机制增强）
   - LB 层需要支持长连接的 health check 和故障剔除

6. **部署方案**
   ```
   LB (Nginx / HAProxy)
   ├── wormhole-server-1 (node-1)
   ├── wormhole-server-2 (node-2)
   └── wormhole-server-3 (node-3)
   └── Redis (shared state)
   ```

**验收标准：**

- [ ] 2+ 节点可同时运行，tunnel 分布在不同节点
- [ ] Client 连接任意节点均可正常注册和使用 tunnel
- [ ] 单节点崩溃后，残留 tunnel 在 TTL 后自动清理
- [ ] 不配置 Redis 时退化为单节点模式（向后兼容）
- [ ] 全量 lint + test 通过

---

### P2-4: Tunnel 生命周期与动态配置管理

| 属性 | 描述 |
|------|------|
| **目标** | 支持 tunnel 的声明式配置、热重载、生命周期管理 |
| **当前状态** | tunnel 仅通过 CLI 参数创建，无配置文件、无热重载、无 tunnel 列表管理 |
| **预估工作量** | **4-5 天** |

**涉及文件：**

| 文件 | 改动类型 |
|------|----------|
| `pkg/client/config_file.go`（新建）| 配置文件加载与解析 |
| `pkg/client/client.go` | 支持多 tunnel、热重载 |
| `cmd/wormhole/cmd/client.go` | 新增 `--config` flag |
| `cmd/wormhole/cmd/tunnels.go`（新建）| `wormhole tunnels list/create/delete` 子命令 |

**具体任务：**

1. **配置文件格式**
   ```yaml
   # ~/.wormhole/config.yml
   server: tunnel.example.com:7000
   tls: true
   token: your-team-token

   tunnels:
     web:
       protocol: http
       local_port: 8080
       subdomain: myapp
       inspector: true

     api:
       protocol: http
       local_port: 3000
       hostname: api.example.com

     db:
       protocol: tcp
       local_port: 5432
   ```

2. **多 Tunnel 支持**
   - Client 从配置文件加载多个 tunnel 定义
   - 单个 mux 连接上注册多个 tunnel

3. **热重载**
   - `SIGHUP` 触发配置重载
   - 对比差异：新增 tunnel → 注册，删除 tunnel → CloseRequest，变更 → 先关再开

4. **CLI 管理命令**
   - `wormhole tunnels list` — 列出当前活跃 tunnel
   - `wormhole tunnels create --protocol tcp --local 3306` — 动态创建
   - `wormhole tunnels delete <tunnel-id>` — 动态删除

**验收标准：**

- [ ] `wormhole client --config config.yml` 可一次启动多个 tunnel
- [ ] `SIGHUP` 触发热重载，新增/删除 tunnel 正常生效
- [ ] `wormhole tunnels list` 可列出活跃 tunnel
- [ ] 无配置文件时行为不变（向后兼容）
- [ ] 全量 lint + test 通过

---

## 时间规划概览

```
Phase       Item              Effort      Dependencies
──────────────────────────────────────────────────────────
P0-1        TLS 闭环           2-3d        无
P0-2        多协议入口          3-4d        无
P0-3        安全加固            2d          无
P0-4        文档修正(第一批)     0.5d        无（现有实现的错误修正）
P0-4        文档修正(第二批)     0.5d        P0-1, P0-2, P0-3
──────────────────────────────────────────────────────────
            P0 小计            ~10d
──────────────────────────────────────────────────────────
P1-1        P2P 数据面          10-15d      P0-2（分两期）
P1-2        协议闭环+重连增强    3-4d        无
P1-3        配额 Enforce       1-2d        无
P1-4        Metrics            3-4d        P0-3（Admin 绑定地址）
P1-5        Protobuf 迁移      3-4d        P1-2
──────────────────────────────────────────────────────────
            P1 小计            ~24d
──────────────────────────────────────────────────────────
P2-1        OIDC/SSO           5-7d        P0-1
P2-2        审计增强            3-4d        P1-4
P2-3        HA/多节点           10-15d      P1-2, P1-3, P1-5
P2-4        Tunnel 生命周期     4-5d        P1-2
──────────────────────────────────────────────────────────
            P2 小计            ~28d
──────────────────────────────────────────────────────────
            总计               ~62d (单人)
```

### 建议执行顺序

```
Week 1:     P0-4(第一批) + P0-1 + P0-3 (可并行)
Week 2:     P0-2 + P0-4(第二批)
Week 3:     P1-2 + P1-3 + P1-4 (可并行，无依赖关系)
Week 4-5:   P1-1 第一期 (基本多路复用 + stream 隔离)
Week 5-6:   P1-1 第二期 (流控 + 背压 + 性能调优) + P1-5 (可交叉)
Week 7-8:   P2-1 + P2-2 (可并行)
Week 9-10:  P2-4
Week 11-15: P2-3 (最大项，可拆成多个 PR)
```

> **并行度优化说明**：P1-4（Metrics）和 P1-1（P2P）没有依赖关系，P1-2/P1-3 也相互独立，Week 3 集中处理这些独立任务。P1-1 较长，可以和 P1-5 交叉进行避免疲劳。

### 测试覆盖率目标

| 阶段 | 目标 |
|------|------|
| **P0 完成后** | 核心包（`client` / `server` / `proto`）测试覆盖率 ≥ 60% |
| **P1 完成后** | 核心包测试覆盖率 ≥ 75%，`p2p` 包 ≥ 70% |
| **P2 完成后** | 整体测试覆盖率 ≥ 70%，关键路径 ≥ 80% |

### 里程碑

| 里程碑 | 标志 | 预期时间 |
|--------|------|----------|
| **v0.9 — 安全基线** | P0 全部完成，默认安全，文档可信 | Week 2 |
| **v1.0 — 产品级** | P1 全部完成，可与 frp 正面对标 | Week 6 |
| **v1.5 — 团队级** | P2-1 + P2-2 完成，支持 SSO 和审计 | Week 8 |
| **v2.0 — 企业级** | P2 全部完成，支持 HA 和声明式配置 | Week 15 |

### 版本发布规则

> _2026-04-11 新增：每完成一个子模块即发布一个 patch 版本，方便阶段性 review 和回滚。_

**当前版本：v0.4.5**

**规则：**

1. **每完成一个独立的开发项（如 P1-3、P1-2 等），在自检通过后，先发布一个 patch 版本再继续下一个开发项。**
2. AI 助手需主动建议版本号和 commit message，用户确认后提交，作为该阶段的 review 节点。
3. 版本号遵循 [Semantic Versioning](https://semver.org/)：
   - **patch**（`x.y.Z`）：单个开发项完成（如 P1-3 完成 → `v0.4.1`）。
   - **minor**（`x.Y.0`）：一个完整阶段完成（如 P1 全部完成 → `v0.5.0`）。
   - **major**（`X.0.0`）：重大里程碑或不兼容变更。
4. Commit message 格式：`feat(scope): 简要描述 [vX.Y.Z]`，body 中列出关键变更。

**版本发布记录：**

| 版本 | 对应开发项 | 日期 | 说明 |
|------|-----------|------|------|
| v0.4.0 | P0 全部完成 | 2026-04-11 | 安全与基础能力闭环，TLS、多协议 CLI、安全加固、文档修正 |
| v0.4.1 | P1-3 | 2026-04-11 | MaxClients 及配额 Enforcement |
| v0.4.2 | P1-2（部分） | 2026-04-11 | 控制协议闭环：Server 端 StatsRequest/CloseRequest 处理，Client 端 RequestStats()/CloseTunnel() 方法 |
| v0.4.3 | P1-4 | 2026-04-11 | Prometheus Metrics & /metrics endpoint；goconst 修复 |
| v0.4.4 | P1-2（完成） | 2026-04-12 | 控制协议完善：CMD 级 graceful shutdown（c.Close() 发送 CloseRequest）；9 个 RequestStats/CloseTunnel 集成测试 |
| v0.4.5 | P1-5 | 2026-04-14 | 控制协议迁移到 Protobuf：control.proto 补全 P2P 消息、pb/control.pb.go 生成、messages.go 实现完整 protobuf↔struct 适配层、Encode() 默认 Protobuf、DecodeControlMessage() 优先 Protobuf 兜底 JSON、WriteControlMessage/ReadControlMessage 长度前缀帧协议；decode 性能 4.2x 提升；全量测试通过 |

---

> **最后建议**：P0 是"不做就不能自信推荐给别人用"的底线，建议不间断完成。P0-4 第一批（修正现有错误）可以立即启动，不必等其他 P0 完成。P1 中 P1-1（P2P 数据面）是 Wormhole 最大的差异化资产，值得投入最多精力，启动前建议做一次技术评审确定是否集成现有 UDP 多路复用库。P1-5（Protobuf 迁移）是 P2 阶段 HA 和性能的基础，不宜推迟到 P2。P2 可以根据实际用户反馈调整优先级。
