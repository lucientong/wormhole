# 更新日志

本文件记录 Wormhole 每个版本的重要变更。使用说明见 [README_zh.md](README_zh.md)，当前系统架构见 [docs/architecture_zh.md](docs/architecture_zh.md)。

**[English](CHANGELOG.md)**

## v0.6.10

安全加固：集群节点间的密钥头（`X-Wormhole-Cluster-Secret`）在请求转发给隧道客户端的本地服务之前会被剥离，共享密钥不再可能泄露进用户内网或应用日志。Token 吊销检查改为 fail-closed——校验期间 Redis/SQLite 故障会拒绝该 token，而不是在无法确认吊销状态时静默放行。认证失败对客户端统一返回笼统的 "authentication failed"（具体原因只写入服务端日志），避免被用来枚举 token 状态。客户端自选的子域名在路由/存储前会按 DNS label 规则校验，拒绝可能产生异常路由或向日志注入控制字符的非法值。启动 Redis 集群时，缺少 `--cluster-node-addr` 会直接快速失败，未设置 `--cluster-secret` 会发出显著告警（否则节点间代理是未认证的）。

## v0.6.9

Client 侧重构：此前 ~2100 行的 `Client` 现在降级为组合根，由 `RelayClient`（控制面连接、含 token 刷新的鉴权、单/多隧道注册、心跳、重连循环）与 `P2PSession`（`wormhole connect` 的 NAT 探测、ECDH 密钥交换、打洞、P2P 数据面）承接。两者都只通过 `Client` 实现的两个小型接口（`localForwarder`/`statsRecorder`）依赖它，`P2PSession` 回调 `RelayClient` 也只经过最小化的 `RelayChannel` 接口——三者互不知道对方的具体类型。原来同时保护两个子系统的一把锁，现在拆成各自精确对应保护范围的两把锁。这与下方 v0.6.8 的 server 侧重构相呼应，也是同一次重构的收尾。

## v0.6.8

Server 侧重构：此前 ~2200 行的 `Server` 现在降级为组合根，由三个独立组件承接：`TunnelRegistry`（客户端会话生命周期、本地/集群路由、TCP 端口分配、集群心跳）、`ProxyService`（HTTP/WebSocket/TCP 数据面转发与并发流预算）、`P2PBroker`（`wormhole connect` 的 offer/result 信令编排）。Admin API 的 `/stats`/`/health`/`/clients`/`/tunnels` 接口现在改为调用 `TunnelRegistry` 的公开方法，不再直接伸手进 `Server` 内部。跨节点转发同时新增 `validateClusterNodeAddr`，在拼接转发目标前先校验为纯 `host:port`——防止状态存储中的异常条目被拼入意料之外的 scheme/用户信息/路径。

## v0.6.7

`Server` 在 `Start(ctx)` 中派生出一个可取消的根 context，并在 `Shutdown()` 的第一步取消它，因此服务端调用树深处此前硬编码等待固定超时的几个位置（认证握手接受、TCP 端口分配、P2P 对端通知、TCP 隧道流打开）在关闭时会立即响应取消，不再需要等自身的固定超时（如认证超时）才返回。`tunnel.Stream` 新增 `ReadContext`/`WriteContext`，持有可取消 ctx 的调用方现在能中断正在阻塞的 `Read`/`Write`——普通的 `Read`/`Write` 仍以不可取消的 context 委托给它们，因此数据面热路径（`io.Copy` 等）不会有任何额外开销。同样的修复也应用到了客户端 14 处存在相同缺口的控制面 RPC（认证、注册、心跳、统计、关闭、P2P offer/result）。

## v0.6.6

`Mux.sendData` 现在复用一个池化的 32KB payload 缓冲区，替代每次 `Stream.Write` 都重新分配（隔离基准测试显示单次发送内存占用降低 99.7%，吞吐 +72%）。服务端 HTTP 响应体/WebSocket/TCP 隧道转发与客户端转发（包括 `wormhole connect`）统一由裸 `io.Copy` 改为池化的 `io.CopyBuffer`，隔离基准测试显示单次拷贝内存占用降低 88.5%，此前被吞掉的拷贝错误现在会以 debug 级别记录。修复了 Inspector 的一个 OOM 风险：读取请求/响应正文时此前没有任何大小上限（尽管代码注释声称有），现已用配置的 `MaxBodySize` 限定。

## v0.6.5

HTTP/管理监听改为带超时的 `Shutdown(ctx)` 优雅关闭，而非进程直接退出；双向代理（WebSocket/TCP）任一方向出错即触发双侧收尾，不再需要等对端超时才释放连接；新增 `--max-concurrent-streams`/`--max-streams-per-client`，超出上限直接拒绝新流而非无限排队；控制消息解码器拒绝畸形的 `UNKNOWN` 类型空控制帧，同时继续放行携带 payload 的、面向未来兼容的未知类型；新增 `--min-client-version` 语义化版本门禁，以及服务端真实能力集广播（`p2p`/`multi-tunnel`/`cluster`/`audit`），client 不再盲目假设可选特性一定存在；删除从未接线的连接池死代码；`--protocol` 可选值中移除 udp（服务端从未实现 UDP 数据面），现在会显式报错而非静默降级；新增 `wormhole tunnels create/delete`，支持给运行中的 client 命令式增删隧道；新增 `wormhole server -c server.yml`，服务端配置文件支持与客户端保持一致。

## v0.6.4

HA 二期：集群心跳每轮同时重新注册（刷新 TTL）该节点持有的每一条路由，修复长连接下路由从 Redis 静默过期的问题；hostname/path 前缀路由现已索引进 Redis，可跨节点访问，不再局限于子域名；`ClusterNodeID` 未设置时默认取 `os.Hostname()`；新增 `--cluster-secret` 校验节点间代理请求；新增 `--persistence redis`，团队/Token 吊销状态跨节点共享、即时失效；`/health` 新增 Redis 连接状态（`cluster.state_store_healthy`，不可达时整体状态降级）；客户端重连时立即回收陈旧持有者的子域名/hostname/path，不再遇到虚假冲突；文档明确 TCP 隧道在 HA 下仅节点本地可达。

## v0.6.3

安全加固：RBAC 写权限检查（viewer 不能再注册/关闭隧道）；隧道控制链路 TLS 与 HTTP 数据面 TLS 解耦，`--require-auth` 配合真实域名时默认开启（配置错误时启动失败而非静默明文）；子域名注册改为原子的、集群一致的申请，真实冲突拒绝新连接而非悄悄覆盖已有路由；修复 token 过期计算的数据竞争，补齐吊销黑名单的周期清理调度；OIDC 显式拒绝 `alg: none` 并校验 `nbf`（带时钟容差）；Inspector 默认对敏感请求头脱敏，并下调默认正文捕获上限；`/metrics` 现在需要管理员认证；审计日志补齐认证成功/IP 封禁/Token 生成/IP 解封事件，并支持可配置的保留期清理（`--audit-retention-days`），同时在 `/stats` 新增 `audit_store_errors` 计数，使审计持久化失败不再无声无息。

## v0.6.2

P2P 数据面接入与传输优化：新增 `wormhole connect <子域名>` 命令，两个 `wormhole client` 打洞后流量全程 P2P 直连（server 只做信令，不转发一个字节）；可靠 UDP 传输从固定重传超时升级为 RFC 6298 风格自适应 RTO + 按段指数退避；发送/接收路径降拷贝（加密直写目标 buffer、消除冗余拷贝）；删除已被取代的单流 ARQ 实现。

## v0.6.1

正确性闭环：可靠的连接丢失检测（mux 关闭通知 + 心跳触发强制重连）、真正生效的多隧道路由（端到端接线分发）、修复 P2P 信令帧不匹配、P2P 接收缓冲背压（带超时的阻塞交付 + 消费者卡死时 RST）、TCP 端口分配失败拒绝注册、可靠的 P2P 建流握手（SYN 重传 + SYN-ACK，此前只要一个 SYN 包在丢包环境下丢失，连接就会悄无声息地"半开"卡死）、修复 WebSocket inspector 的数据竞争。**端到端 SSO 可用**：`wormhole login` 保存的凭证现在会被 `wormhole client` 自动加载（无需再手动 `--token`），access token 过期后通过 refresh token 静默续期（包括会话中途、断线重连场景），device flow 轮询请求补齐 `client_id`（符合 RFC 8628），`wormhole client` 未传 `--local`/`--config` 时会回退到默认配置路径。

## v0.6.0

P2（企业级能力）收尾：修复 22 项 lint 警告与若干安全扫描问题（显式处理错误返回、SQL 全参数化）；全部测试（含 race detector）通过，lint 与安全扫描均无告警。

## v0.5.4

HA / 多节点控制面：`StateStore` 接口（路由条目、节点心跳、失效节点驱逐）；单节点验证用的内存实现，以及用于生产集群的 Redis 后端实现；集群心跳 goroutine（30 秒间隔，2 分钟驱逐阈值）；跨节点 HTTP 反向代理；新增 `--cluster-node-id`/`--cluster-redis-addr` 等参数。

## v0.5.3

OIDC / OAuth SSO：OIDC Discovery + JWKS JWT 校验（RS256/ES256/ES384）；OAuth2 Device Code Flow；本地凭证持久化；`wormhole login` 子命令。

## v0.5.2

声明式隧道配置与生命周期管理：YAML 客户端配置文件；支持并行注册多个隧道；`SIGHUP` 热重载（差量对比增删隧道）；本地控制 API 暴露隧道状态；`wormhole tunnels list` 子命令。

## v0.5.1

审计日志增强：新增 6 种事件类型；可插拔的 `AuditStore`（内存环形缓冲区或 SQLite 持久化）；Admin API 查询（`GET /audit`，支持过滤）与导出（`GET /audit/export`，CSV/JSON）接口。

## v0.5.0

P2P 数据面完善：多路复用、可靠的 UDP 传输（自定义帧头，ARQ + 滑动窗口流控）；P2P 可用时客户端完全切换到该传输层，否则回退到 relay；按 NAT 类型排序的 peer 匹配；对称 NAT 场景下的端口预测候选；模拟丢包环境下的压力测试。

## v0.4.5

控制协议迁移到 Protobuf：完整消息 schema、生成的代码绑定、完整的 protobuf↔struct 适配层，以及带长度前缀的帧协议；为保持向后兼容自动回退到 JSON；解码性能提升约 4.2 倍。

## v0.4.0 – v0.4.4

初始的安全与核心能力基线：端到端 TLS、多协议 CLI（HTTP/HTTPS/TCP/WebSocket/gRPC）、连接数/配额限制、Prometheus 指标，以及最初的控制协议请求/响应生命周期（统计查询、隧道关闭、客户端优雅退出）。

## 更早期的开发

在上面这种"每个变更对应一个版本号"的规范建立之前，Wormhole 经历了一段初期开发阶段，主要包括：带多路复用的 TCP 隧道；带 TLS 与 Admin API 的 HTTP 主机路由；流量检查器 UI；P2P 基础原语（STUN、打洞、端口预测、信令）及其端到端集成（peer 匹配、数据传输、Relay→P2P 自动切换）；基于 HMAC Token 与角色权限的团队认证；以及 P2P 端到端加密（X25519 ECDH + AES-256-GCM，带 HMAC 认证的打洞）。
