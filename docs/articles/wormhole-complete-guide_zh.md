# Wormhole：从零构建现代内网穿透工具

> 深入解析 [Wormhole](https://github.com/lucientong/wormhole) —— 一款零配置、可自托管的 Go 内网穿透工具，涵盖二进制帧协议、流多路复用、P2P 打洞、端到端加密，以及与 ngrok、frp 等竞品的对比。

## 目录

1. [为什么要自己造轮子？](#1-为什么要自己造轮子)
2. [架构概览](#2-架构概览)
3. [核心：二进制帧协议](#3-核心二进制帧协议)
4. [核心：流多路复用](#4-核心流多路复用)
5. [控制协议与 HTTP 路由](#5-控制协议与-http-路由)
6. [P2P：STUN NAT 探测](#6-p2p-stun-nat-探测)
7. [P2P：UDP 打洞](#7-p2p-udp-打洞)
8. [P2P：端到端加密](#8-p2p-端到端加密)
9. [P2P：NAT 诊断与 FAQ](#9-p2p-nat-诊断与-faq)
10. [认证与安全](#10-认证与安全)
11. [与竞品对比](#11-与竞品对比)
12. [快速上手与部署](#12-快速上手与部署)
13. [经验总结](#13-经验总结)

---

## 1. 为什么要自己造轮子？

现有的内网穿透方案如 ngrok、frp、Cloudflare Tunnel 都很好用——直到遇到瓶颈：

- **ngrok 免费版**限制单一端点、随机子域名、有速率限制。付费版起步 $8/月。
- **Cloudflare Tunnel** 要求所有流量经过 Cloudflare 网络，与其生态深度绑定。
- **frp** 功能强大但配置繁琐——每个服务都需要在客户端和服务端写 TOML 配置。
- **厂商锁定**：如果服务调价或下线功能，你的工作流就会中断。

Wormhole 诞生于对**零配置、可自托管**隧道工具的需求，同时支持 P2P 直连和端到端加密等现代特性。

---

## 2. 架构概览

Wormhole 采用客户端-服务器模型，可选 P2P 直连：

```
                    ┌─────────────────────────────────┐
                    │         Wormhole Server          │
 互联网 ──────────▶ │  ┌─────────┐  ┌──────────────┐  │
  (HTTP/TCP)        │  │ 路由器   │  │ 隧道多路复用  │  │
                    │  │ (主机 →  │──│ (单连接承载   │──│────▶ 客户端 A
                    │  │  客户端) │  │  多个流)      │  │
                    │  └─────────┘  └──────────────┘  │
                    │                                  │────▶ 客户端 B
                    └─────────────────────────────────┘
                                         │
                                     (可选)
                                         │
                    客户端 A ◀── P2P UDP 打洞 ──▶ 客户端 B
                                  (E2E 加密)
```

系统由五个主要层组成：

| 层级 | 职责 |
|------|------|
| **帧协议** | 自定义二进制格式，用于所有数据交换 |
| **流多路复用** | 单个 TCP 连接上承载多个逻辑流 |
| **控制协议** | JSON 格式的握手、注册、信令消息 |
| **HTTP 路由** | 将入站请求映射到正确的客户端隧道 |
| **P2P 子系统** | STUN 探测、打洞、加密直连 |

---

## 3. 核心：二进制帧协议

所有传输数据都封装在**帧**中。格式故意设计得很简单——10 字节固定头部加可变长度载荷：

```
+----------+----------+------------+----------+------------------+
| Version  |   Type   |  StreamID  |  Length  |     Payload      |
|  1 字节  |  1 字节  |   4 字节   |  4 字节  |      N 字节      |
+----------+----------+------------+----------+------------------+
```

### 为什么这样设计？

- **固定头部大小**（10 字节）：解码器总是准确知道先读多少字节，简化状态机。
- **版本字节**：为协议升级预留。当前固定为 `1`。
- **StreamID**：标识帧属于哪个逻辑流。`0` 保留给连接级帧（ping/pong）。
- **长度字段在载荷前**：读 10 字节，提取长度，再精确读取对应字节。无需分隔符或转义。

### 帧类型

七种帧类型处理所有通信：

```go
const (
    FrameData         FrameType = 0x01  // 流数据
    FrameWindowUpdate FrameType = 0x02  // 流控
    FramePing         FrameType = 0x03  // 保活请求
    FramePong         FrameType = 0x04  // 保活响应
    FrameClose        FrameType = 0x05  // 流关闭
    FrameHandshake    FrameType = 0x06  // 新建流
    FrameError        FrameType = 0x07  // 错误信号
)
```

这借鉴了 HTTP/2 的帧设计但做了精简——隧道数据是不透明字节，不需要 HEADERS、SETTINGS 等复杂帧类型。

### 编解码器

`FrameCodec` 使用 `sync.Pool` 复用头部缓冲区，减少热路径上的 GC 压力：

```go
type FrameCodec struct {
    maxPayloadSize uint32
    bufferPool     *sync.Pool
}

func (c *FrameCodec) Encode(w io.Writer, f *Frame) error {
    // 从池中获取头部缓冲区
    bufPtr := c.bufferPool.Get().(*[]byte)
    header := *bufPtr
    defer c.bufferPool.Put(bufPtr)

    // 编码：[Version][Type][StreamID][Length]
    header[0] = f.Version
    header[1] = byte(f.Type)
    binary.BigEndian.PutUint32(header[2:6], f.StreamID)
    binary.BigEndian.PutUint32(header[6:10], uint32(len(f.Payload)))

    if _, err := w.Write(header); err != nil {
        return fmt.Errorf("write header: %w", err)
    }
    if len(f.Payload) > 0 {
        if _, err := w.Write(f.Payload); err != nil {
            return fmt.Errorf("write payload: %w", err)
        }
    }
    return nil
}
```

**安全边界**：最大载荷限制为 **16 MB**（`MaxFramePayloadSize`），默认 **32 KB**。防止恶意对端强制分配无限内存。

---

## 4. 核心：流多路复用

单个 TCP 连接在客户端和服务器之间承载多个逻辑**流**——每个流代表一个独立的代理请求。

### 为什么要多路复用？

每个请求创建新 TCP 连接意味着：
- 每个请求都有 TCP 握手延迟
- TLS 重协商开销
- 两端连接数压力
- 无法维持持久控制通道

Wormhole 只创建**一个** TCP 连接，在其上多路复用多个流，就像 HTTP/2 一样。

### 流 ID 分配

客户端和服务器使用**奇偶数流 ID**避免冲突：

```go
if isClient {
    m.nextStreamID = 1  // 1, 3, 5, 7, ...
} else {
    m.nextStreamID = 2  // 2, 4, 6, 8, ...
}
```

### Mux 架构

`Mux` 结构运行三个后台 goroutine：

```go
type Mux struct {
    conn    net.Conn           // 底层 TCP 连接
    codec   *FrameCodec        // 帧编解码器
    streams map[uint32]*Stream // 活跃流（按 ID 索引）
    sendCh  chan *Frame        // 出站帧队列
}

func newMux(conn net.Conn, config MuxConfig, isClient bool) (*Mux, error) {
    m := &Mux{...}
    go m.recvLoop()      // 读帧 → 分发到流
    go m.sendLoop()      // 消费 sendCh → 写入连接
    go m.keepAliveLoop() // 定期 ping/pong
    return m, nil
}
```

**为什么要专用发送 goroutine？** 多个流并发写入。与其争抢 `net.Conn` 的互斥锁，不如将所有帧入队到 `sendCh`，由单个 goroutine 串行化写入。

### 流控

每个流有**发送窗口**和**接收窗口**，类似 TCP 滑动窗口：

```go
type StreamConfig struct {
    WindowSize     uint32  // 初始：256KB
    MaxWindowSize  uint32  // 最大：16MB
    ReadBufferSize int     // 读缓冲：64KB
}
```

当流的读缓冲区被消费时，发送 `FrameWindowUpdate` 告诉发送方可以发更多数据。

### 保活

多路复用器定期发送 `FramePing`（默认每 30 秒），期望在超时时间（10 秒）内收到 `FramePong`。如果没有收到响应，连接视为断开并被拆除。

---

## 5. 控制协议与 HTTP 路由

### 控制消息

Wormhole 使用 **JSON 格式的控制协议**处理结构化消息。控制消息在普通多路复用流上传输：

```go
type ControlMessage struct {
    Type     MessageType `json:"type"`
    Sequence uint64      `json:"sequence"`

    AuthRequest      *AuthRequest      `json:"auth_request,omitempty"`
    RegisterRequest  *RegisterRequest  `json:"register_request,omitempty"`
    P2POfferRequest  *P2POfferRequest  `json:"p2p_offer_request,omitempty"`
    // ...
}
```

**为什么用 JSON？** 控制消息不频繁且很小。JSON 自描述特性方便调试。热路径——实际数据传输——使用二进制帧协议。

### 连接握手

```
客户端                                   服务器
  │                                          │
  │──── TCP 连接 ───────────────────────────▶│
  │                                          │
  │──── [Stream 1] AuthRequest ────────────▶ │
  │◀─── [Stream 1] AuthResponse ─────────── │
  │                                          │
  │──── [Stream 3] RegisterRequest ────────▶ │
  │◀─── [Stream 3] RegisterResponse ──────── │
  │           {tunnel_id, public_url}        │
```

### HTTP 路由

`Router` 支持三种路由策略，按优先级检查：

1. **自定义主机名** —— 完整主机名匹配（如 `api.mycompany.com`）
2. **子域名** —— 子域名提取（如 `myapp.tunnel.example.com`）
3. **路径前缀** —— 最长前缀匹配（如 `/myapp/`）

```go
func (r *Router) Route(host, path string) *ClientSession {
    // 1. 自定义主机名匹配
    if client, ok := r.hostnames[host]; ok {
        return client
    }
    // 2. 子域名匹配
    if subdomain := r.extractSubdomain(host); subdomain != "" {
        if client, ok := r.subdomains[subdomain]; ok {
            return client
        }
    }
    // 3. 路径前缀匹配
    return r.matchPath(path)
}
```

---

## 6. P2P：STUN NAT 探测

大多数计算机位于 NAT 后面。当两个都在 NAT 后的对端想要直接通信时，双方都无法到达对方——NAT 会丢弃未经请求的入站包。

中继方案增加延迟（多两跳）。如果双方在同一城市，但中继服务器在大洋彼岸，每个包都要付出沉重的 RTT 代价。

### STUN 协议

STUN（RFC 5389）很简单：向 STUN 服务器发送 UDP 包，它会告诉你看到的 IP:port——你的**映射地址**。

从**同一个本地端口**查询两个不同的 STUN 服务器，可以分类 NAT 类型：

| 场景 | NAT 类型 | 可以 P2P？ |
|------|----------|------------|
| 映射地址 == 本地地址 | 无 NAT（公网 IP） | ✅ |
| 两个服务器看到相同映射地址 | 锥形 NAT | ✅ |
| 不同映射地址 | 对称 NAT | ❌（基本） |

### 实现

Wormhole 实现了纯 Go STUN 客户端——无外部依赖：

```go
const (
    stunMagicCookie  = 0x2112A442
    stunHeaderSize   = 20
    stunBindingReq   = 0x0001
)

func buildBindingRequest(txID [12]byte) []byte {
    msg := make([]byte, stunHeaderSize)
    binary.BigEndian.PutUint16(msg[0:2], stunBindingReq)
    binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
    copy(msg[8:20], txID[:])
    return msg
}

func classifyNAT(local, mapped1, mapped2 *Endpoint) NATType {
    if local.Port == mapped1.Port && isPublicIP(local.IP) {
        return NATNone
    }
    if mapped1.IP == mapped2.IP && mapped1.Port == mapped2.Port {
        return NATPortRestricted  // 保守估计
    }
    return NATSymmetric
}
```

---

## 7. P2P：UDP 打洞

### 工作原理

NAT 维护映射表。当你的机器向 `dest:port` 发送 UDP 时，NAT 创建一条条目允许来自该目标的响应。

技巧：如果对端 A 向对端 B 的公网地址发送，**同时** B 也向 A 的公网地址发送，两边 NAT 都会创建条目。其中一个包会在另一方 NAT 条目创建后到达——然后就通了！

### Wormhole 打洞协议（WHPP）

探测包结构简单：

```
┌──────────────┬───────────┬────────────────────────┐
│  Magic (4B)  │ Payload   │  HMAC-SHA256 Tag (32B) │
│  "WHPP"      │ "probe"   │  (认证标签)             │
└──────────────┴───────────┴────────────────────────┘
```

4 字节魔数 `"WHPP"`（WormHole Punch Protocol）防止随机 UDP 流量误判。HMAC 标签使用 ECDH 共享密钥派生的密钥认证发送方。

```go
func (h *HolePuncher) sendProbes(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) {
    baseProbe := append(punchMagic, []byte("probe")...)
    
    // 附加 HMAC 标签认证
    probe := baseProbe
    if h.cipher != nil {
        tag := h.cipher.SignProbe(baseProbe)
        probe = append(baseProbe, tag...)
    }

    // 立即发送第一个探测，然后每 100ms 发送一次
    conn.WriteTo(probe, peer)
    
    ticker := time.NewTicker(100 * time.Millisecond)
    for i := 1; i < 30; i++ {  // 30 次尝试
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            conn.WriteTo(probe, peer)
        }
    }
}
```

### 为什么要 HMAC 认证探测包？

没有认证的话，攻击者可以注入假探测包劫持流量。HMAC 密钥通过 HKDF 从 ECDH 共享密钥派生，使用上下文 `"wormhole-punch-v1"`，所以只有完成密钥交换的两个对端才能生成有效探测。

---

## 8. P2P：端到端加密

UDP 路径建立后，所有数据都要加密。即使服务器看不到 P2P 流量，我们仍然需要 E2E 加密，因为：
- UDP 可以在共享网络上被嗅探
- 路径上的路由器可以检查数据包
- 纵深防御：不信任网络

### 密钥交换：X25519 ECDH

每个对端生成临时 X25519 密钥对：

```go
func GenerateKeyPair() (*KeyPair, error) {
    curve := ecdh.X25519()
    priv, _ := curve.GenerateKey(rand.Reader)
    return &KeyPair{
        Private: priv,
        Public:  priv.PublicKey().Bytes(),  // 32 字节
    }, nil
}
```

为什么选 X25519？
- **快速**：约 25,000 次密钥交换/秒
- **安全**：128 位安全强度，抗时序攻击
- **紧凑**：32 字节公钥
- **标准**：TLS 1.3、WireGuard、Signal 协议都在用

### 密钥派生：HKDF-SHA256

ECDH 共享密钥从不直接使用。HKDF 将其提取并扩展为特定用途的密钥：

```go
func DeriveSession(localPriv *ecdh.PrivateKey, remotePubBytes []byte) (*SessionCipher, error) {
    remotePub, _ := ecdh.X25519().NewPublicKey(remotePubBytes)
    sharedSecret, _ := localPriv.ECDH(remotePub)

    // 为不同目的派生独立密钥
    encKey, _ := deriveKey(sharedSecret, []byte("wormhole-p2p-v1"), 32)
    punchKey, _ := deriveKey(sharedSecret, []byte("wormhole-punch-v1"), 32)

    block, _ := aes.NewCipher(encKey)
    aead, _ := cipher.NewGCM(block)

    return &SessionCipher{aead: aead, punchKey: punchKey}, nil
}
```

**从一个 ECDH 派生两个密钥**：不同的 HKDF info 字符串确保密码学独立性。

### 加密：AES-256-GCM

每个包使用基于计数器的 nonce 加密：

```go
func (sc *SessionCipher) Encrypt(plaintext []byte) ([]byte, error) {
    counter := atomic.AddUint64(&sc.sendNonce, 1)
    nonce := buildNonce(sc.aead.NonceSize(), counter)
    ciphertext := sc.aead.Seal(nil, nonce, plaintext, nil)

    // 输出：[8字节计数器][密文 + 16字节 GCM 标签]
    out := make([]byte, 8+len(ciphertext))
    binary.BigEndian.PutUint64(out[:8], counter)
    copy(out[8:], ciphertext)
    return out, nil
}
```

**线上格式**：`[Counter 8B][AES-256-GCM 密文 + 16B 标签]`

总开销：每包 **24 字节**。

### 安全分析

| 威胁 | 缓解措施 |
|------|----------|
| 窃听 | AES-256-GCM（128 位安全强度） |
| 包篡改 | GCM 认证标签 |
| 探测注入 | HMAC-SHA256 认证探测 |
| 重放攻击 | 单调递增 nonce 计数器 |
| Nonce 重用 | 原子计数器保证唯一性 |
| 密钥交换 MITM | 信令通过已认证隧道 |

---

## 9. P2P：NAT 诊断与 FAQ

### NAT 类型如何检测

你不需要手动判断 NAT 类型——Wormhole 在客户端启动时**自动**完成检测。流程如下：

```
客户端以 --p2p=true 启动（默认开启）
  │
  ├─ 发送 STUN Binding Request → stun.l.google.com:19302  → 映射地址 A
  ├─ 发送 STUN Binding Request → stun1.l.google.com:19302 → 映射地址 B
  │   （两次均从同一个本地 UDP 端口发出）
  │
  └─ 比较 A 和 B：
       • A == B  → 锥形 NAT（可穿透 ✅）
       • A ≠ B   → 对称 NAT（受限 ⚠️）
       • A == 本地地址 → 无 NAT（公网 IP ✅）
```

客户端连接后会显示检测结果：

```
  🕳️  Wormhole is ready!

  Forwarding:   https://myapp.tunnel.example.com -> http://127.0.0.1:8080
  Version:      1.0.0
  NAT Type:     Port Restricted Cone
  Public Addr:  203.0.113.42:54321
  Traversable:  ✅ Yes (P2P direct connections possible)
  P2P Mode:     Relay

  Tip: Run 'wormhole nat-check' for detailed NAT diagnostics
```

### NAT 诊断命令

使用内置的 `nat-check` 命令获取详细 NAT 诊断：

```bash
wormhole nat-check
```

输出示例：

```
🔍 Diagnosing NAT type...

  NAT Discovery Results
  ─────────────────────────────────────
  NAT Type:      Port Restricted Cone
  Public IP:     203.0.113.42
  Public Port:   54321
  Local IP:      192.168.1.100
  Local Port:    12345
  Traversable:   ✅ Yes
  Discovery:     245ms
  ─────────────────────────────────────

  P2P Compatibility
  ─────────────────────────────────────
  ✅ Your NAT type supports P2P connections!

  You can establish direct P2P with peers
  behind any NAT type.
```

### NAT 兼容性矩阵

| 你的 NAT | 对端 NAT | 可以 P2P？ | 说明 |
|---|---|---|---|
| 公网 IP | 任意 | ✅ 必成功 | 无 NAT 需要穿越 |
| Full Cone | 任意 | ✅ 必成功 | 最宽松的 NAT 类型 |
| Restricted Cone | 任意 | ✅ 必成功 | 需要先从内部发出探测包 |
| Port Restricted | 任意锥形 / 公网 | ✅ | 最常见的家庭 NAT |
| Port Restricted | Symmetric | ✅ | 一端可预测 |
| Symmetric | 任意锥形 / 公网 | ✅ | 对端的锥形 NAT 允许通过 |
| Symmetric | Symmetric | ❌ | 两端均不可预测 |

**核心规则**：只有**双方都是 Symmetric NAT** 时，P2P 才会失败。

### 常见网络环境

| 环境 | 典型 NAT 类型 | 可能 P2P？ | 原因 |
|---|---|---|---|
| **家庭宽带** | Port Restricted Cone | ✅ 可以 | 消费级路由器使用锥形 NAT |
| **运营商级 NAT（CGNAT）** | Symmetric | ⚠️ 受限 | ISP 级 NAT 增加不可预测性 |
| **企业/校园网** | Symmetric | ⚠️ 受限 | 多层防火墙和 NAT |
| **移动 4G/5G** | Symmetric | ⚠️ 受限 | 运营商网络使用 CGNAT |
| **云服务器 / VPS** | 无 NAT（公网 IP） | ✅ 必成功 | 公网 IP，无 NAT 障碍 |
| **VPN** | 不定 | ❓ 视情况 | 取决于 VPN 出口节点 NAT |
| **酒店/机场 WiFi** | Symmetric | ⚠️ 受限 | 强制门户，限制性 NAT |

### 自动降级

如果 P2P 连接因任何原因失败，Wormhole **透明地回退**到服务器中继：

```
P2P 连接尝试
  │
  ├─ NAT 发现 ────────────── [启动时自动执行]
  │   └─ 失败？→ 中继模式（不尝试 P2P）
  │
  ├─ 对端发现 ────────────── [通过服务器信令]
  │   └─ 无对端？→ 中继模式
  │
  ├─ NAT 兼容性检查 ────────── [服务器检查双方 NAT 类型]
  │   └─ 双方 Symmetric？→ 中继模式
  │
  ├─ UDP 打洞 ────────────── [UDP 探测交换，10 秒超时]
  │   └─ 超时？→ 中继模式
  │
  └─ P2P 建立成功！────────── [E2E 加密 UDP 直连]
      └─ 连接断开？→ 自动回退到中继
```

用户无需干预——中继路径始终可用，P2P 是透明的优化。

### P2P 故障排查

**Q：P2P 一直失败，怎么办？**

1. 运行 `wormhole nat-check` 确认你的 NAT 类型
2. 如果看到 "Symmetric"，说明你的网络较为限制——P2P 需要对端有锥形 NAT 或公网 IP
3. 如果 STUN 发现本身失败，检查防火墙是否阻止了 UDP 19302 端口的出站流量

**Q：可以强制使用中继模式吗？**

可以，禁用 P2P：

```bash
wormhole client --server tunnel.example.com:7000 --local 8080 --p2p=false
```

**Q：P2P 可以跨不同运营商工作吗？**

可以，只要至少一端有锥形 NAT 或公网 IP。STUN 发现在任何允许出站 UDP 的网络上都可以工作。

**Q：中继模式比 P2P 慢吗？**

P2P 省去了服务器中转环节，延迟通常更低。对于同城但服务器在海外的场景，P2P 可减少 100ms+ 的 RTT。不过中继模式功能完全正常——差异主要在延迟而非吞吐。

---

## 10. 认证与安全

### 认证模式

Wormhole 支持多种认证模式：

- **简单 Token** —— 预共享 Token 列表
- **HMAC Token** —— 服务器持有密钥；Token 用 HMAC-SHA256 签名并嵌入声明（团队、角色、过期时间）
- **无认证** —— 用于开发/可信网络

### HMAC Token 结构

```go
type TokenClaims struct {
    TokenID   string    `json:"tid"`
    Team      string    `json:"team"`
    Role      Role      `json:"role"`      // admin, member, viewer
    IssuedAt  time.Time `json:"iat"`
    ExpiresAt time.Time `json:"exp"`
}
```

### 速率限制

防暴力破解：某 IP 在时间窗口内认证失败 N 次后被封禁：

```go
type RateLimiter struct {
    maxFailures int           // 默认：5
    window      time.Duration // 默认：1 分钟
    blockTime   time.Duration // 默认：5 分钟
}
```

### RBAC 权限

| 角色 | 权限 |
|------|------|
| Admin | 所有操作，包括 Token 管理 |
| Member | 创建隧道、查看自己的隧道 |
| Viewer | 仅查看，不能创建隧道 |

---

## 11. 与竞品对比

### 功能矩阵

| 功能 | ngrok | frp | cloudflared | bore | Wormhole |
|------|-------|-----|-------------|------|----------|
| HTTP 隧道 | ✅ | ✅ | ✅ | ❌ | ✅ |
| HTTPS / TLS 终结 | ✅ | ✅ | ✅ | ❌ | ✅（自动证书） |
| TCP 隧道 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 自定义域名 | ✅（付费） | ✅ | ✅ | ❌ | ✅ |
| 路径路由 | ❌ | ❌ | ✅ | ❌ | ✅ |
| HTTP 请求检查 | ✅ | ❌ | ❌ | ❌ | ✅ |
| P2P 直连 | ❌ | ✅（XTCP） | ❌ | ❌ | ✅ |
| E2E 加密（P2P） | N/A | ❌ | N/A | N/A | ✅ |
| 零配置客户端 | ✅ | ❌ | ❌ | ✅ | ✅ |
| HMAC Token + RBAC | ❌ | ❌ | N/A | ❌ | ✅ |
| 速率限制 | ✅ | ❌ | ✅ | ❌ | ✅ |
| 可自托管 | ❌ | ✅ | ❌ | ✅ | ✅ |

### 何时用什么

| 工具 | 最适合场景 |
|------|------------|
| **ngrok** | 快速演示、Webhook 测试、愿意为功能付费 |
| **frp** | 复杂多服务配置、需要 UDP、配置驱动工作流 |
| **cloudflared** | 已在 Cloudflare 生态、需要零信任访问 |
| **bore** | 最简单的 TCP 隧道、性能关键、极简代码库 |
| **Wormhole** | 零配置 + 全功能 + P2P + E2E 加密、自托管 |

### 成本对比

| 工具 | 自托管 | 云/SaaS |
|------|--------|---------|
| ngrok | N/A | 免费（受限）→ $8-25/月 |
| frp | ～$5/月 VPS | N/A |
| cloudflared | N/A | 免费（受限）→ $7/用户/月 |
| bore | ～$5/月 VPS | 免费（bore.pub） |
| Wormhole | ～$5/月 VPS | N/A |

---

## 12. 快速上手与部署

### 安装

```bash
# Go install
go install github.com/lucientong/wormhole@latest

# Homebrew
brew install lucientong/tap/wormhole

# Docker
docker pull lucientong/wormhole
```

### 服务器配置

```bash
# 基础服务器
wormhole server --domain tunnel.example.com

# 带认证（HMAC 签名 Token）
wormhole server --domain tunnel.example.com \
    --require-auth \
    --auth-secret "your-secret-key-at-least-16"

# 带 TLS（设置域名后自动 Let's Encrypt，无需手动指定证书）
wormhole server --domain tunnel.example.com --tls

# 带 TLS（手动证书）
wormhole server --domain tunnel.example.com \
    --tls --cert /path/to/cert.pem --key /path/to/key.pem
```

### 客户端使用

```bash
# 暴露本地 8080 端口
wormhole client --server tunnel.example.com:7000 --local 8080

# 快速模式（简写）
wormhole 8080

# 带认证
wormhole client --server tunnel.example.com:7000 \
    --local 8080 \
    --token "your-token"

# 请求特定子域名
wormhole client --server tunnel.example.com:7000 \
    --local 8080 \
    --subdomain myapp
```

### Docker Compose

```yaml
version: '3.8'
services:
  wormhole-server:
    image: lucientong/wormhole:latest
    command: server --domain tunnel.example.com
    ports:
      - "7070:7070"   # 隧道端口
      - "80:80"       # HTTP
      - "443:443"     # HTTPS
    volumes:
      - ./certs:/etc/wormhole/certs
```

---

## 13. 经验总结

### 协议设计

1. **先设计线上格式。** 帧协议是基础。正确的设计（固定头部、显式长度、有界载荷）避免了无数 bug。

2. **大力多路复用。** 一个连接，多个流。实现复杂度前置，但运维收益巨大。

3. **控制和数据在关注点上分离，传输上不分离。** 控制消息用 JSON 方便调试；数据帧用原始字节保证性能。两者流过同一连接。

### 网络与韧性

4. **退避不可省略。** 任何不带指数退避的重连客户端都会在故障期间 DDoS 服务器。

5. **始终提供中继回退。** 对称 NAT、企业防火墙、运营商级 NAT 都会击败打洞。中继路径必须始终可用；P2P 是优化。

6. **设计优雅降级。** P2P 任何阶段失败都应静默回退到中继。用户不应察觉。

### 性能与安全

7. **热路径上池化一切。** 头部缓冲区的 `sync.Pool` 看似微小，但在每秒数千帧时，能消除可测量的 GC 压力。

8. **GCM 用计数器 nonce > 随机 nonce。** 原子计数器更快，保证唯一性，简化代码。

9. **不同目的用不同密钥。** 用 HKDF 配合不同 info 字符串从一个共享密钥派生加密和 HMAC 密钥，简单且密码学安全。

10. **认证打洞包。** 没有 HMAC 的探测包，攻击者可以劫持 P2P 连接。

---

## 资源

- **源代码**：[github.com/lucientong/wormhole](https://github.com/lucientong/wormhole)
- **文档**：[docs/architecture.md](../architecture.md)
- **问题追踪**：[GitHub Issues](https://github.com/lucientong/wormhole/issues)

---

*Wormhole 采用 MIT 许可证。欢迎贡献。*
