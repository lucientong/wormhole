# Wormhole: Building a Modern Tunnel Tool from Scratch

> A comprehensive deep dive into [Wormhole](https://github.com/lucientong/wormhole) — a zero-config, self-hosted tunnel tool in Go featuring binary frame protocol, stream multiplexing, P2P hole punching, end-to-end encryption, and how it compares to ngrok, frp, and other alternatives.

## Table of Contents

1. [Why Build Your Own Tunnel?](#1-why-build-your-own-tunnel)
2. [Architecture Overview](#2-architecture-overview)
3. [Core: Binary Frame Protocol](#3-core-binary-frame-protocol)
4. [Core: Stream Multiplexing](#4-core-stream-multiplexing)
5. [Control Protocol & HTTP Routing](#5-control-protocol--http-routing)
6. [P2P: NAT Discovery with STUN](#6-p2p-nat-discovery-with-stun)
7. [P2P: UDP Hole Punching](#7-p2p-udp-hole-punching)
8. [P2P: End-to-End Encryption](#8-p2p-end-to-end-encryption)
9. [P2P: NAT Diagnostics & FAQ](#9-p2p-nat-diagnostics--faq)
10. [Authentication & Security](#10-authentication--security)
11. [Comparison with Alternatives](#11-comparison-with-alternatives)
12. [Quick Start & Deployment](#12-quick-start--deployment)
13. [Lessons Learned](#13-lessons-learned)


---

## 1. Why Build Your Own Tunnel?

Existing tunnel solutions like ngrok, frp, and Cloudflare Tunnel work great — until they don't:

- **ngrok free tier** restricts you to one endpoint, randomized subdomains, and rate-limited connections. Paid plans start at $8/month.
- **Cloudflare Tunnel** requires routing traffic through Cloudflare's network and tying your infrastructure to their ecosystem.
- **frp** is powerful but config-heavy — every service needs explicit TOML configuration on both client and server.
- **Vendor lock-in**: If the service changes pricing or deprecates features, your workflow breaks.

Wormhole was born from a desire for a **zero-config, self-hosted** tunnel that you fully control, with modern features like P2P direct connections and end-to-end encryption.

---

## 2. Architecture Overview

Wormhole follows a client-server model with optional P2P direct connections:

```
                    ┌─────────────────────────────────┐
                    │         Wormhole Server          │
 Internet ────────▶ │  ┌─────────┐  ┌──────────────┐  │
  (HTTP/TCP)        │  │  Router  │  │ Tunnel Mux   │  │
                    │  │ (host →  │──│ (streams over │──│────▶ Client A
                    │  │  client) │  │  single conn) │  │
                    │  └─────────┘  └──────────────┘  │
                    │                                  │────▶ Client B
                    └─────────────────────────────────┘
                                         │
                                    (optional)
                                         │
                    Client A ◀── P2P UDP Hole Punch ──▶ Client B
                                 (E2E Encrypted)
```

The system has five main layers:

| Layer | Purpose |
|-------|---------|
| **Frame Protocol** | Custom binary wire format for all data exchange |
| **Stream Multiplexer** | Multiple logical streams over a single TCP connection |
| **Control Protocol** | JSON-based messages for handshake, registration, signaling |
| **HTTP Router** | Maps incoming requests to correct client tunnel |
| **P2P Subsystem** | STUN discovery, hole punching, encrypted direct connections |

---

## 3. Core: Binary Frame Protocol

Every byte on the wire is structured as a **frame**. The format is intentionally simple — a fixed 10-byte header followed by a variable-length payload:

```
+----------+----------+------------+----------+------------------+
| Version  |   Type   |  StreamID  |  Length  |     Payload      |
|  1 byte  |  1 byte  |  4 bytes   |  4 bytes |    N bytes       |
+----------+----------+------------+----------+------------------+
```

### Why This Design?

- **Fixed header size** (10 bytes): The decoder always knows exactly how many bytes to read first, simplifying the state machine.
- **Version byte**: Future-proofs the protocol. Currently always `1`.
- **StreamID**: Identifies which logical stream a frame belongs to. StreamID `0` is reserved for connection-level frames.
- **Length field before payload**: Read 10 bytes, extract length, read exactly that many more. No delimiters, no escaping.

### Frame Types

Seven frame types handle all communication:

```go
const (
    FrameData         FrameType = 0x01  // Stream data
    FrameWindowUpdate FrameType = 0x02  // Flow control
    FramePing         FrameType = 0x03  // Keep-alive request
    FramePong         FrameType = 0x04  // Keep-alive response
    FrameClose        FrameType = 0x05  // Stream closure
    FrameHandshake    FrameType = 0x06  // New stream creation
    FrameError        FrameType = 0x07  // Error signaling
)
```

This is inspired by HTTP/2's frame design but stripped down to essentials — tunnel data is opaque bytes, so we don't need HEADERS, SETTINGS, or PUSH_PROMISE.

### The Codec

The `FrameCodec` uses `sync.Pool` for header buffers to minimize GC pressure in hot paths:

```go
type FrameCodec struct {
    maxPayloadSize uint32
    bufferPool     *sync.Pool
}

func (c *FrameCodec) Encode(w io.Writer, f *Frame) error {
    // Get header buffer from pool
    bufPtr := c.bufferPool.Get().(*[]byte)
    header := *bufPtr
    defer c.bufferPool.Put(bufPtr)

    // Encode: [Version][Type][StreamID][Length]
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

**Safety bounds**: Maximum payload is capped at **16 MB** (`MaxFramePayloadSize`), while the default is **32 KB**. This prevents malicious peers from forcing unbounded memory allocation.

---

## 4. Core: Stream Multiplexing

A single TCP connection between client and server carries multiple logical **streams** — each representing an independent proxied request.

### Why Multiplex?

Creating a new TCP connection per request means:
- TCP handshake latency on every request
- TLS renegotiation overhead
- Connection limit pressure on both ends
- No way to maintain a persistent control channel

Instead, Wormhole creates **one** TCP connection and multiplexes many streams over it, just like HTTP/2.

### Stream ID Allocation

Client and server use **odd/even stream IDs** to avoid collisions:

```go
if isClient {
    m.nextStreamID = 1  // 1, 3, 5, 7, ...
} else {
    m.nextStreamID = 2  // 2, 4, 6, 8, ...
}
```

### Mux Architecture

The `Mux` struct runs three background goroutines:

```go
type Mux struct {
    conn    net.Conn           // Underlying TCP connection
    codec   *FrameCodec        // Frame encoder/decoder
    streams map[uint32]*Stream // Active streams by ID
    sendCh  chan *Frame        // Outgoing frame queue
}

func newMux(conn net.Conn, config MuxConfig, isClient bool) (*Mux, error) {
    m := &Mux{...}
    go m.recvLoop()      // Read frames → dispatch to streams
    go m.sendLoop()      // Drain sendCh → write to wire
    go m.keepAliveLoop() // Periodic ping/pong
    return m, nil
}
```

**Why a dedicated send goroutine?** Multiple streams write concurrently. Instead of fighting over a mutex for the `net.Conn`, all frames are enqueued into `sendCh`, and a single goroutine serializes writes.

### Flow Control

Each stream has a **send window** and **receive window**, similar to TCP's sliding window:

```go
type StreamConfig struct {
    WindowSize     uint32  // Initial: 256KB
    MaxWindowSize  uint32  // Maximum: 16MB
    ReadBufferSize int     // Read buffer: 64KB
}
```

When a stream's read buffer is consumed, it sends `FrameWindowUpdate` to tell the sender it can send more data.

### Keep-Alive

The multiplexer sends periodic `FramePing` (every 30s by default) and expects `FramePong` within a timeout (10s). If no pong arrives, the connection is torn down.

---

## 5. Control Protocol & HTTP Routing

### Control Messages

Wormhole uses a **JSON-based control protocol** for structured messages. Control messages flow over regular multiplexed streams:

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

**Why JSON?** Control messages are infrequent and small. JSON's self-describing nature simplifies debugging. The hot path — actual data transfer — uses the binary frame protocol.

### Connection Handshake

```
Client                                    Server
  │                                          │
  │──── TCP Connect ────────────────────────▶│
  │                                          │
  │──── [Stream 1] AuthRequest ────────────▶ │
  │◀─── [Stream 1] AuthResponse ─────────── │
  │                                          │
  │──── [Stream 3] RegisterRequest ────────▶ │
  │◀─── [Stream 3] RegisterResponse ──────── │
  │           {tunnel_id, public_url}        │
```

### HTTP Routing

The `Router` supports three routing strategies, checked in priority order:

1. **Custom hostname** — Full hostname match (e.g., `api.mycompany.com`)
2. **Subdomain** — Subdomain extraction (e.g., `myapp.tunnel.example.com`)
3. **Path prefix** — Longest prefix match (e.g., `/myapp/`)

```go
func (r *Router) Route(host, path string) *ClientSession {
    // 1. Custom hostname match
    if client, ok := r.hostnames[host]; ok {
        return client
    }
    // 2. Subdomain match
    if subdomain := r.extractSubdomain(host); subdomain != "" {
        if client, ok := r.subdomains[subdomain]; ok {
            return client
        }
    }
    // 3. Path prefix match
    return r.matchPath(path)
}
```

---

## 6. P2P: NAT Discovery with STUN

Most computers sit behind NATs. When two peers both behind NATs want to talk directly, neither can reach the other — the NAT drops unsolicited packets.

The relay solution adds latency (two extra hops). If both peers are in the same city but the relay is across an ocean, you pay a heavy RTT penalty.

### STUN Protocol

STUN (RFC 5389) is simple: send a UDP packet to a STUN server, and it tells you what IP:port it saw — your **mapped address**.

By querying two different STUN servers from the **same local port**, you can classify the NAT:

| Scenario | NAT Type | P2P Possible? |
|---|---|---|
| Mapped address == local address | No NAT (public IP) | ✅ |
| Same mapped address from both servers | Cone NAT | ✅ |
| Different mapped addresses | Symmetric NAT | ❌ (mostly) |

### Implementation

Wormhole implements a pure-Go STUN client — no external dependencies:

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
        return NATPortRestricted  // Conservative estimate
    }
    return NATSymmetric
}
```

---

## 7. P2P: UDP Hole Punching

### How It Works

NATs maintain a mapping table. When your machine sends UDP to `dest:port`, the NAT creates an entry allowing responses from that destination.

The trick: if Peer A sends to Peer B's public address **and** Peer B simultaneously sends to Peer A's public address, both NATs create entries. One packet arrives after the other's NAT entry is created — and gets through!

### Wormhole Punch Protocol (WHPP)

Probe packets have a simple structure:

```
┌──────────────┬───────────┬────────────────────────┐
│  Magic (4B)  │ Payload   │  HMAC-SHA256 Tag (32B) │
│  "WHPP"      │ "probe"   │  (authenticated)       │
└──────────────┴───────────┴────────────────────────┘
```

The 4-byte magic `"WHPP"` (WormHole Punch Protocol) prevents false positives from random UDP traffic. The HMAC tag authenticates the sender using a key derived from the ECDH shared secret.

```go
func (h *HolePuncher) sendProbes(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) {
    baseProbe := append(punchMagic, []byte("probe")...)
    
    // Append HMAC tag for authentication
    probe := baseProbe
    if h.cipher != nil {
        tag := h.cipher.SignProbe(baseProbe)
        probe = append(baseProbe, tag...)
    }

    // Send first probe immediately, then at 100ms intervals
    conn.WriteTo(probe, peer)
    
    ticker := time.NewTicker(100 * time.Millisecond)
    for i := 1; i < 30; i++ {  // 30 attempts
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            conn.WriteTo(probe, peer)
        }
    }
}
```

### Why HMAC-Authenticated Probes?

Without authentication, an attacker could inject fake probes and redirect traffic. The HMAC key is derived from the ECDH shared secret via HKDF with context `"wormhole-punch-v1"`, so only the two peers who completed key exchange can produce valid probes.

---

## 8. P2P: End-to-End Encryption

Once the UDP path is established, all data is encrypted. Even though the server can't see P2P traffic, we want E2E encryption because:
- UDP can be sniffed on shared networks
- Routers along the path could inspect packets
- Defense in depth: don't trust the network

### Key Exchange: X25519 ECDH

Each peer generates an ephemeral X25519 key pair:

```go
func GenerateKeyPair() (*KeyPair, error) {
    curve := ecdh.X25519()
    priv, _ := curve.GenerateKey(rand.Reader)
    return &KeyPair{
        Private: priv,
        Public:  priv.PublicKey().Bytes(),  // 32 bytes
    }, nil
}
```

Why X25519?
- **Fast**: ~25,000 key exchanges/sec
- **Secure**: 128-bit security, resistant to timing attacks
- **Compact**: 32-byte public keys
- **Standard**: Used by TLS 1.3, WireGuard, Signal Protocol

### Key Derivation: HKDF-SHA256

The ECDH shared secret is never used directly. HKDF extracts and expands it into purpose-specific keys:

```go
func DeriveSession(localPriv *ecdh.PrivateKey, remotePubBytes []byte) (*SessionCipher, error) {
    remotePub, _ := ecdh.X25519().NewPublicKey(remotePubBytes)
    sharedSecret, _ := localPriv.ECDH(remotePub)

    // Derive separate keys for different purposes
    encKey, _ := deriveKey(sharedSecret, []byte("wormhole-p2p-v1"), 32)
    punchKey, _ := deriveKey(sharedSecret, []byte("wormhole-punch-v1"), 32)

    block, _ := aes.NewCipher(encKey)
    aead, _ := cipher.NewGCM(block)

    return &SessionCipher{aead: aead, punchKey: punchKey}, nil
}
```

**Two keys from one ECDH**: Different HKDF info strings ensure cryptographic independence.

### Encryption: AES-256-GCM

Each packet is encrypted with counter-based nonces:

```go
func (sc *SessionCipher) Encrypt(plaintext []byte) ([]byte, error) {
    counter := atomic.AddUint64(&sc.sendNonce, 1)
    nonce := buildNonce(sc.aead.NonceSize(), counter)
    ciphertext := sc.aead.Seal(nil, nonce, plaintext, nil)

    // Output: [8-byte counter][ciphertext + 16-byte GCM tag]
    out := make([]byte, 8+len(ciphertext))
    binary.BigEndian.PutUint64(out[:8], counter)
    copy(out[8:], ciphertext)
    return out, nil
}
```

**Wire format**: `[Counter 8B][AES-256-GCM ciphertext + 16B tag]`

Total overhead: **24 bytes** per packet.

### Security Analysis

| Threat | Mitigation |
|---|---|
| Eavesdropping | AES-256-GCM (128-bit security) |
| Packet tampering | GCM authentication tag |
| Probe injection | HMAC-SHA256 authenticated probes |
| Replay attack | Monotonic nonce counter |
| Nonce reuse | Atomic counter guarantees uniqueness |
| MITM during key exchange | Signaling over authenticated tunnel |

---

## 9. P2P: NAT Diagnostics & FAQ

### How NAT Type is Detected

You don't need to manually determine your NAT type — Wormhole does it **automatically** at client startup. Here's the process:

```
Client starts with --p2p=true (default)
  │
  ├─ Send STUN Binding Request → stun.l.google.com:19302  → Mapped Address A
  ├─ Send STUN Binding Request → stun1.l.google.com:19302 → Mapped Address B
  │   (both from the SAME local UDP port)
  │
  └─ Compare A and B:
       • A == B  → Cone NAT (traversable ✅)
       • A ≠ B   → Symmetric NAT (limited ⚠️)
       • A == local addr → No NAT (public IP ✅)
```

The result is displayed when the client connects:

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

### NAT Check Diagnostic Command

For detailed NAT diagnostics, use the built-in `nat-check` command:

```bash
wormhole nat-check
```

This outputs:

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

### NAT Compatibility Matrix

| Your NAT | Peer NAT | P2P Possible? | Notes |
|---|---|---|---|
| Public IP | Any | ✅ Always | No NAT to traverse |
| Full Cone | Any | ✅ Always | Most permissive NAT |
| Restricted Cone | Any | ✅ Always | Requires initial outbound packet |
| Port Restricted | Any Cone / Public | ✅ | Most common home NAT |
| Port Restricted | Symmetric | ✅ | One side is predictable |
| Symmetric | Any Cone / Public | ✅ | Peer's Cone NAT allows it |
| Symmetric | Symmetric | ❌ | Both sides unpredictable |

**Key rule**: P2P fails **only** when **both** peers are behind Symmetric NAT.

### Common Network Environments

| Environment | Typical NAT Type | P2P Likely? | Why |
|---|---|---|---|
| **Home broadband** | Port Restricted Cone | ✅ Yes | Consumer routers use Cone NAT |
| **Carrier-grade NAT (CGNAT)** | Symmetric | ⚠️ Limited | ISP-level NAT adds unpredictability |
| **Corporate/campus network** | Symmetric | ⚠️ Limited | Multi-layer firewalls and NAT |
| **Mobile 4G/5G** | Symmetric | ⚠️ Limited | Carrier networks use CGNAT |
| **Cloud VPS / Server** | None (Public IP) | ✅ Always | Public IP, no NAT barrier |
| **VPN** | Varies | ❓ Depends | Depends on VPN exit node NAT |
| **Hotel / Airport WiFi** | Symmetric | ⚠️ Limited | Captive portals, restrictive NAT |

### Automatic Fallback

If P2P connection fails for any reason, Wormhole **transparently falls back** to server relay:

```
P2P Connection Attempt
  │
  ├─ NAT Discovery ────────────── [automatic at startup]
  │   └─ Failed? → Relay mode (no P2P attempted)
  │
  ├─ Peer Discovery ───────────── [via server signaling]
  │   └─ No peer? → Relay mode
  │
  ├─ NAT Compatibility Check ──── [server checks both NAT types]
  │   └─ Both Symmetric? → Relay mode
  │
  ├─ Hole Punching ────────────── [UDP probe exchange, 10s timeout]
  │   └─ Timeout? → Relay mode
  │
  └─ P2P Established! ─────────── [E2E encrypted UDP direct path]
      └─ Connection lost? → Auto-fallback to relay
```

Users never need to intervene — the relay path always works, and P2P is a transparent optimization.

### Troubleshooting P2P

**Q: P2P keeps failing, what can I do?**

1. Run `wormhole nat-check` to confirm your NAT type
2. If you see "Symmetric", your network is restrictive — P2P requires the other peer to have a Cone NAT or public IP
3. If STUN discovery itself fails, check if your firewall blocks outbound UDP on port 19302

**Q: Can I force relay mode?**

Yes, disable P2P entirely:

```bash
wormhole client --server tunnel.example.com:7070 --local 8080 --p2p=false
```

**Q: Does P2P work across different ISPs?**

Yes, as long as at least one peer has a Cone NAT or public IP. The STUN discovery works across any network that allows outbound UDP.

**Q: Is relay mode slower than P2P?**

P2P eliminates the server hop, so latency is typically lower. For peers in the same city but with a server overseas, P2P can reduce RTT by 100ms+. However, relay mode is fully functional — the difference is mainly latency, not throughput.

---

## 10. Authentication & Security

### Authentication Modes

Wormhole supports multiple authentication modes:

- **Simple tokens** — Pre-shared token list
- **HMAC tokens** — Server holds secret; tokens are HMAC-SHA256 signed with embedded claims (team, role, expiry)
- **No auth** — For development/trusted networks

### HMAC Token Structure

```go
type TokenClaims struct {
    TokenID   string    `json:"tid"`
    Team      string    `json:"team"`
    Role      Role      `json:"role"`      // admin, member, viewer
    IssuedAt  time.Time `json:"iat"`
    ExpiresAt time.Time `json:"exp"`
}
```

### Rate Limiting

Protection against brute-force: after N failed auth attempts from an IP within a time window, that IP is blocked:

```go
type RateLimiter struct {
    maxFailures int           // Default: 5
    window      time.Duration // Default: 1 minute
    blockTime   time.Duration // Default: 5 minutes
}
```

### RBAC Permissions

| Role | Permissions |
|------|-------------|
| Admin | All operations including token management |
| Member | Create tunnels, view own tunnels |
| Viewer | View only, no tunnel creation |

---

## 11. Comparison with Alternatives

### Feature Matrix

| Feature | ngrok | frp | cloudflared | bore | Wormhole |
|---|---|---|---|---|---|
| HTTP tunneling | ✅ | ✅ | ✅ | ❌ | ✅ |
| HTTPS / TLS termination | ✅ | ✅ | ✅ | ❌ | ✅ (auto-cert) |
| TCP tunneling | ✅ | ✅ | ✅ | ✅ | ✅ |
| Custom domains | ✅ (paid) | ✅ | ✅ | ❌ | ✅ |
| Path-based routing | ❌ | ❌ | ✅ | ❌ | ✅ |
| HTTP request inspection | ✅ | ❌ | ❌ | ❌ | ✅ |
| P2P direct connection | ❌ | ✅ (XTCP) | ❌ | ❌ | ✅ |
| E2E encryption (P2P) | N/A | ❌ | N/A | N/A | ✅ |
| Zero-config client | ✅ | ❌ | ❌ | ✅ | ✅ |
| HMAC tokens + RBAC | ❌ | ❌ | N/A | ❌ | ✅ |
| Rate limiting | ✅ | ❌ | ✅ | ❌ | ✅ |
| Self-hostable | ❌ | ✅ | ❌ | ✅ | ✅ |

### When to Use What

| Tool | Best For |
|------|----------|
| **ngrok** | Quick demos, webhook testing, willing to pay for features |
| **frp** | Complex multi-service setups, need UDP, config-driven workflows |
| **cloudflared** | Already in Cloudflare ecosystem, need zero-trust access |
| **bore** | Simplest TCP tunnel, performance-critical, minimal codebase |
| **Wormhole** | Zero-config + full features + P2P + E2E encryption, self-hosted |

### Cost Comparison

| Tool | Self-hosted | Cloud/SaaS |
|---|---|---|
| ngrok | N/A | Free (limited) → $8-25/mo |
| frp | ~$5/mo VPS | N/A |
| cloudflared | N/A | Free (limited) → $7/user/mo |
| bore | ~$5/mo VPS | Free (bore.pub) |
| Wormhole | ~$5/mo VPS | N/A |

---

## 12. Quick Start & Deployment

### Installation

```bash
# Go install
go install github.com/lucientong/wormhole@latest

# Homebrew
brew install lucientong/tap/wormhole

# Docker
docker pull lucientong/wormhole
```

### Server Setup

```bash
# Basic server
wormhole server --domain tunnel.example.com

# With authentication (HMAC signed tokens)
wormhole server --domain tunnel.example.com \
    --require-auth \
    --auth-secret "your-secret-key-at-least-16"

# With TLS (auto Let's Encrypt when domain is set and no cert/key provided)
wormhole server --domain tunnel.example.com --tls

# With TLS (manual certificates)
wormhole server --domain tunnel.example.com \
    --tls --cert /path/to/cert.pem --key /path/to/key.pem
```

### Client Usage

```bash
# Expose local port 8080
wormhole client --server tunnel.example.com:7000 --local 8080

# Quick mode (shorthand)
wormhole 8080

# With authentication
wormhole client --server tunnel.example.com:7000 \
    --local 8080 \
    --token "your-token"

# Request specific subdomain
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
      - "7070:7070"   # Tunnel port
      - "80:80"       # HTTP
      - "443:443"     # HTTPS
    volumes:
      - ./certs:/etc/wormhole/certs
```

---

## 13. Lessons Learned
### Protocol Design

1. **Design the wire format first.** The frame protocol is the foundation. Getting it right (fixed header, explicit length, bounded payload) saved countless bugs.

2. **Multiplex aggressively.** One connection, many streams. Implementation complexity is front-loaded, but operational benefits are enormous.

3. **Keep control and data separate in concern, not transport.** Control messages use JSON for debuggability; data frames use raw bytes for performance. Both flow over the same connection.

### Network & Resilience

4. **Backoff is not optional.** Any reconnecting client without exponential backoff will DDoS the server during outages.

5. **Always provide a relay fallback.** Symmetric NATs, corporate firewalls, and carrier-grade NATs defeat hole punching. The relay path must always work; P2P is an optimization.

6. **Design for graceful degradation.** P2P failure at any stage should silently fall back to relay. The user should never notice.

### Performance & Security

7. **Pool everything in hot paths.** `sync.Pool` for header buffers seems minor, but at thousands of frames per second, it eliminates measurable GC pressure.

8. **Counter nonces > random nonces for GCM.** Atomic counters are faster, guarantee uniqueness, and simplify code.

9. **Separate keys for separate purposes.** Using HKDF with different info strings to derive encryption and HMAC keys from one shared secret is simple and cryptographically sound.

10. **Authenticate the punch.** Without HMAC on probe packets, attackers could hijack P2P connections.

---

## Resources

- **Source Code**: [github.com/lucientong/wormhole](https://github.com/lucientong/wormhole)
- **Documentation**: [docs/architecture.md](../architecture.md)
- **Issue Tracker**: [GitHub Issues](https://github.com/lucientong/wormhole/issues)

---

*Wormhole is MIT licensed. Contributions welcome.*
