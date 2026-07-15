// Package client implements the Wormhole client: it dials a Wormhole
// server, authenticates, registers one or more local services as tunnels,
// and proxies inbound traffic to them — optionally negotiating a direct
// P2P data path for `wormhole connect`.
//
// # Composition
//
// [Client] is a composition root, not the thing that does the work. It
// wires together two independent lifecycles and owns only the
// cross-cutting concerns neither should know about (aggregated [Stats],
// the traffic inspector, and the optional local HTTP control/inspector
// servers):
//
//   - [RelayClient] (implemented by relayClient) owns the control-plane
//     connection: dial, auth (with token-refresh retry), tunnel
//     registration, heartbeat, and reconnect-with-backoff. It also carries
//     the actual proxied bytes for ordinary tunnels — see Client.forwardToLocal.
//   - [P2PSession] (implemented by p2pSession) owns the `wormhole connect`
//     hole-punching lifecycle: sending/receiving P2P offers over the
//     relay's control channel ([RelayChannel]) and driving the encrypted
//     UDP data path once a direct connection is established.
//
// Client glues the two together in one direction only: relayClient's
// inbound P2P notifications are routed into p2pSession (via a
// setNotificationHandler-style callback wired up in relay_client.go), and
// p2pSession's outbound offers ride relayClient's control connection. Each
// side is unit-testable against a fake implementation of the other's
// narrow interface, without spinning up the whole [Client].
//
// # Configuration
//
// [Config] describes a single tunnel end-to-end (server address, local
// target, protocol, subdomain, auth token, TLS, P2P on/off). Multi-tunnel
// setups load a [FileConfig] from YAML (`--config`) via [LoadFileConfig];
// [Client] then internally manages multiple [TunnelDef]/[ActiveTunnel]
// entries under one control connection. SIGHUP-triggered hot-reload
// diffs the new file against the running tunnel set and calls
// [Client.ReloadTunnels], which adds/removes only what changed instead of
// tearing down the whole connection.
//
// [PersistentConfig] ([LoadPersistentConfig]/[UpdatePersistentConfig] in
// persist.go) separately remembers the last-used CLI flags in
// `~/.wormhole/config.yaml`, purely as a convenience default for the next
// invocation — it is not related to the multi-tunnel YAML config.
//
// # Control API
//
// When `--ctrl-port` is set, [Client] exposes a small local HTTP API
// (control.go) backing `wormhole tunnels list/create/delete`: list active
// tunnels, add one at runtime ([Client.CreateTunnel]), or remove one
// ([Client.DeleteTunnel]) — all without restarting the process.
//
// # Reconnection
//
// Losing the server connection does not fail the process: [Client.Start]
// delegates its long-running loop to relayClient.Run, which reconnects
// with backoff and, on an auth failure that looks like an expired token,
// transparently refreshes credentials (via `pkg/auth`) before retrying —
// see authenticateWithRefresh in relay_client.go.
package client
