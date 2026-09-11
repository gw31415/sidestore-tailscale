# Design

This document is for maintainers. It records internal behavior, constraints,
and design decisions. End-user setup belongs in the repository README.

## Operating model

SideStore is configured in **Remote Endpoint** mode with the reflector's
explicit Tailscale IPv4 address. The reflector address can be any stable IPv4
assigned to its tailnet node; it is not derived from an iPhone address.

One reflector can serve multiple iPhones. No client address is compiled into
the process and there is no per-device runtime configuration.

SideStore currently probes and connects to the remote endpoint on its device
service port, normally TCP 49152. Tailscale routes that connection to the
reflector. The response is delivered back through the same reflection path.

## Packet path

For an iPhone client port `P` connecting to its local service port `Q` through
the reflector:

```text
iPhone:P -> reflector:Q
    WireGuard decrypt
    tun.Device.Write
    swap IPv4 source and destination
    in-memory receive queue
    tun.Device.Read
    WireGuard encrypt
reflector:P -> iPhone:Q

iPhone:Q -> reflector:P
    reflect again
reflector:Q -> iPhone:P
```

Only the IPv4 source and destination fields change. Ports, transport headers,
and payloads remain untouched. Exchanging the two IPv4 address words preserves
the IPv4 header checksum and the TCP/UDP pseudo-header sum.

Malformed IPv4 and non-IPv4 packets are dropped. Valid packets are trimmed to
the IPv4 total-length field before they are queued.

## SideStore connection mode

The supported setup uses SideStore's Remote Endpoint mode rather than Local
VPN auto-discovery.

At the minimuxer revision inspected during development, Local VPN discovery
only selected `utun` interfaces that had IPv4 addresses and no IPv6 addresses.
Tailscale creates a dual-stack `utun`, so it was excluded and SideStore showed
`Tunnel IP: N/A` and `Device IP: N/A`. An explicit remote endpoint bypasses
that interface-selection path while the destination is still routed through
Tailscale.

This distinction also removes the former `iPhone IPv4 + 1` requirement. That
address derivation belongs to the Local VPN discovery path, not to an explicit
Remote Endpoint address.

## Embedded Tailscale node

The process embeds `tsnet.Server` and supplies a custom in-memory `tun.Device`.
The WireGuard engine calls `Write` for decrypted tailnet packets and polls
`Read` for packets to encrypt and send. This keeps packet handling inside one
process and does not require a kernel TUN device.

The node is persistent, not ephemeral. Its control-plane identity and keys are
stored in the tsnet state directory.

## Enrollment

The command has no arguments and supports interactive enrollment only.
`TS_AUTHKEY` and its `TS_AUTH_KEY` alias are cleared before tsnet starts because
tsnet otherwise reads them implicitly. A first start therefore emits a browser
login URL.

This does not remove Tailscale node authentication: every node must enroll in a
tailnet before it receives an identity, keys, policy, and addresses. It only
removes auth-key provisioning from this application.

## State directory

The state location is selected without application configuration:

1. Use `STATE_DIRECTORY` when systemd supplies it for `StateDirectory=`.
2. On Windows, use `%USERPROFILE%\AppData\Local\sidestore-reflector`.
3. Otherwise, use `~/.local/state/sidestore-reflector`.

The included unit uses a dynamic user and
`StateDirectory=sidestore-reflector`, which resolves to
`/var/lib/sidestore-reflector` on a standard systemd installation.

Do not move or delete the state directory during upgrades. Losing it requires
enrolling a new Tailscale node.

## Process interface

The executable deliberately has no command-line or application configuration
surface. Any command-line argument is rejected. The hostname is fixed as
`sidestore-reflector`, and backend diagnostic logging is disabled. User-facing
tsnet messages and lifecycle events go to the standard Go logger.

Shutdown is driven by SIGINT or SIGTERM. The custom TUN closes before the
tsnet server so blocked reads are released before engine teardown. Final
reflected and dropped counters are logged during shutdown.

## Queueing and ownership

The TUN uses a bounded channel of 256 packets between `Write` and `Read`.
Packets are copied on write because the caller retains ownership of its input
buffers. Batch size is one.

The queue is intentionally left open during shutdown. Readers and writers
select on a separate `done` channel so concurrent close and send operations
cannot panic.

## Security boundary

Reflection is address-agnostic: every well-formed IPv4 packet delivered to the
node is reflected. Tailnet policy is the authorization boundary. Deployments
must use Tailscale ACLs or grants to limit which peers can reach the node when
the tailnet includes untrusted devices.

Packet payloads are not logged. Counters contain no peer identities or packet
contents.

## Repository layout

```text
cmd/sidestore-reflector/  process lifecycle and tsnet wiring
internal/reflecttun/      custom TUN device and IPv4 transformation
dist/                     systemd unit
docs/                     maintainer documentation
```

## Verification

Run the implementation checks with:

```sh
go test ./...
go test -race ./...
go vet ./...
```

The packet tests cover address swapping, checksum invariance, offsets,
malformed packets, queue behavior, and shutdown unblocking. An end-to-end
deployment check should also connect through the reflector from a separate
tailnet peer to a service on that same peer.
