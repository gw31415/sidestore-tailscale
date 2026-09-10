# sidestore-reflector

A single Go binary that lets [SideStore](https://sidestore.io) 0.6.3+ talk to
its minimuxer peer over Tailscale **without ever tearing down the iPhone's
Tailscale VPN interface**.

SideStore derives the minimuxer peer address as `device IP + 1`. This program
joins your tailnet as an embedded [tsnet](https://pkg.go.dev/tailscale.com/tsnet)
node whose Tailscale IPv4 is exactly that address, and reflects every packet
from the iPhone back with the IPv4 source and destination swapped:

```
SideStore/client :P                     SideStore/client :P
        │                                       ▲
        │ DEVICE:P → NODE:Q                     │ NODE:Q → DEVICE:P
        ▼                                       │
   Tailscale VPN ──► sidestore-reflector ──► Tailscale VPN
                        (swap IPv4 src/dst)
        ┌──────────► iPhone local service :Q ◄──────────┐
        │            DEVICE:Q → NODE:P (replied)        │
        └────────────────── reflector again ────────────┘
```

Ports and payloads are never modified, so transport checksums stay valid.

## What it replaces

Compared to Docker-based SideStore/Tailscale setups, this binary needs:

- ❌ no Docker
- ❌ no external `tailscaled`
- ❌ no `/dev/net/tun`, no `NET_ADMIN`, no root, no `CAP_NET_ADMIN`
- ❌ no `iptables` / `nftables`, no network namespaces
- ✅ a normal user, a persistent state directory, and tailnet connectivity

## Requirements

- Go ≥ 1.26 (tailscale.com v1.102.3 requires 1.26+)
- A tailnet with a **pre-approved reserved IP** for the reflector (see below)
- ACLs allowing the iPhone ↔ reflector in **both** directions, e.g.

```jsonc
{
  "grants": [
    { "src": ["100.101.102.103/32"], "dst": ["100.101.102.104/32"], "ip": ["*"] },
    { "src": ["100.101.102.104/32"], "dst": ["100.101.102.103/32"], "ip": ["*"] }
  ]
}
```

(In production, use autogroup/user/tag selectors instead of raw IPs.)

## Build

```sh
go build ./cmd/sidestore-reflector
```

Release / static build (verifiable with `file` and `ldd`):

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o sidestore-reflector ./cmd/sidestore-reflector
file sidestore-reflector   # -> statically linked
ldd  sidestore-reflector   # -> not a dynamic executable
```

## Usage

```
sidestore-reflector --device-ip IP

  --device-ip IP    iPhone's Tailscale IPv4 (required)
  --hostname NAME   Tailscale node name (default sidestore-reflector)
  --state-dir DIR   tsnet state directory (default ~/.local/state/sidestore-reflector)
  --verbose         enable diagnostic logging and periodic stats
```

The only environment variable is `TS_AUTHKEY` (there is deliberately no
`--auth-key` flag so the secret never shows up in the process list).

`nodeIP` is always computed as `deviceIP + 1`; both addresses must be inside
Tailscale's CGNAT range `100.64.0.0/10`.

### First run (enrollment)

```sh
TS_AUTHKEY=tskey-auth-... ./sidestore-reflector --device-ip 100.101.102.103
```

Without a key, the binary prints a login URL instead. Once the machine has
joined the tailnet:

1. Open the **Tailscale Admin Console → Machines**, find `sidestore-reflector`
   and **edit its IPv4 address** to `device IP + 1`
   (e.g. `100.101.102.103` → set `100.101.102.104`).
2. Restart `sidestore-reflector`.

The reflector **refuses to forward packets** unless its assigned Tailscale IPv4
equals `device IP + 1`, and exits with an explanation otherwise.

If `device IP + 1` is already taken by another node, do not pick a different
address — SideStore always dials `+1`. Instead move the iPhone to another free
address whose `+1` is also free, and point the reflector at the new `+1`.

State persists in `--state-dir`, so `TS_AUTHKEY` is only needed on the first
run. Don't keep the auth key in any persistent config.

### Running as a service

After enrollment and the IP fix, install as a normal unprivileged service
(see `dist/sidestore-reflector.service`):

```sh
install -m755 sidestore-reflector /usr/local/bin/
install -m644 dist/sidestore-reflector.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sidestore-reflector
journalctl -u sidestore-reflector -f
```

It runs with `DynamicUser=yes` — no root, no capabilities, no device nodes.

## Security

Only packets matching **both** `src == iPhone` and `dst == reflector` are
reflected. IPv6, malformed IPv4, wrong sources (other tailnet peers), and
wrong destinations are silently dropped and counted. On shutdown (and every
10 s with `--verbose`) the binary logs `reflected=N dropped=M`.

## Verification on the iPhone

With Wi-Fi on, Tailscale on, and LocalDevVPN off, check SideStore →
Settings → Health Check:

| Field | Expected |
|---|---|
| Tunnel Interface IP | `--device-ip` |
| Tunnel Peer IP | reflector node IP |
| Device Reachability | healthy |
| Pairing | connected |

Then run Refresh All. SideStore's RSD/lockdownd services require the device to
be Wi-Fi associated; cellular-only is not supported.

## Development

```sh
go test ./...        # packet reflection, checksums, offsets, shutdown
go vet ./...
```

Layout:

```
cmd/sidestore-reflector/   CLI + tsnet wiring + IP validation
internal/reflecttun/       in-memory tun.Device + IPv4 reflection
dist/                      systemd unit
```
