# sidestore-reflector

`sidestore-reflector` provides a Tailscale endpoint that SideStore can use to
reach the iPhone's local device services. It runs as one unprivileged process.

## Requirements

- A Linux server connected to the internet
- A Tailscale tailnet
- An iPhone with Wi-Fi and Tailscale connected
- A SideStore build with **Settings → Connection Config**
- Go 1.26 or newer to build the binary

## Install

Build a static binary:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o sidestore-reflector ./cmd/sidestore-reflector
```

Install and start the included systemd service:

```sh
sudo install -m755 sidestore-reflector /usr/local/bin/
sudo install -m644 dist/sidestore-reflector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sidestore-reflector
```

## Register the server

Follow the service log:

```sh
sudo journalctl -u sidestore-reflector -f
```

On the first start, open the `login.tailscale.com` URL shown in the log and
approve the new `sidestore-reflector` machine. Wait for a line like this:

```text
reflector up: hostname=sidestore-reflector state=/var/lib/sidestore-reflector ips=[100.x.y.z ...]
```

Record the IPv4 address (`100.x.y.z`) as `REFLECTOR_IP`. The address does not
need to be adjacent to the iPhone's address. If you change it later in the
Tailscale admin console, update SideStore to match.

## Configure SideStore

Keep Wi-Fi and Tailscale connected on the iPhone, then:

1. Open **SideStore → Settings → Connection Config**.
2. Turn **Use Local VPN** off.
3. Enter `REFLECTOR_IP` under **Remote Endpoint → Device IP**.
4. Enter `49152` for **RemotePair Port**, or leave it empty to use the default.
5. Tap **Confirm**.
6. Fully close and reopen SideStore.
7. Run **Settings → Health Check**, then try **Refresh All**.

Do not use the automatically discovered Tunnel IP or Device IP for this setup.
Multiple iPhones may use the same `REFLECTOR_IP`.

## Check the service

```sh
systemctl status sidestore-reflector
sudo journalctl -u sidestore-reflector --since today
```

The expected service state is `active (running)`. The reflector's Tailscale
IPv4 appears in the `reflector up` log line and in the Tailscale admin console.

## Troubleshooting

### Tunnel IP and Device IP show N/A

This setup does not use SideStore's Local VPN auto-discovery. Turn **Use Local
VPN** off and enter the reflector address under **Remote Endpoint**.

### Remote Endpoint shows Reachable: No

- Confirm that both the iPhone and `sidestore-reflector` are online in
  Tailscale.
- Confirm that SideStore contains the reflector's current IPv4 address.
- Reconnect Tailscale and fully restart SideStore after an address change.
- Check that the tailnet ACL permits traffic between the iPhone and reflector.
- Confirm that the iPhone is associated with Wi-Fi.

### The service asks for registration again

Check that `/var/lib/sidestore-reflector` still exists and is writable through
the unit's `StateDirectory=sidestore-reflector` setting. Registration state is
stored there by systemd deployments.

## Security

The service reflects every well-formed IPv4 packet that reaches its Tailscale
address. Restrict access to trusted tailnet devices with Tailscale ACLs. Do not
expose the reflector address to untrusted peers.

## Manual operation

The binary accepts no arguments:

```sh
./sidestore-reflector
```

Interactive runs store state in `~/.local/state/sidestore-reflector` on Linux.
Stop the process with `Ctrl+C`.

## Development

```sh
go test ./...
go vet ./...
```

Implementation details and design decisions are documented separately in
[docs/DESIGN.md](docs/DESIGN.md).
