# WireGuard capture mode (experimental)

> **Experimental.** Built only with the cargo feature `wireguard`, which is off by default:
> release binaries do not contain it. It was written as a spike, tested on loopback with an
> in-process WireGuard client, and has not been tried with a real phone yet.

Through an HTTP proxy, wirust sees only the traffic that honours the proxy setting. Apps that
ignore the system proxy (Flutter's `dart:io`, raw sockets) and HTTP/3 (QUIC, UDP) go around
it. In the WireGuard capture mode the phone runs the official WireGuard app pointed at this
computer, so every packet of the phone reaches wirust, and wirust terminates each TCP
connection itself, in userspace: no TUN device, no route or firewall change, no root.

## Use

```sh
cargo build --release --features wireguard

# 1. A peer: prints the app configuration as text and as a QR code.
wirust wireguard add-peer phone                     # --lan-ip IP and --port P override the endpoint

# 2. The listener, on the LAN address the configuration names (a non-loopback address needs
#    --allow-remote, as for the HTTP listener).
wirust wireguard --listen 192.168.1.5:51820 --allow-remote --ui 127.0.0.1:8081
```

Scan the QR code with the WireGuard app (Add tunnel > Scan from QR code) and switch the tunnel
on. Install the wirust CA on the phone as for the proxy mode (`docs/mobile.md`); without it,
TLS interception fails exactly as it would through the proxy.

The options of a plain run (`--ui`, `--rules`, `--passthrough`, `--session` ...) apply. The
HTTP proxy listener keeps running, moved to a free loopback port. Peers are read when
`wirust wireguard` starts: restart it after `add-peer`.

## Files and addresses

`<config dir>/wireguard/` (mode 0700, next to the CA):

| File | Contents | Mode |
|---|---|---|
| `server.key` | the server's private key, base64, created on first use | 0600 |
| `peers` | one line per peer: `NAME PUBLIC_KEY ADDRESS` | 0600 |

A peer's private key is printed once by `add-peer` and stored nowhere. To remove a peer,
delete its line from `peers` and restart.

The tunnel uses `10.233.0.0/24`: the server is `10.233.0.1`, peers get `.2`, `.3` and so
on. The client configuration says `Address = 10.233.0.N/32`, `DNS = 10.233.0.1`,
`AllowedIPs = 0.0.0.0/0, ::/0` (everything goes through the tunnel) and
`Endpoint = LAN_IP:PORT`.

## What happens to each packet

| Arrives | What wirust does |
|---|---|
| UDP datagram that is not WireGuard | dropped, no answer |
| Handshake from a configured public key | answered; the session is kept by boringtun |
| Handshake from any other key | dropped, no answer (the listener looks closed) |
| Data from an established session | decrypted; the inner packet is used only if its source is the peer's own tunnel address |
| IPv4 TCP | terminated by a smoltcp stack; see below |
| IPv4 UDP to port 53 | relayed to the first `nameserver` of `/etc/resolv.conf`; the answer comes back from the address the phone asked. No resolver found: dropped, one line on stderr |
| IPv4 UDP to port 443 (QUIC) | dropped, so the app falls back to TCP; one entry in the flow log per run says so |
| Other IPv4 UDP | dropped, one line on stderr per port |
| ICMP, other IPv4 protocols | dropped |
| IPv6 | dropped (the tunnel routes `::/0`, so it does not leak around the capture either) |

Each terminated TCP connection is handed to the same code a CONNECT tunnel uses, with the
peer's tunnel address and port as the flow's client:

- **Port 80**: served as HTTP/1.1, request by request; the `Host` header names the server.
- **Any other port**: the first bytes are read as for a CONNECT tunnel. A TLS ClientHello is
  intercepted under its SNI (fingerprint, per-SNI certificate, rules and passthrough as
  usual; the server connection goes to the SNI name, resolved by this computer). Anything
  else is relayed raw to the original address and port; a protocol where the server speaks
  first waits the same short time as in a CONNECT tunnel before the relay starts.

## Threat model

A WireGuard listener is a network service. What guards it:

- **Bind address**: `--listen` defaults to `127.0.0.1:51820`. Any other address needs
  `--allow-remote`, the same guard as the HTTP listener and the UI.
- **Who may connect**: only the public keys in `peers`. A handshake from another key gets no
  answer; boringtun's handshake rate limiter and cookie mechanism stay on.
- **Spoofing inside the tunnel**: a peer's packets are used only with its own tunnel address
  as the source.
- **No open relay to this machine**: connections to loopback, unspecified, broadcast and
  multicast addresses, to `10.233.0.1`, to the refused addresses (the UI) and to the HTTP
  listener are not served, nor TLS with an SNI of `localhost`. A DNS name that resolves to a
  loopback address is not caught, the same as through the proxy. The peers can otherwise
  reach whatever this computer can reach, as a proxy client can.
- **Keys**: the server key is created with mode 0600 in a 0700 directory; peer private keys
  are never written to disk. Anyone who reads `server.key` can impersonate the server to the
  peers; anyone who has a peer's configuration can use the listener as that peer.
- **Traffic**: everything a peer sends is decrypted and logged like proxy traffic; session
  files hold the same secrets.

## Not built

- HTTP/3 termination: QUIC is dropped. Terminating it needs `quinn` plus `h3` with per-SNI
  certificates from the CA, and a UDP path in the stack.
- IPv6 inside the tunnel.
- IP fragments: the stack is built without reassembly, so fragmented packets are dropped. The
  WireGuard app's MTU (1420) avoids them in practice.
- Backpressure from the server side towards the phone: data waiting for the phone's TCP
  window is buffered without a bound. The other direction is bounded (the stack's window
  shrinks while the handler is not reading).
- DNS over TCP to `10.233.0.1`, peer removal and reload without a restart, preshared keys.
- Measurements under load.

## Tests

`cargo test --features wireguard --test wireguard` runs a boringtun client and a smoltcp
stack in the test process, over UDP on `127.0.0.1`: an HTTP request through the tunnel
becomes a flow with the peer's tunnel address as its client, and a handshake from an unknown
key gets no answer. No network device is created.
