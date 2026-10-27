# HeduVPN

**A self-hosted VPN that looks like an ordinary HTTPS website.**

HeduVPN carries your TCP traffic inside TLS 1.3 on a normal HTTPS port. It does not
use WireGuard, OpenVPN, PPTP, L2TP or any recognisable VPN handshake, and it opens no
unusual ports. To a network observer the relay is just another pinned-HTTPS site with a
WebSocket endpoint — and when someone knocks on the door without the key, it answers
with an ordinary web page.

```
   your apps                                                     the internet
 ┌───────────┐   SOCKS5/HTTP CONNECT    ┌────────────┐   TLS 1.3    ┌───────────┐
 │ browser   │─────────────────────────▶│ HeduVPN    │─────────────▶│ HeduVPN   │────▶ TCP
 │ curl, OS  │  127.0.0.1:1080          │ client     │  :443, /ws   │ relay     │
 └───────────┘                          └────────────┘              └───────────┘
                                         padding, jitter,           decoy website,
                                         cover traffic,             active-probe
                                         session rotation           resistance
```

---

## Contents

- [Why another VPN](#why-another-vpn)
- [Try it in two minutes](#try-it-in-two-minutes)
- [How it avoids VPN blocking](#how-it-avoids-vpn-blocking)
- [Deploy a relay](#deploy-a-relay)
- [Use the client](#use-the-client)
- [Desktop app](#desktop-app)
- [Dashboard and live lab](#dashboard-and-live-lab)
- [How it works](#how-it-works)
- [Security model and limits](#security-model-and-limits)
- [Configuration](#configuration)
- [Tests](#tests)
- [Repository layout](#repository-layout)
- [License](#license)

---

## Why another VPN

Censors rarely block "encrypted traffic" any more. They block specific protocols and
ports, they fingerprint handshakes, they blacklist SNIs, and they actively probe servers
that look interesting. WireGuard and OpenVPN are easy targets: fixed packet layouts,
recognisable handshakes, default ports, no cover story.

HeduVPN takes a different approach:

| What a censor does | What HeduVPN does |
| --- | --- |
| Blocks known VPN ports and protocols | One TLS 1.3 listener. Default port 443. No VPN signature anywhere in the handshake. |
| Fingerprints the TLS handshake | Speaks ordinary TLS via OpenSSL with ALPN `http/1.1`. Terminating TLS at nginx/Caddy gives the relay a mainstream server fingerprint; client-side fingerprints are discussed in [the limits](#security-model-and-limits). |
| Blacklists VPN hostnames (SNI) | You use a domain you control, with a real certificate. The same host serves a decoy website on `/`. |
| Actively probes suspicious servers | Unknown paths return realistic 404s, junk returns 400, and the WebSocket endpoint refuses to upgrade unless the request carries a short-lived HMAC gate token. |
| Analyses packet sizes | Record padding (`random`, `cells`) and optional cover traffic blur plaintext lengths. |
| Analyses timing | Optional per-record jitter, cover traffic while idle, and periodic session rotation. |
| Replays captured handshakes | Timestamped handshakes (120 s window), fresh nonces, and a per-relay nonce replay cache. |
| Mounts a MITM proxy | Certificate pinning is baked into the connection link. A wrong certificate fails closed; there is no insecure fallback. |
| Blocks your relay IP | Nothing local can fix that. Use a fresh IP, a different hosting provider, or put a WebSocket-capable CDN in front. |

The client is deliberately boring: a local **SOCKS5 proxy** (plus an optional **HTTP
CONNECT proxy**) that your apps already know how to use. No kernel driver, no TUN
device, no administrator rights, and the same code runs on Linux, macOS and Windows.

---

## Try it in two minutes

Requirements: Python 3.10+, `pip install .` (the only runtime dependency is
`cryptography`).

### 1. Start the dashboard

```bash
python -m heduvpn dashboard
# → http://127.0.0.1:8000
```

The **Overview** tab runs a *real* lab on loopback: a relay, a client and an origin web
server, all with real TLS, real key exchange and real traffic. The **Wire lab** tab shows
what a network observer would see — records, sizes, padding share, timing — and runs nine
active probes against the relay. The **Connect** tab starts the same client engine
against a real link. Nothing is faked for the demo.

### 2. Or do it from the terminal

```bash
# A throwaway relay on localhost (no root needed above 1024)
python -m heduvpn relay --domain localhost --port 8443 --state-dir ./demo-relay

# In another terminal, copy the printed hedu1:// link and connect
python -m heduvpn client --link 'hedu1://…' --socks-port 1080 --test http://example.com/

# Use it
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me/ip
```

---

## How it avoids VPN blocking

Each layer is independent, so you can trade some camouflage for simplicity:

1. **Outer transport — nothing exotic.**
   A standard TLS 1.3 connection with ALPN `http/1.1`. The tunnel frames are encrypted
   *inside* that connection, so even a TLS-terminating reverse proxy sees only opaque
   WebSocket or application data.

2. **Two shapes of traffic.**
   - `ws` (default): a normal HTTP `GET /ws` upgrade with `Sec-WebSocket-*` headers,
     then RFC 6455 binary frames. Indistinguishable from a chat app or a metrics socket.
   - `tls`: the tunnel writes length-prefixed records directly after the TLS handshake.
     Fewer bytes of overhead, slightly less "webby".

3. **A real certificate and a real website.**
   Generate a self-signed certificate on first start (pinned in the link), or use a
   Let's Encrypt certificate. Browsing to the relay shows a generic placeholder site;
   unknown paths return nginx-style 404 pages; malformed requests return 400. Server
   banner, `Date`, `ETag` and `Last-Modified` look like nginx.

4. **A gate instead of a giveaway.**
   Upgrading `/ws` requires a cookie containing an HMAC-signed, 120-second token derived
   from the pre-shared key. Without it: a 404, exactly like a mistyped path. Even with a
   valid token, the tunnel handshake — an AEAD message under a key derived from the PSK —
   must authenticate or the connection is dropped. Captured tokens expire quickly; a
   captured handshake cannot be replayed.

5. **No plaintext, no "accept anyway".**
   The PSK never travels on the wire. Certificate pinning is mandatory in pin mode and a
   pin mismatch is a hard failure. The relay rejects private and loopback destinations by
   default, so a compromised client cannot use it to scan its LAN.

6. **Metadata camouflage.**
   - `random` padding: 0–96 random bytes per record.
   - `cells` padding: bodies rounded up to 256-byte cells with a little noise, so sizes
     cluster instead of tracking plaintext.
   - `jitter`: small random delays on short records.
   - `cover`: keep-alive and cover frames while idle (`none`, `low`, `medium`).
   - `rotate`: reconnect with fresh keys after N minutes.

7. **Server-side anti-probing.**
   The relay only speaks HTTP to things that look like HTTP. Direct TLS with junk gets a
   `400 Bad Request` and a close. A valid WebSocket handshake without the gate token gets
   a `404`. A valid token but a bad HELLO gets a decoy 400 over native TLS, or a clean
   close over WebSocket. Every probe is counted in the dashboard, so you can see what
   scanners are doing.

What it does **not** hide: the IP address of your relay, the total volume of your
traffic, and long-term flow correlation. See [Security model and limits](#security-model-and-limits) and
[`docs/threat-model.md`](docs/threat-model.md).

---

## Deploy a relay

You need a VPS with a public IPv4 address, an `A` record pointing at it, and port 443
reachable (TCP). Root is only needed to bind ports below 1024.

### Installation

```bash
git clone https://github.com/hadi-fakih/HeduVPN.git
cd HeduVPN
python3 -m pip install .
# or, to keep the system Python clean:
python3 -m pip install --user .   # ~/.local/bin/heduvpn
```

### Option A — HeduVPN terminates TLS (self-signed certificate)

```bash
sudo heduvpn relay --domain vpn.example.com --port 443
```

On first start it creates `~/.heduvpn/relay/` with a private key, a self-signed
certificate (CN/SAN = your domain), a 256-bit PSK, `relay.json` and a ready-to-use
client link. Clients pin the certificate, so no CA is involved. The link contains the
PSK — treat it like a password.

If you cannot run as root, use `--port 8443` and pass `--public-port 8443` so the link
matches, or grant the capability:

```bash
sudo setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(which python3)")"
```

### Option B — a public certificate (Let's Encrypt)

```bash
sudo certbot certonly --standalone -d vpn.example.com
sudo heduvpn relay --domain vpn.example.com --port 443 \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key  /etc/letsencrypt/live/vpn.example.com/privkey.pem \
  --state-dir /var/lib/heduvpn
```

The link still carries the certificate pin (computed from the first certificate in the
chain), which is stricter than CA validation: a compromised or mis-issued certificate
cannot impersonate the relay. Use `--verify system` on the client if you prefer CA
semantics; both are supported.

### Option C — nginx/Caddy terminates TLS (recommended for busy servers)

Let the web server own TLS, hide the relay on loopback, and inherit a mainstream TLS
fingerprint:

```bash
sudo heduvpn relay --domain vpn.example.com --plaintext \
  --listen-host 127.0.0.1 --port 8080 \
  --state-dir /var/lib/heduvpn
```

The printed link uses `verify: system`, port 443 and the WebSocket transport. An nginx
site like this is enough (full example in [`deploy/nginx.conf.example`](deploy/nginx.conf.example)):

```nginx
server {
    listen 443 ssl http2;
    server_name vpn.example.com;

    ssl_certificate     /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # the tunnel
    location = /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_read_timeout 1h;
    }

    # the cover story
    location / { root /var/www/vpn-decoy; }
}
```

A CDN that forwards WebSocket upgrades (Cloudflare, Fastly, …) can also front the relay
— set the origin to `127.0.0.1:8080` style plain-HTTP WebSocket. Remember that the CDN
then sees your traffic metadata, and some CDNs have their own policies about VPNs.

### Keep it running

A systemd unit is included: [`deploy/heduvpn-relay.service`](deploy/heduvpn-relay.service).

```bash
sudo cp deploy/heduvpn-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now heduvpn-relay
sudo journalctl -u heduvpn-relay -f
```

### Distribute the link

```bash
cat /var/lib/heduvpn/client-link.txt      # or ~/.heduvpn/relay/client-link.txt
```

`heduvpn relay` prints the link and also writes `client-link.txt` (mode 0600) plus a
ready `client.json`. The link looks like:

```
hedu1://vpn.example.com:443#eyJrIjoiaGR1MV9oMl9T…
```

Everything after `#` is base64url JSON containing the PSK, SNI, pin and transport. It is
deliberately a URI *fragment*, so it is not sent in HTTP requests if the link is ever
pasted into a browser. Send it over a channel you trust; anyone with the link has the key.

---

## Use the client

### Import and connect

```bash
heduvpn import 'hedu1://…' --out ~/.heduvpn/client.json
heduvpn client --config ~/.heduvpn/client.json
# local SOCKS5 on 127.0.0.1:1080
```

Or skip the file:

```bash
heduvpn client --link 'hedu1://…' --http-proxy 8080
```

Useful client flags:

| Flag | Meaning |
| --- | --- |
| `--socks-port N` / `--socks-host H` | Where the local SOCKS5 listener binds (default `127.0.0.1:1080`). |
| `--http-proxy N` | Also run a local HTTP `CONNECT` proxy on port `N`. |
| `--allow-lan` | Allow other machines on your LAN to use the proxies. |
| `--system-proxy` | Point the operating-system proxy at the tunnel while connected, and restore the previous settings on exit. |
| `--dns system\|dns\|remote` | Resolve names locally (system resolver), via a chosen DNS server, or send names to the relay (no local DNS leak). |
| `--padding none\|random\|cells` | Record padding mode. |
| `--cover none\|low\|medium` | Cover traffic while idle. |
| `--jitter MS` | Random delay on small records. |
| `--rotate MINUTES` | Rotate session keys periodically (`0` = never). |
| `--test URL` / `--test-only` | Fetch a URL through the new tunnel, then keep running or exit. |
| `--duration SECONDS` | Stop automatically (handy for scripts). |

`heduvpn check --url https://ifconfig.me/ip` does a one-shot request through an already
running client, printing the status and body. `heduvpn doctor` checks the environment,
the tunnel port and the proxy state.

### Point applications at it

- **Firefox** — Settings → Network Settings → Manual proxy → SOCKS host `127.0.0.1`,
  port `1080`, SOCKS v5, tick *Proxy DNS when using SOCKS v5*.
- **curl** — `curl --socks5-hostname 127.0.0.1:1080 https://example.com/`
- **Anything that only speaks HTTP proxies** — start the client with `--http-proxy 8080`
  and set `http_proxy=http://127.0.0.1:8080`.
- **System-wide** — use the desktop app or `heduvpn client --system-proxy` /
  `heduvpn system-proxy on`. Apps that ignore the OS proxy (some games, UDP traffic,
  services without proxy support) are not covered: HeduVPN is a proxy, not a TUN adapter.

### Run it as a user service

```bash
heduvpn import 'hedu1://…' --out ~/.heduvpn/client.json
heduvpn client --config ~/.heduvpn/client.json --system-proxy
```

Keep it in a terminal, or wrap it in a small systemd user unit / Windows scheduled task.
The GUI has a *Connect on startup* setting.

---

## Desktop app

```bash
python -m heduvpn gui
# optional: heduvpn gui --connect --system-proxy
```

A dependency-free tkinter app (tkinter ships with python.org installers; on Debian/Ubuntu
install `python3-tk`). It provides:

- import / paste a connection link, one-click connect and disconnect;
- live throughput, record-size and wire-overhead telemetry;
- SOCKS/HTTP port, padding, cover, DNS and transport settings, saved to `~/.heduvpn/client.json`;
- a **Use as system proxy** switch that snapshots the OS proxy settings and restores them
  on disconnect — or on the next launch if the app was killed;
- auto-reconnect with backoff, and session rotation.

Supported system-proxy backends: Windows WinINET (per-user), macOS `networksetup` on the
active network service, and GNOME `gsettings`. The CLI equivalents are
`heduvpn system-proxy on|off|status`.

---

## Dashboard and live lab

```bash
heduvpn dashboard --port 8000
```

Four tabs:

- **Overview** — relay/client state, TLS details, pin, PSK fingerprint, rates, record
  counters, probe verdicts, activity log.
- **Wire lab** — the anti-censorship story with real numbers: record-size histograms,
  padding share, overhead, inter-arrival spacing, the last captured records, and the
  result of nine probes a censor would run (`GET /`, a fake admin page, `/ws` without a
  token, `/ws` with a forged token, random bytes over TLS, a token-bearing WebSocket
  upgrade without the PSK, a wrong-key HELLO, certificate/ALPN inspection). Change
  padding, cover, jitter or transport and restart the lab to compare.
- **Connect** — import a `hedu1://` link, start/stop a real client, copy the SOCKS and
  HTTP proxy addresses, toggle the system proxy, download `client.json`.
- **Guide** — copy-paste commands for deployment and client setup.

The lab is entirely local (relay, client and origin on `127.0.0.1`, ephemeral ports,
temporary state). It is not a mock: bytes really go through TLS, WebSocket framing,
padding and the AEAD protocol.

Running the dashboard with a real setup:

```bash
heduvpn dashboard --relay-config /var/lib/heduvpn/relay.json
heduvpn dashboard --client-config ~/.heduvpn/client.json
```

The dashboard has **no authentication**. Bind it to `127.0.0.1` (the default) or reach it
through an SSH tunnel. `--host 0.0.0.0` exposes a control panel that can start clients and
change proxy settings.

---

## How it works

HeduVPN is a small, testable protocol rather than a fork of an existing VPN:

1. **Handshake (inside TLS).** The client sends a 4-byte length followed by a
   ChaCha20-Poly1305 envelope (key = HKDF-SHA256(PSK, "handshake")). The plaintext carries
   a version, 16-byte client nonce, Unix timestamp and random padding. The relay replies
   with its own nonce and timestamp, with the client nonce as AEAD associated data. Both
   sides reject stale handshakes outside a 120-second window; the relay remembers recent
   client nonces and refuses replays.

2. **Session keys.** HKDF-SHA256(PSK, salt = client nonce ‖ server nonce) produces 64
   bytes: one 32-byte key per direction. Each record uses a 96-bit nonce built from a
   monotonically increasing counter, so reordering, truncation or replay of records fails
   authentication.

3. **Records.** `uint32 ciphertext_length | ChaCha20-Poly1305(plaintext)`, where the
   associated data is the length field and the plaintext is
   `type | stream_id | payload_length | payload | padding`. Types cover
   HELLO/ACK, OPEN/OPEN_OK/DATA/CLOSE, PING/PONG, ERROR and PAD.

4. **Multiplexing.** One TLS connection carries many streams. The client's SOCKS5 and
   HTTP CONNECT handlers allocate stream IDs; the relay dials destinations and pipes
   bytes. Half-closes are explicit, so `curl`-style request/response flows close cleanly.

5. **Transport.** Over WebSocket, each HeduVPN record is one binary WS frame; over native
   TLS it is written directly after the handshake. The WebSocket path requires a
   gate cookie (HMAC-SHA256 of timestamp and nonce, 120 s lifetime) before the upgrade.

The complete wire format — including the link encoding, address encoding, padding rules
and error codes — is documented in [`docs/protocol.md`](docs/protocol.md).

### Why the pieces matter

- **PSK-only by default, no PKI on the client.** With `verify=pin` (the default) there
  is no CA to trust, no ACME client on the client side, and no way for a corporate MITM
  root to silently decrypt the tunnel. `verify=system` is available for deployments
  where ordinary CA validation is preferred.
- **Fail closed.** Bad pin, bad PSK, stale handshake, unknown protocol version → the
  connection is dropped. There is no downgrade path.
- **Small blast radius.** The relay is a proxy: it opens TCP connections to destinations
  you ask for, with a policy layer. It does not run as root after binding, does not
  install routes, and does not touch DNS unless you ask it to.

---

## Security model and limits

**What HeduVPN protects against**

- Protocol/port blocking and simple DPI: it is TLS 1.3 with a web front.
- SNI-based blocking: you choose the domain, and the relay serves a plausible site.
- Active probing: the relay answers like a web server without the key.
- MITM and certificate substitution: pinned certificates.
- Replay of captured handshakes and records.
- Casual traffic analysis: record padding, jitter, cover traffic, session rotation.

**What it does not protect against**

- **IP blocking.** If a censor blocks your relay's address, you need another address or a
  CDN in front. Nothing in the protocol can fix that.
- **A determined, global observer.** Long-lived flows and total volume remain visible.
  Padding raises the cost of size/timing analysis; it does not eliminate it.
- **TLS fingerprinting.** The client's TLS stack is Python/OpenSSL, which does not
  perfectly match a browser's ClientHello (JA3/JA4), so a DPI box that fingerprints
  clients can still tell it apart from Chrome. Terminating TLS at nginx or Caddy changes
  the *server* fingerprint an active prober sees, not the client's ClientHello. If
  client-side fingerprinting matters in your environment, put a browser-shaped TLS
  front end on the client side too (or terminate the tunnel inside a browser).
- **Server fingerprint.** A self-signed, auto-generated certificate and a Python TLS
  server are visible to active scanners. Fronting the relay with nginx/Caddy and a real
  certificate is recommended in that case, and it is why `--plaintext` mode exists.
- **Endpoint compromise or key theft.** Anyone with the PSK (the link) is inside the
  tunnel. Keys are stored with mode 0600, but a compromised laptop is a compromised VPN.
- **No perfect forward secrecy from the PSK alone.** Session keys mix two fresh nonces,
  so a passive attacker who did *not* record the handshake cannot derive them. But an
  attacker who records handshakes *and* later obtains the PSK can derive those session
  keys. Rotate the PSK if you suspect it leaked; generate a new relay identity to rotate
  everything.
- **UDP, ICMP and non-TCP protocols.** This is a TCP proxy. Voice/video over UDP, games
  and ICMP do not go through it.
- **Full-device VPN semantics.** There is no TUN device, so applications that bypass the
  OS proxy are not covered. Route them through the HTTP/SOCKS proxy explicitly, or use a
  separate tun2socks layer.
- **Legal and policy risk.** Running or using circumvention tools may violate local law
  or provider terms. You are responsible for how you use it.

**Operational hygiene**

- Serve the link over an authenticated channel; it is a credential.
- Keep `relay.json`, `cert.pem`, `key.pem`, `psk` and `client.json` readable only by their
  owner (the CLI sets 0600).
- Put the relay behind a host firewall that allows only 443 (and SSH from your
  addresses). The relay never needs other inbound ports.
- Watch the dashboard's probe counters and the logs for scanning activity.
- Upgrade `cryptography` and Python for security fixes.

---

## Configuration

### Relay (`relay.json`)

Created on first run in the state directory. Fields (defaults shown):

| Key | Default | Meaning |
| --- | --- | --- |
| `listen_host`, `listen_port` | `0.0.0.0`, `443` | Where the relay listens. |
| `domain` | `localhost` | Public hostname; used as certificate CN/SAN and in the link. |
| `psk` | generated | 256-bit pre-shared key, `hdu1_…`. |
| `certfile`, `keyfile` | generated | TLS certificate chain and key. |
| `tls` | `true` | `false` when a reverse proxy/CDN terminates TLS (`--plaintext`). |
| `behind_proxy` | `false` | Set automatically by `--plaintext`. |
| `alpn` | `["http/1.1"]` | Advertised ALPN protocols. |
| `ws_path`, `ws_cookie` | `/ws`, `hid` | WebSocket endpoint and gate-cookie name. |
| `ws_token_ttl` | `120` | Gate-token lifetime in seconds. |
| `allow_private` | `false` | Permit loopback/RFC1918 destinations (lab/testing only). |
| `allow_ports` | `[]` | Optional destination-port allowlist. |
| `block_ports` | `[25, 465, 587]` | Destination ports always refused (SMTP abuse). |
| `block_hosts` | `[]` | Destination hostname suffix denylist. |
| `max_sessions`, `max_streams` | `0`, `512` | Session cap (`0` = unlimited) and per-session stream cap. |
| `idle_timeout`, `connect_timeout` | `300`, `10` | Seconds. |
| `decoy_site`, `decoy_server` | `Hedu Labs`, `nginx/1.24.0` | Cover-site title and `Server` header. |
| `padding` | `random` | Relay-side padding for server→client records. |
| `log_path` | `""` | Optional log file; empty means stdout. |

### Client (`client.json`, or the GUI)

`psk`, `name` plus:

| Section | Keys |
| --- | --- |
| `connection` | `server`, `port`, `sni`, `transport` (`ws`/`tls`), `ws_path`, `ws_host`, `ws_cookie`, `verify` (`pin`/`system`/`insecure`), `pin`, `connect_timeout`, `upstream` (optional `socks5://…` for the TLS leg) |
| `camouflage` | `padding` (`none`/`random`/`cells`), `jitter_ms`, `cover` (`none`/`low`/`medium`), `rotate_minutes` |
| `socks` | `host`, `port`, `proxy_port`, `allow_lan`, `dns` (`system`/`dns`/`remote`), `dns_server`, `username`, `password` |

`heduvpn import 'hedu1://…' --out client.json` writes a complete file; every field can
also be overridden on the command line.

---

## Tests

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest
```

69 tests cover:

- PSK/token/handshake formats, ACK binding, certificate generation and pinning;
- address encoding (IPv4/IPv6/domain, IDNA), frame codec for every padding mode,
  authentication failures, size limits, replay protection;
- RFC 6455 framing, masking, fragmentation, gate cookies, HTTP request/response parsing,
  decoy responses;
- end-to-end relay/client traffic over both transports, SOCKS5 and HTTP CONNECT
  (including a request body sent immediately after `CONNECT`), DNS modes, session
  rotation, private-destination policy, wrong PSK and replayed handshakes;
- the demo lab against a real loopback relay, the CLI (link/import/relay/doctor), the
  system-proxy snapshot logic.

The tests use only loopback sockets and temporary directories; no network access or root
is required.

---

## Repository layout

```
heduvpn/
  crypto.py       PSK, HKDF, AEAD, certificate generation, pinning, WS tokens
  protocol.py     handshake, record codec, padding, SOCKS-style addresses
  httpwire.py     minimal HTTP parsing and realistic decoy responses
  websocket.py    RFC 6455 client/server, fragmentation, control frames
  transport.py    TLS wrapping, pinning, SOCKS5 dialing, stream helpers
  config.py       client settings and validation
  client.py       tunnel client, SOCKS5/HTTP proxies, DNS, rotation, keepalive
  relay.py        relay, sessions, policy, gate, decoys, counters
  link.py         hedu1:// link encoding/decoding
  demo.py         real loopback lab and active probes
  dashboard.py    zero-dependency web server/API
  web/            dashboard UI (no external assets)
  gui/            tkinter desktop app
  systemproxy.py  Windows/macOS/GNOME proxy snapshot + restore
  cli.py          command line interface
tests/            pytest suite (69 tests)
docs/             protocol and threat-model documentation
deploy/           systemd unit and nginx example
```

---

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 hadi-fakih.

HeduVPN is an anti-censorship tool. Use it only on networks and in jurisdictions where
you are allowed to, and respect the terms of service of the systems you connect to.
