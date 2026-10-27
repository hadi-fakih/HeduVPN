# HeduVPN wire protocol (v1)

This document describes version 1 of the HeduVPN protocol as implemented in
`heduvpn/protocol.py`, `heduvpn/crypto.py`, `heduvpn/websocket.py` and
`heduvpn/relay.py`. It is meant to be complete enough for an independent
implementation and for security review.

All integers are unsigned and big-endian. `PSK` is a 32-byte pre-shared key,
transported as `hdu1_<base64url>` in configuration and links.

---

## 1. Layering

```
application bytes
  └─ stream multiplexing (OPEN/DATA/CLOSE, stream ids)
      └─ records: length | AEAD(type|sid|len|payload|pad)
          └─ framing: WebSocket binary frames, or raw writes
              └─ TLS 1.3 (ALPN http/1.1)
                  └─ TCP, normally port 443
```

The relay can also run with TLS terminated by a reverse proxy (`--plaintext`).
In that case only the outer TLS layer is removed; everything above it is
unchanged, and the WebSocket transport must be used.

---

## 2. Connection link

```
hedu1://HOST:PORT#BASE64URL(JSON)
```

The fragment is a compact JSON object with single-letter keys:

| Key | Meaning | Example |
| --- | --- | --- |
| `k` | PSK (`hdu1_…`) | `hdu1_h2_…` |
| `s` | TLS SNI / expected hostname | `vpn.example.com` |
| `p` | Certificate pin, `sha256:<hex>` (empty when `v` = `system`) | `sha256:9776…` |
| `t` | Transport: `ws` or `tls` | `ws` |
| `w` | WebSocket path | `/ws` |
| `h` | HTTP `Host` header for the upgrade | `vpn.example.com` |
| `c` | Gate-cookie name | `hid` |
| `v` | Verification mode: `pin`, `system`, `insecure` | `pin` |
| `d` | Padding: `none`, `random`, `cells` | `random` |
| `j` | Jitter in milliseconds | `12` |
| `o` | Cover traffic: `none`, `low`, `medium` | `low` |
| `n` | Human-readable name | `vpn.example.com · HeduVPN` |

The scheme is `hedu1`, the host is an IPv4 address, bracketed IPv6 address or
DNS name, and the port is the TCP port to connect to. The link is a credential:
anyone holding it can use the relay. It is a URI fragment so that pasting it
into a browser does not transmit the PSK to the server.

`sha256:` pins are the SHA-256 of the DER encoding of the leaf certificate
(the first certificate in `cert.pem` / `fullchain.pem`).

---

## 3. Transports

### 3.1 Native TLS (`transport = "tls"`)

After the TLS handshake, both sides exchange handshake messages and records as
length-prefixed blobs directly on the TLS stream. The first bytes the client
sends therefore look like arbitrary application data inside TLS.

### 3.2 WebSocket (`transport = "ws"`)

The client performs a normal HTTP/1.1 upgrade:

```http
GET /ws HTTP/1.1
Host: vpn.example.com
User-Agent: Mozilla/5.0 (…)
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <16 random bytes, base64>
Sec-WebSocket-Version: 13
Cookie: hid=<gate token>
```

The gate token is:

```
ts      = uint64 unix time, seconds
nonce   = 8 random bytes
mac     = HMAC-SHA256(PSK, "ws1|" + decimal(ts) + "|" + nonce)[:16]
token   = base64url(ts || nonce || mac)   # no padding
```

The relay accepts tokens whose timestamp is within ±120 seconds (configurable
with `ws_token_ttl`). Anything else — no cookie, wrong cookie name, invalid
base64, stale or forged token — receives a `404 Not Found` decoy page, the same
as any unknown path.

After `101 Switching Protocols`, each HeduVPN record is sent as one binary
WebSocket frame (clients mask, servers do not). Implementations must handle
fragmented messages, ping/pong and close frames; text frames are ignored. The
relay closes the WebSocket when the tunnel session ends.

Without the PSK the WebSocket is just a WebSocket: the relay waits for a HELLO,
fails to authenticate it, sends a decoy HTTP `400` (or closes), and tears the
connection down.

---

## 4. Handshake

Both handshake messages use the "envelope" format:

```
uint32 total_length
12-byte nonce (random)
ciphertext + 16-byte tag = ChaCha20-Poly1305(key, nonce, plaintext, aad)
```

`key = HKDF-SHA256(PSK, salt = "heduvpn/v1", info = "handshake", length = 32)`.
`total_length` covers the 12-byte nonce plus the ciphertext and tag and must be
≤ 4096.

### 4.1 HELLO (client → relay)

Plaintext:

```
uint8   version      = 1
uint8   flags        = 0
bytes16 client_nonce (random)
uint64  timestamp    (unix seconds)
uint16  pad_length
bytes   pad          (0..48 random bytes)
```

The relay opens the envelope with its PSK-derived key. It rejects:

- an unauthenticated envelope (wrong PSK),
- an unknown version,
- a timestamp more than 120 seconds away from its clock,
- a `client_nonce` seen in the last 120 seconds (replay cache).

### 4.2 ACK (relay → client)

Plaintext:

```
uint8   version      = 1
uint8   flags        = 0
bytes16 server_nonce (random)
uint64  timestamp    (unix seconds)
uint16  pad_length
bytes   pad
```

The ACK is encrypted with the same handshake key, but with the **client nonce as
associated data**. A client therefore only accepts an ACK that belongs to its own
HELLO; an attacker cannot splice an ACK from another session.

### 4.3 Session keys

```
okm = HKDF-SHA256(PSK, salt = client_nonce || server_nonce,
                  info = "heduvpn/v1/session", length = 64)
client → relay key = okm[0:32]
relay → client key = okm[32:64]
```

Each direction has its own 32-byte key and its own 64-bit record counter starting
at zero. The record nonce is 12 bytes: `0x00000000 || counter` (big-endian).
Counters are never reused for a given key, and a fresh handshake produces fresh
keys.

---

## 5. Records

Every record after the handshake is:

```
uint32 ciphertext_length          (7 ≤ length ≤ 131072)
bytes  ciphertext, length = ciphertext_length

associated data = uint32(ciphertext_length)
plaintext =
    uint8   type
    uint32  stream_id
    uint16  payload_length
    bytes   payload
    bytes   padding            (0..512 bytes, see below)
```

The cipher is ChaCha20-Poly1305 with the directional session key and the counter
nonce. The length field is authenticated as AAD, so truncation, extension or
record reordering is detected. Any authentication failure terminates the session;
there is no attempt to resynchronise.

| Type | Name | Direction | Payload |
| --- | --- | --- | --- |
| `0x01` | HELLO | C→R | handshake envelope (pre-record) |
| `0x02` | ACK | R→C | handshake envelope (pre-record) |
| `0x10` | OPEN | C→R | SOCKS-style address (see §6) |
| `0x11` | OPEN_OK | R→C | 0 or 1 byte: 1 = connected, empty = opening |
| `0x12` | DATA | both | stream bytes (≤ 16 KiB per record) |
| `0x13` | CLOSE | both | 1 byte reason (see §7) |
| `0x14` | PING | both | arbitrary (≤ 32 bytes) |
| `0x15` | PONG | both | echo of the PING payload |
| `0x16` | ERROR | R→C | 1 byte code + UTF-8 message |
| `0x17` | PAD | both | random bytes, must be discarded |

HELLO and ACK are not records: they are bare envelopes, so the relay can answer
junk with an HTTP error before any tunnel state exists.

Error codes:

| Code | Meaning |
| --- | --- |
| `1` | policy refused the destination (private address, blocked port/host) |
| `2` | destination connection failed |
| `3` | protocol error |
| `4` | internal relay error |

Stream ids are chosen by the client; `0` is reserved. The relay may limit the
number of concurrent streams per session (`max_streams`, default 512).

---

## 6. Address encoding

OPEN payloads use SOCKS5 address encoding:

```
ATYP=1: 0x01 | IPv4 (4 bytes)        | port (uint16)
ATYP=3: 0x03 | len (uint8) | domain  | port (uint16)
ATYP=4: 0x04 | IPv6 (16 bytes)       | port (uint16)
```

Domains are IDNA-encoded and limited to 255 bytes. The relay resolves names
itself when the client sends a domain name. With `dns = "remote"` the client
always sends names; otherwise it resolves locally (system resolver or the DNS
server configured in the client) and sends an IP address.

---

## 7. Stream lifecycle

```
client                                   relay                    target
  │ OPEN(addr)                             │                        │
  │───────────────────────────────────────▶│ connect ───────────────▶│
  │ OPEN_OK                                │                        │
  │◀───────────────────────────────────────│                        │
  │ DATA ⇄ DATA                            │ ⇄ bytes                │
  │ CLOSE(0x01)  (my write side is done)   │ write_eof ────────────▶│
  │                                        │ ◀──────────── EOF      │
  │ CLOSE(0x01)  (target write side done)  │                        │
  │◀───────────────────────────────────────│                        │
  │ CLOSE(0x00)  (tear down)               │ close                  │
```

CLOSE payload:

- `0x00` — close both directions and release the stream.
- `0x01` — the sender will send no more data, but still accepts data. The peer
  forwards EOF to its socket and later sends its own `CLOSE(0x01)` when the other
  direction ends.
- any other value — treated like `0x01`.

Either side may send `CLOSE(0x00)` at any time (for example when a local socket
errors), which aborts the stream.

---

## 8. Padding, jitter and cover traffic

Padding is appended inside the AEAD plaintext, so its length is not directly
visible; only the ciphertext length is. Modes:

| Mode | Rule |
| --- | --- |
| `none` | `padding_length = 0` |
| `random` | uniform 0–96 bytes per record |
| `cells` | round the record body up to a 256-byte cell plus 0–24 bytes of noise |

Padding applies to both directions but is configured independently on the client
and relay. `jitter_ms` adds a random delay of `uniform(0, jitter_ms)` to 35 % of
records smaller than 2 KiB. Cover traffic (`low`, `medium`) sends PING/PAD
records while the tunnel is idle; `none` stays silent. `rotate_minutes > 0`
reconnects the tunnel with a fresh handshake and fresh keys after the configured
time.

None of these make traffic analysis impossible; they change the shape of the
observable flow. See `docs/threat-model.md`.

---

## 9. Decoy behaviour

The relay's TLS listener behaves like a small web server:

| Request | Response |
| --- | --- |
| `GET /` | `200 OK`, generic HTML page, nginx-style headers (`Server`, `Date`, `ETag`, `Last-Modified`) |
| Unknown path | `404 Not Found`, nginx-style error page |
| Malformed HTTP | `400 Bad Request` |
| Binary junk over TLS | `400 Bad Request`, then close |
| `GET /ws` without a valid gate cookie | `404 Not Found` |
| `GET /ws` with a valid gate cookie | `101 Switching Protocols`, then tunnel handshake |
| Valid WebSocket but wrong PSK | `400 Bad Request` after the HELLO fails |

The title of the page, its server banner, WebSocket path and cookie name are
configurable so the cover story can match the site you are pretending to be.
No response contains the strings "HeduVPN", "VPN", "tunnel" or the PSK.

---

## 10. Limits and timeouts

- Handshake envelopes: ≤ 4096 bytes, 8-second read timeout.
- Records: ciphertext ≤ 131072 bytes; payload ≤ 16384 bytes; padding ≤ 512 bytes.
- Handshake time skew: 120 seconds.
- Gate token lifetime: 120 seconds (default).
- Idle tunnel: PING every 15 seconds from the client; the relay closes a session
  after `idle_timeout` (default 300 s) without traffic.
- Destination connect timeout: 10 seconds (default).
- Session close is graceful on both sides; the WebSocket close frame and TLS
  `close_notify` are sent when possible.

---

## 11. Compatibility notes

- Version 1 is the only version. Unknown versions are rejected, not negotiated.
- New frame types may be added; implementations must ignore unknown types other
  than for logging.
- The WebSocket subprotocol is deliberately *not* negotiated, matching ordinary
  WebSocket apps.
- Nothing in the protocol is tied to a particular port, domain or certificate
  authority. Port 443 and a public DNS name are operational choices.
