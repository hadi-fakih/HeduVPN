# Threat model

HeduVPN is built for one job: keeping a usable TCP tunnel open on a network that
tries to find and block VPNs, while giving a network observer as little to work
with as possible. This document describes what it defends against, how, and what
it cannot do.

## Assets

- The **PSK** in the connection link, which authenticates clients and gates the
  WebSocket endpoint.
- The **relay's private key** (when the relay terminates TLS) and the
  certificate pin distributed in links.
- **Session keys** derived per connection.
- The **content** of tunneled streams and the **destination hostnames/addresses**.
- Availability of the relay on the client's network.

## Adversaries

1. **DPI middlebox / national firewall.** Can inspect packet headers, TLS
   ClientHello SNI/ALPN/JA3, block IPs, ports and protocols, and inject RSTs.
2. **Active prober.** Can connect to the relay from arbitrary addresses and send
   HTTP requests, malformed TLS, WebSocket upgrades, and handshakes with guessed
   keys, looking for a distinguishable response.
3. **On-path observer.** Can capture and replay traffic, including full TLS
   sessions (but cannot break TLS 1.3).
4. **Malicious network operator / MITM.** Can present any certificate.
5. **Abusive client.** Someone holding a link could try to scan private networks
   or send spam through the relay.

## Defences

| Threat | Defence |
| --- | --- |
| Protocol/port blocking | TLS 1.3 on 443 with ALPN `http/1.1`; no WireGuard/OpenVPN/PPTP fingerprint; WebSocket or length-prefixed records look like ordinary HTTPS application data. |
| SNI blocking | Operator-chosen domain, real certificate, decoy website at `/`; no vendor-specific hostname pattern. |
| Active probing | Generic decoy pages, nginx-style 404/400, gate cookie required for `/ws`, decoy 400 for bad handshakes, identical close behaviour for junk and failed auth. |
| Handshake replay | Timestamp (±120 s) and 16-byte client nonce, plus a replay cache in the relay. ACKs are bound to the client nonce as AEAD AAD. |
| Record replay/reordering | Directional keys, per-direction counters and AEAD over the length field. |
| MITM / rogue CA | Certificate pin in the link, checked after the TLS handshake; pin mismatch closes the connection. No `--insecure` default. |
| Size analysis | AEAD hidden padding (`random` or `cells`), so outer record lengths do not track plaintext lengths exactly. |
| Timing analysis | Optional jitter on small records, cover traffic while idle, session rotation. |
| Credential leakage via HTTP | The link uses a URI fragment; PSK is never sent in an HTTP request. |
| Link theft by a network attacker | TLS protects the link in transit; share it over an authenticated channel anyway. |
| Relay abuse as a scanner/proxy | Destination policy: loopback/RFC1918/link-local blocked unless `allow_private`; SMTP ports blocked by default; optional port allowlist and host denylist; per-session stream cap. |

## Non-goals and residual risks

- **IP blocking.** A censor that blocks the relay's address wins. Mitigations are
  operational: fresh addresses, a different provider/ASN, or a CDN that forwards
  WebSocket upgrades.
- **Blanket allowlisting.** If only a handful of services are reachable, no
  general-purpose tunnel can help.
- **TLS fingerprint mismatch.** Python/OpenSSL's ClientHello is consistent but not
  identical to a browser's. JA3/JA4 fingerprinting can distinguish it from Chrome.
  Terminating TLS at nginx or Caddy only changes the *server* fingerprint that an
  active prober sees; the client's ClientHello still comes from Python. Native TLS
  mode avoids WebSocket-specific patterns but uses the same client stack. A
  browser-shaped client or TLS front end is future work.
- **Statistical traffic analysis.** Padding and cover traffic raise the cost of
  size/timing classifiers; they do not defeat a well-trained classifier with
  long-term flow records. There is no constant-rate mode.
- **PSK compromise and forward secrecy.** Session keys are derived from the PSK
  and two nonces. An adversary who records handshakes and later obtains the PSK
  can derive those session keys. There is no independent Diffie-Hellman exchange
  in v1. Rotate the PSK and issue a new relay identity if it may have leaked.
- **Endpoint security.** Malware, keyloggers or a compromised OS defeat any VPN.
  Keys are files with mode 0600; the link is a bearer credential.
- **UDP, ICMP and non-TCP traffic.** Not carried.
- **Anonymity.** The relay sees the destination of every stream (by design — it
  is a VPN) and can log it. Run your own relay if you do not trust the operator.
  HeduVPN does not claim to provide Tor-style anonymity.
- **Dashboard exposure.** The dashboard has no authentication. Keep it on
  loopback or behind an authenticated tunnel/reverse proxy.

## Operational recommendations

- Terminate TLS at a mainstream web server (nginx/Caddy) on 443 and run the relay
  on loopback (`--plaintext`). This inherits the web server's fingerprint and
  keeps the tunnel process unprivileged.
- Use a domain you control with a plausible cover site. The decoy page title and
  server banner are configurable; make them match the site's real content.
- Put nginx/Caddy in front (plaintext relay on loopback) so active scanners see a
  mainstream web-server handshake and certificate rather than Python's.
- Keep `--allow-private` off in production.
- Rotate the PSK if a device is lost; there is no per-device key management in v1.
- Watch probe counters and auth-failure logs. A burst of 404s/400s from one
  address is someone scanning.
- Keep the relay, Python and `cryptography` patched. Rebuild links after rotating
  certificates or keys.

## Verification

The security-relevant behaviours above are covered by the test-suite: handshake
authentication and replay, record tampering, padding modes, pin mismatch, gate
tokens, decoy responses, private-destination policy, CONNECT/SOCKS handling and
end-to-end tunnels over both transports. The protocol is documented in
`docs/protocol.md`; independent review is welcome.
