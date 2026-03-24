# STRIDE Analysis — Oracle Cloud Relay Server

## Component Description

The relay server is the sole centralised component — a Flask/Python application deployed on Oracle Cloud Free Tier. It provides:
- **Store-and-forward** message queuing for asynchronous delivery
- **WebSocket push** for real-time delivery
- **ECDSA challenge-response authentication** → JWT issuance
- **Device registration** — stores userId ↔ publicKey ↔ device metadata

The relay **cannot** decrypt message content (Signal E2E), but it has full visibility into the communication metadata graph. The relay operator is explicitly modelled as a potential adversary.

**References:** `relay-server/server.py`, `app/.../transport/InternetTransport.kt`, `docs/networking.md`

---

## STRIDE Threat Table

| Threat ID | Category | Component | Attack Scenario | Signal Protocol mitigates? | Likelihood | Impact | Status |
|-----------|----------|-----------|-----------------|---------------------------|------------|--------|--------|
| REL-S-01 | Spoofing | JWT authentication | Attacker who has exfiltrated the HS256 JWT signing secret (from relay server environment) forges valid JWTs for any userId. Can impersonate arbitrary users at the relay level — fetch their queued messages, send messages appearing to originate from them. | No — JWT is relay-layer; Signal sessions are unaffected, but messages will be attributed to the wrong userId at the relay | Low | High | Gap — HS256 symmetric secret; compromise of relay = compromise of all auth |
| REL-S-02 | Spoofing | Device registration | Adversary registers a new device with a chosen userId and their own public key. The relay has no mechanism to verify that a userId is "claimed" by a specific key — any key can claim any userId on first registration. Target user's relay mailbox is unaffected (different recipient_id), but the registration pollutes the device table. | No | Medium | Low | Accepted — relay IDs are pseudonymous; no user-facing name binding at relay |
| REL-S-03 | Spoofing | Sender_id field | Sender_id in `POST /relay/message` is validated against the JWT's user_id claim. However, if REL-S-01 is realised (JWT forgery), attacker can set arbitrary sender_id to forge message origin at the relay level. Signal session will reject or flag the message at the application layer. | Partially — Signal sessions include sender identity binding; forged relay sender_id would mismatch Signal sender identity | Low | Medium | Partially mitigated — Signal catches at application layer |
| REL-T-01 | Tampering | Queued message content | Relay operator with DB access could modify `encrypted_content` field in the `QueuedMessage` table. Signal Protocol AEAD (AES-GCM) will detect tampering on decryption — the recipient's app will receive a MAC verification failure, not silently accept tampered content. | Yes — AEAD detects tampering | Low | Low | Mitigated — Signal AEAD |
| REL-T-02 | Tampering | TLS MITM (no certificate pinning) | Adversary with access to a trusted CA (corporate proxy, state-level actor) issues a certificate for the relay domain. MITM proxy intercepts the HTTPS connection. Can observe cleartext HTTP request/response — sender_id, recipient_id, encrypted_content (though Signal-encrypted), timestamps. Cannot decrypt Signal payload. | No — TLS MITM exposes relay-layer metadata; Signal still protects content | Low | Medium | Gap — no certificate pinning (`SECURITY_AUDIT_GUIDE.md` notes this) |
| REL-T-03 | Tampering | JWT expiry manipulation | Relay server validates JWT expiry (`exp` claim). If HS256 secret is known, attacker can issue a non-expiring JWT. Requires REL-S-01 precondition. | No | Low | Medium | Gap — depends on REL-S-01 |
| REL-R-01 | Repudiation | Message delivery | Relay logs delivery events (`delivered`, `delivered_at`). An adversary who can access the DB can modify these fields to deny delivery confirmation or fabricate it. | No | Low | Low | Accepted — relay delivery confirmation is best-effort |
| REL-R-02 | Repudiation | Relay operator action | Relay operator can silently drop messages, modify delivery timestamps, or suppress WebSocket pushes without any cryptographic audit trail that the client can detect. | No — relay is semi-trusted for availability | Medium | Medium | Accepted — operator trust is foundational assumption |
| REL-I-01 | Information Disclosure | Communication graph (metadata) | Relay operator observes: sender_id ↔ recipient_id pairs for every message, timestamps, message sizes, content types. Over time this reveals: who communicates with whom, at what frequency, at what times, for how long. For MeshCipher's target users this is a high-impact threat. | No — E2E protects content only | High | High | Gap — metadata minimisation not implemented; no padding, no dummy traffic |
| REL-I-02 | Information Disclosure | IP address logging | Every HTTPS/WSS request from a non-Tor client reveals the sender's IP address. The relay logs this (standard HTTP access logs). IP → geolocation, ISP, identity correlation with other services. | No | High | High | Partially mitigated — Tor relay mode hides sender IP; default mode exposes it |
| REL-I-03 | Information Disclosure | Online presence (WebSocket) | The relay tracks active WebSocket connections in memory. The relay operator knows which users are currently online (connected) at any given moment, and can log connection/disconnection events. | No | High | Medium | Gap — no countermeasure (inherent to push delivery) |
| REL-I-04 | Information Disclosure | Message size as content oracle | Signal AEAD does not pad message sizes. An adversary observing `len(encrypted_content)` at the relay can make inferences about plaintext length (file vs. text, approximate text length). | Partially — encrypts content but not size | High | Low | Gap — no padding |
| REL-I-05 | Information Disclosure | Compelled disclosure (legal) | State actor compels Oracle Cloud or relay operator to produce DB records, access logs, or enable real-time monitoring under legal process. Relay has all metadata enumerated in REL-I-01 to REL-I-04 available for disclosure. | No | Medium | High | Partially mitigated — Tor relay mode reduces IP exposure; metadata graph still available |
| REL-D-01 | Denial of Service | Relay endpoint flooding | Adversary floods `POST /relay/message` endpoint with valid or forged requests, exhausting rate limits or relay capacity. Disrupts message delivery for all users of the relay. Rate limiting at 60/min per IP mitigates single-IP floods but not distributed floods. | No | Medium | High | Partially mitigated — rate limiting; Oracle Cloud DDoS protection (basic) |
| REL-D-02 | Denial of Service | Mailbox flooding (per-recipient) | Adversary floods a specific recipient's mailbox up to the 500-message limit. Legitimate messages are rejected as mailbox full. Targeted DoS against specific user. | No | Medium | Medium | Partially mitigated — 500 message cap; no per-sender rate limit on writes to specific recipient |
| REL-D-03 | Denial of Service | WebSocket exhaustion | Adversary opens many authenticated WebSocket connections, exhausting server file descriptors or connection pool. Disrupts real-time push for all users. | No | Low | Medium | Partially mitigated — rate limiting on auth; connection count limits unclear |
| REL-D-04 | Denial of Service | Relay server availability (single point of failure) | The relay is a single instance on Oracle Cloud Free Tier with no redundancy or failover. Relay downtime forces all internet-mode communication to fail until connectivity is restored. BLE/WiFi Direct/P2P Tor transports are unaffected. | No | Medium | High | Gap — single instance; no HA; no standby relay |
| REL-E-01 | Elevation of Privilege | Server-side code execution via input | Malformed input to relay API endpoints (injection in sender_id, JSON payload fields) could trigger a vulnerability in Flask or the DB layer. If exploited, attacker gains process-level access to the relay VM, including DB and JWT secret. | No | Low | Critical | Partially mitigated — input sanitisation, type checking, max-length validation in `server.py` |

---

## Key Observations

**The relay is a metadata-rich target.** Every message that uses internet transport (the most common transport) contributes to a growing communication graph that is fully accessible to the relay operator and anyone who can compel them. This is an architectural constraint — store-and-forward inherently requires a trusted intermediary for metadata.

**Tor relay mode is the primary mitigation for IP exposure**, but it is opt-in and not the default. Users who do not enable Tor expose their IP on every relay interaction.

**No certificate pinning** is the most operationally significant gap at this boundary — it enables a well-resourced MITM (corporate proxy, state-level CA) to transparently intercept relay traffic with no client-visible indication.

**HS256 for JWT** is a symmetric-key scheme — the relay holds the signing secret. Asymmetric JWTs (RS256/ES256) would allow clients to verify tokens without the relay secret being a single point of failure.

See attack tree: `04-attack-trees/at-relay-server-compromise.md`
