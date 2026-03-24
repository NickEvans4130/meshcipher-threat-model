# STRIDE Analysis — Tor Transport (Relay-via-Tor + P2P Hidden Service)

## Component Description

Two Tor-based transport modes:

1. **Relay-via-Tor** — OkHttp configured with `Proxy(SOCKS, localhost:9050)` via Orbot. Hides sender IP from relay server. Relay still processes message metadata.
2. **P2P Tor hidden service** — Embedded Tor daemon (Guardian Project `tor-android`). Persistent ED25519-V3 hidden service. Both endpoints are `.onion` addresses. No relay involved.

**References:** `app/.../tor/EmbeddedTorManager.kt`, `app/.../tor/HiddenServiceServer.kt`, `app/.../tor/P2PClient.kt`, `docs/p2p_tor.md`

---

## STRIDE Threat Table

| Threat ID | Category | Component | Attack Scenario | Signal Protocol mitigates? | Likelihood | Impact | Status |
|-----------|----------|-----------|-----------------|---------------------------|------------|--------|--------|
| TOR-S-01 | Spoofing | P2P hidden service identity | Two `.onion` addresses are exchanged out-of-band (e.g., via a separate channel or QR code). If the exchange channel is compromised, an adversary substitutes their own `.onion` address. The victim's app connects to the adversary's hidden service. Combined with a Signal MITM (SIG-S-02), this creates a full interception path. | Partially — Safety number verification detects Signal-layer MITM; Tor connection is transparent to app | Low | High | Partially mitigated — safety number verification closes the loop |
| TOR-S-02 | Spoofing | Orbot/local SOCKS5 proxy | A malicious app intercepts connections to `localhost:9050` (e.g., if Orbot is not running and another app binds port 9050). Relay traffic is sent to the adversary's SOCKS5 endpoint instead of the Tor network. | No | Low | High | Gap — no verification that localhost:9050 is Orbot; check for bootstrap success before sending |
| TOR-T-01 | Tampering | P2P Tor message stream | Tor provides transport integrity (Tor cell MACs). Signal Protocol provides end-to-end AEAD. A MITM between Tor exit and relay (relay-via-Tor mode) cannot tamper with Signal content. In P2P mode, no MITM position exists outside the Tor network itself. | Yes — Signal AEAD + Tor cell MAC | Low | Low | Mitigated |
| TOR-T-02 | Tampering | ED25519 hidden service key (EncryptedSharedPreferences) | Attacker with root access modifies the stored ED25519 private key. App generates a new `.onion` address on next Tor bootstrap, breaking existing connections and confusing peers about the device's identity. | No | Low | Medium | Partially mitigated — EncryptedSharedPreferences (AES-256-GCM, Keystore-backed); root required |
| TOR-R-01 | Repudiation | P2P message delivery | No delivery receipt mechanism in the P2P Tor protocol that is verifiable outside the session. Sender cannot prove delivery; recipient can deny receipt. P2PMessage ACK type exists but is application-layer, not a signed receipt. | N/A — deniability is a design property | N/A | N/A | Accepted |
| TOR-I-01 | Information Disclosure | Stable .onion address (long-term pseudonym) | The ED25519 hidden service key is persistent — same `.onion` address on every app restart. Any party who knows the `.onion` address can probe it to determine when the hidden service is online, building a presence timeline. Unlike IP addresses, `.onion` addresses are not tied to physical location, but they are a stable long-term identifier. | No | Medium | Medium | Gap — no key rotation mechanism; key intentionally persistent for usability |
| TOR-I-02 | Information Disclosure | Timing correlation (global passive adversary) | A state-level adversary with visibility into a large fraction of Tor relay bandwidth observes: (1) traffic entering the Tor network from sender's guard node, (2) traffic exiting to recipient's guard node. Statistical timing correlation can deanonymise both parties even with end-to-end Tor encryption. | No — this is a Tor-layer attack | Low | High | Accepted — inherent Tor limitation; beyond MeshCipher's threat model to solve |
| TOR-I-03 | Information Disclosure | Guard node observation | The sender's guard node knows the sender's real IP address and the timing of Tor circuits being established. Does not know destination. Over time, the guard node can correlate traffic volume patterns. | No | Low | Medium | Partially mitigated — Tor guard selection randomisation; guard rotation after ~2-3 months |
| TOR-I-04 | Information Disclosure | Relay-via-Tor: metadata still at relay | When using Tor relay mode, the relay server still observes: sender_id (pseudonymous), recipient_id, message size, timing. Tor only hides the sender's IP. All metadata threats from `stride-relay-server.md` (REL-I-01 through REL-I-04) remain. | No — Tor does not protect relay metadata | High | Medium | Partially mitigated — Tor hides IP (REL-I-02); other relay metadata threats persist |
| TOR-D-01 | Denial of Service | Orbot not available / bootstrap failure | If Orbot is not installed or fails to bootstrap, relay-via-Tor fails and the app may fall back to direct internet relay (exposing sender IP). The app should either block fallback or explicitly warn the user when Tor is unavailable. | No | Medium | Medium | Gap — fallback behaviour under Tor failure needs explicit UX treatment |
| TOR-D-02 | Denial of Service | P2P hidden service unreachable | P2P Tor requires both devices to have running Tor daemons and stable hidden services. If either Tor daemon fails or the network is blocked (censorship), P2P mode fails entirely. No fallback within the P2P Tor transport. | No | Medium | High | Partially mitigated — transport fallback to WiFi Direct or BLE |
| TOR-D-03 | Denial of Service | Tor network censorship | State-level adversary blocks Tor entry nodes (common in some jurisdictions). Disables all Tor-based transports. Users in censored regions must rely on BLE/WiFi Direct for E2E encrypted comms. | No — network-level censorship | Medium | High | Gap — no Tor bridge/pluggable transport support identified in codebase |
| TOR-E-01 | Elevation of Privilege | ED25519 key extraction | Attacker with root access extracts ED25519 hidden service private key from EncryptedSharedPreferences. Can stand up a fake hidden service at the same `.onion` address (only one active at a time — fork attack). Existing connections from peers would need to be re-established to the attacker's service. | No | Low | High | Partially mitigated — EncryptedSharedPreferences; root required |

---

## Key Observations

**The persistent `.onion` address is a deliberate usability trade-off** — users need a stable address to share out-of-band with contacts. The privacy cost is a stable long-term pseudonym that can be probed for online presence. An opt-in ephemeral mode (new key per session) would improve privacy for high-risk sessions at the cost of contact management complexity.

**TOR-S-02 (fake SOCKS5 on :9050)** is a subtle but realistic risk on uncontrolled Android devices where multiple apps may compete for the port, or where Orbot is not running. The app should verify Tor bootstrap status before sending sensitive traffic through the proxy.

**No Tor bridge support** means the entire Tor transport fails in censored environments. Integrating `obfs4` or similar pluggable transports would significantly improve usability in high-censorship environments — directly relevant for MeshCipher's target user base.
