# 06 — Risk Register

Likelihood and impact ratings:
- **Likelihood:** Low (unlikely given the threat actor capability required), Medium (feasible for a motivated adversary), High (routinely exploitable with commodity tools)
- **Impact:** Low (limited harm), Medium (significant operational harm), High (severe harm to target user's safety or security), Critical (identity compromise or RCE)

CVSS v3.1 base scores are provided where a realistic CVE analogue exists. Scores use the standard vector format.

---

## Risk Register

| Risk ID | Threat IDs | Title | Likelihood | Impact | Risk Level | CVSS v3.1 | Gap Ref | Owner | Status | Remediation note |
|---------|-----------|-------|------------|--------|------------|-----------|---------|-------|--------|-----------------|
| R-01 | BLE-I-01, BLE-I-04 | BLE stable identifier enables passive presence tracking and social graph construction | High | High | **Critical** | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 6.5 | GAP-01 | — | Partially mitigated | RM-06: Epoch-based pseudonymous BLE identifiers (HMAC-SHA256, 1-hour rotation). Passive observers cannot track across epochs. Pre-contact beacon contains no user/device identifier. |
| R-02 | BLE-I-02, BLE-I-03, at-mesh | MeshMessage plaintext routing headers expose sender, recipient, and full relay path to every hop | High | High | **Critical** | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 6.5 | GAP-02 | — | Partially mitigated | RM-07 Phase 1: path field removed from MeshMessage. TTL flood routing + UUID dedup (MC-11) handles delivery. Phase 2 routing header encryption remains a gap. |
| R-03 | REL-I-01, REL-I-02, REL-I-03 | Relay server communication graph and IP logging accessible to operator and under legal compulsion | High | High | **Critical** | AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N — 6.8 (operator) | — | relay operator | Accepted (architectural) | — |
| R-04 | REL-T-02 | No certificate pinning allows TLS MITM by rogue CA | Low | Medium | Medium | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N — 6.5 | GAP-03 | — | Mitigated | RM-01: CertificatePinner added to OkHttp in NetworkModule.kt and RelayAuthManager.kt. Production pins pending (CertificatePins.kt TODO). > **Note:** Certificate pins in CertificatePins.kt are placeholder TODOs. Production deployment requires real SPKI hashes before operational use. |
| R-05 | REL-S-01, REL-T-03 | HS256 JWT secret — relay compromise yields full token forgery | Low | High | High | AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H — 8.0 | GAP-04 | — | Mitigated | RM-02: Relay switched to ES256 asymmetric JWT. Private key loaded from JWT_PRIVATE_KEY_PATH. Client verifies via JwtSignatureVerifier.kt. Token expiry 7 days. |
| R-06 | LNK-S-02, LNK-I-02 | QR code photograph enables rogue linked device registration (metadata oracle) | Medium | High | **Critical** | AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N — 6.1 | GAP-05, GAP-06 | — | Mitigated | RM-03 + RM-04: One-time nonce + 5-min timestamp validation. 60-second QR expiry UI. Desktop confirmation dialog (types 18/19/20) with 2-min timeout. approved=false until desktop confirms. |
| R-07 | WFD-T-01, WFD-E-01 | Java deserialization on WiFi Direct TCP socket — potential RCE from malicious peer | Low | Critical | High | AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H — 8.3 | GAP-07 | — | Mitigated | RM-05: ObjectInputStream/ObjectOutputStream replaced with WifiDirectMessageCodec typed binary. 0xACED rejected. 10 MB payload cap before allocation. |
| R-08 | SIG-S-01, SIG-S-02 | TOFU without verification — unverified sessions vulnerable to Signal MITM | Medium | Critical | **Critical** | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N — 6.8 | — (UX gap) | — | Partially mitigated | RM-13: First-message unverified banner; nudge after 10 messages; QR-based safety number verification; verification badge. TOFU on first contact is an inherent limitation. |
| R-09 | All transports (HNDL) | Post-quantum gap — X25519 sessions vulnerable to harvest-now-decrypt-later | Medium | High | High | Not directly CVSSable (future threat) | GAP-08 | — | Mitigated | RM-10: PQXDH hybrid (X25519 + Kyber-1024). Session key = KDF(X25519_output \|\| Kyber_KEM_output). Backwards-compatible fallback to classical X3DH for older clients. |
| R-10 | TOR-I-01 | Persistent .onion address enables online presence probing | Medium | Medium | Medium | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 5.3 | GAP-10 | — | Mitigated | RM-14: Opt-in ephemeral .onion mode — new ED25519 key per session (memory-only). Contacts notified via signed OnionAddressUpdate. Persistent mode default unchanged. |
| R-11 | TOR-D-03 | No Tor bridge support — Tor transports fail under censorship | Medium | High | High | — | GAP-09 | — | Mitigated | RM-11: obfs4 pluggable transport via tor-android. Bridge config UI with manual entry, torproject.org fetch, and test capability. |
| R-12 | TOR-S-02 | Fake SOCKS5 on localhost:9050 if Orbot not running | Low | High | Medium | AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N — 4.7 | — | — | Mitigated | RM-08: TorBootstrapVerifier checks Orbot installed, bootstrap at 100%, PID on port 9050 is Orbot. Send blocked with explicit error if any check fails. |
| R-13 | REL-D-04 | Single relay instance — no HA; outage disables all internet transport | Medium | High | High | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 7.5 | — | relay operator | Partially mitigated | RM-12: RelayHealthMonitor (60s polling). Smart Mode degrades to P2P Tor then BLE then WiFi Direct after 3 failures. User-visible relay status. Message queue 500 cap FIFO. Single-instance relay remains architectural. |
| R-14 | BLE-D-01 | GATT server flooding — no per-peer rate limiting | Medium | Medium | Medium | AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 6.5 | — | — | Mitigated | RM-09: Per-connection GATT rate limiting — 10 messages per 5-second window. Excess triggers disconnect + 5-minute blocklist. |
| R-15 | SIG-I-01, SIG-D-01 | Pre-key exhaustion — one-time pre-key depletion weakens session establishment | Medium | Medium | Medium | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L — 5.3 | — | — | Open | — |
| R-16 | LNK-E-01 | Desktop linked device uses software key (no hardware TEE) | Medium | High | High | AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N — 6.3 | — | — | Accepted (platform constraint) | — |
| R-17 | REL-I-04 | No message size padding — size oracle at relay and mesh | High | Low | Medium | AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N — 2.7 | — | — | Accepted | — |

---

## Priority Matrix

```mermaid
quadrantChart
    title Risk Priority Matrix (Likelihood vs Impact)
    x-axis Low Likelihood --> High Likelihood
    y-axis Low Impact --> High Impact
    quadrant-1 Monitor
    quadrant-2 Address Soon
    quadrant-3 Low Priority
    quadrant-4 Immediate Action
    R-01 BLE Presence Tracking: [0.85, 0.85]
    R-02 Mesh Routing Headers: [0.85, 0.80]
    R-03 Relay Metadata (Arch): [0.80, 0.80]
    R-08 TOFU MITM: [0.50, 0.90]
    R-06 QR Photograph: [0.50, 0.80]
    R-09 HNDL PQC Gap: [0.45, 0.75]
    R-05 HS256 JWT: [0.25, 0.80]
    R-07 Java Deserialization: [0.20, 0.95]
    R-11 Tor Censorship: [0.50, 0.70]
    R-13 Relay SPOF: [0.50, 0.70]
    R-04 No Cert Pinning: [0.25, 0.55]
    R-16 Desktop Soft Key: [0.45, 0.70]
    R-10 Stable Onion: [0.50, 0.50]
    R-14 GATT Flooding: [0.50, 0.45]
    R-15 Pre-key Exhaustion: [0.50, 0.45]
    R-12 Fake SOCKS5: [0.20, 0.70]
    R-17 Size Oracle: [0.85, 0.20]
```

---

## Top 5 Risks by Priority

### 1. R-01 / R-02 — BLE Metadata Leakage (Partially mitigated)

The combination of stable BLE identifiers (R-01) and plaintext routing headers in MeshMessage (R-02) originally created a comprehensive presence-and-communications monitoring capability for any adversary within BLE range.

**R-01 (Partially mitigated):** RM-06 introduced epoch-based pseudonymous BLE identifiers (HMAC-SHA256, 1-hour rotation). Passive scanners can no longer build a stable presence timeline across epochs. Residual risk: adversaries with multiple scanners can correlate rotated identifiers via timing and RSSI within a single epoch.

**R-02 (Partially mitigated):** RM-07 Phase 1 removed the `path` field from MeshMessage, eliminating routing path reconstruction by relay nodes. Residual risk: `originDeviceId`, `originUserId`, and `destinationUserId` remain plaintext. Phase 2 routing header encryption is an open item — see Remaining Open Items in `07-security-roadmap.md`.

### 2. R-08 — TOFU Without Verification (Partially mitigated)

Signal Protocol's security guarantees are conditional on safety number verification. RM-13 introduced first-message banners, a nudge after 10 messages, QR-based safety number comparison, and a contact-list verification badge. TOFU on first contact remains an inherent limitation — there is no way to distinguish a legitimate session from an intercepted one until the verification ceremony is completed.

### 3. R-06 — QR Photograph Enables Rogue Linked Device (Mitigated)

Previously a low-sophistication opportunistic attack. RM-03 and RM-04 closed the gap: one-time nonce (consumed via relay endpoint, 409 on replay), 5-minute timestamp validation, 60-second QR auto-dismiss, and a mandatory desktop confirmation dialog before `approved=true` is set. A photographed QR is now unusable after first scan or expiry.

### 4. R-03 — Relay Server as Metadata Sink (Accepted architectural)

The relay operator's visibility into the communication graph remains an architectural property. Addressed by: Tor relay mode (opt-in), Smart Mode relay fallback (RM-12), moving users toward P2P transports. The communication graph and timing metadata are structurally unavoidable while store-and-forward relay is in use.

### 5. R-09 — Post-Quantum HNDL Gap (Mitigated)

RM-10 implemented PQXDH hybrid key agreement (X25519 + Kyber-1024). Session keys are now `KDF(X25519_output || Kyber_KEM_output)`. Ciphertext captured today requires breaking both X25519 and Kyber-1024 simultaneously to decrypt. Sessions with older clients fall back to classical X3DH and are logged as a warning.
