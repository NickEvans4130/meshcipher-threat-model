# 06 — Risk Register

Likelihood and impact ratings:
- **Likelihood:** Low (unlikely given the threat actor capability required), Medium (feasible for a motivated adversary), High (routinely exploitable with commodity tools)
- **Impact:** Low (limited harm), Medium (significant operational harm), High (severe harm to target user's safety or security), Critical (identity compromise or RCE)

CVSS v3.1 base scores are provided where a realistic CVE analogue exists. Scores use the standard vector format.

---

## Risk Register

| Risk ID | Threat IDs | Title | Likelihood | Impact | Risk Level | CVSS v3.1 | Gap Ref | Owner | Status |
|---------|-----------|-------|------------|--------|------------|-----------|---------|-------|--------|
| R-01 | BLE-I-01, BLE-I-04 | BLE stable identifier enables passive presence tracking and social graph construction | High | High | **Critical** | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 6.5 | GAP-01 | — | Open |
| R-02 | BLE-I-02, BLE-I-03, at-mesh | MeshMessage plaintext routing headers expose sender, recipient, and full relay path to every hop | High | High | **Critical** | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 6.5 | GAP-02 | — | Open |
| R-03 | REL-I-01, REL-I-02, REL-I-03 | Relay server communication graph and IP logging accessible to operator and under legal compulsion | High | High | **Critical** | AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N — 6.8 (operator) | — | relay operator | Accepted (architectural) |
| R-04 | REL-T-02 | No certificate pinning allows TLS MITM by rogue CA | Low | Medium | Medium | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N — 6.5 | GAP-03 | — | Open |
| R-05 | REL-S-01, REL-T-03 | HS256 JWT secret — relay compromise yields full token forgery | Low | High | High | AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H — 8.0 | GAP-04 | — | Open |
| R-06 | LNK-S-02, LNK-I-02 | QR code photograph enables rogue linked device registration (metadata oracle) | Medium | High | **Critical** | AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N — 6.1 | GAP-05, GAP-06 | — | Open |
| R-07 | WFD-T-01, WFD-E-01 | Java deserialization on WiFi Direct TCP socket — potential RCE from malicious peer | Low | Critical | High | AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H — 8.3 | GAP-07 | — | Open |
| R-08 | SIG-S-01, SIG-S-02 | TOFU without verification — unverified sessions vulnerable to Signal MITM | Medium | Critical | **Critical** | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N — 6.8 | — (UX gap) | — | Open |
| R-09 | All transports (HNDL) | Post-quantum gap — X25519 sessions vulnerable to harvest-now-decrypt-later | Medium | High | High | Not directly CVSSable (future threat) | GAP-08 | — | Open (roadmap) |
| R-10 | TOR-I-01 | Persistent .onion address enables online presence probing | Medium | Medium | Medium | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 5.3 | GAP-10 | — | Open |
| R-11 | TOR-D-03 | No Tor bridge support — Tor transports fail under censorship | Medium | High | High | — | GAP-09 | — | Open (roadmap) |
| R-12 | TOR-S-02 | Fake SOCKS5 on localhost:9050 if Orbot not running | Low | High | Medium | AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N — 4.7 | — | — | Open |
| R-13 | REL-D-04 | Single relay instance — no HA; outage disables all internet transport | Medium | High | High | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 7.5 | — | relay operator | Accepted (Free Tier constraint) |
| R-14 | BLE-D-01 | GATT server flooding — no per-peer rate limiting | Medium | Medium | Medium | AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 6.5 | — | — | Open |
| R-15 | SIG-I-01, SIG-D-01 | Pre-key exhaustion — one-time pre-key depletion weakens session establishment | Medium | Medium | Medium | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L — 5.3 | — | — | Open |
| R-16 | LNK-E-01 | Desktop linked device uses software key (no hardware TEE) | Medium | High | High | AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N — 6.3 | — | — | Accepted (platform constraint) |
| R-17 | REL-I-04 | No message size padding — size oracle at relay and mesh | High | Low | Medium | AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N — 2.7 | — | — | Accepted |

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

### 1. R-01 / R-02 — BLE Metadata Leakage (Critical)

The combination of stable BLE identifiers (R-01) and plaintext routing headers in MeshMessage (R-02) creates a comprehensive presence-and-communications monitoring capability for any adversary within BLE range. This is the highest-severity finding for MeshCipher's target user base. No cryptographic capability is required — commodity hardware and a logging app suffice.

**Remediation:** GAP-01 (identifier rotation), GAP-02 (routing header encryption or path field removal).

### 2. R-08 — TOFU Without Verification (Critical)

Signal Protocol's security guarantees are conditional on safety number verification. Users who never verify are fully vulnerable to a Signal-layer MITM. For first-time contacts, there is no way to distinguish a legitimate session from an intercepted one without the verification ceremony.

**Remediation:** UX changes to promote verification; automatic warning for unverified high-frequency contacts; QR-based verification flow improvement.

### 3. R-06 — QR Photograph Enables Rogue Linked Device (Critical)

A low-sophistication opportunistic attack that yields a persistent metadata oracle. The attack window exists as long as the QR is displayed (potentially indefinitely, as there is no timeout). Affects the most security-sensitive users who are most likely to use the linked device feature with operational equipment.

**Remediation:** GAP-05 (one-time-use nonce), GAP-06 (desktop confirmation step).

### 4. R-03 — Relay Server as Metadata Sink (Critical, Accepted Architectural)

The relay operator's visibility into the communication graph is an architectural property. Addressed by: Tor relay mode (opt-in), data retention minimisation, moving users toward P2P transports (P2P Tor, BLE mesh) where the relay has no involvement.

**Remediation:** Partial — Tor relay mode, message retention policy, relay data minimisation.

### 5. R-09 — Post-Quantum HNDL Gap (High, Roadmap)

Ciphertext captured today may be decrypted by a quantum adversary in the future. The risk is increasing as quantum computing hardware advances. MeshCipher's target users (journalists, activists) may generate communications whose long-term confidentiality is important. Kyber pre-key infrastructure is already partially stubbed in the codebase.

**Remediation:** GAP-08 (CRYSTALS-Kyber / PQXDH integration).
