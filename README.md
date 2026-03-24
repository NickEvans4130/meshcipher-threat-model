# MeshCipher Threat Model

Formal security threat model for [MeshCipher](https://github.com/NickEvans4130/MeshCipher) — a multi-transport encrypted messaging application targeting privacy-sensitive users (journalists, activists, first responders).

## Scope

This document set covers the **MeshCipher v1.x** architecture as implemented at `/home/sirey/Desktop/MeshCipher` (commit reference: initial codebase exploration, March 2026). It does **not** cover planned roadmap items (post-quantum cryptography, MLS group messaging, LoRa/Meshtastic transport, ATAK plugin) except where they represent known gaps in the current posture.

## Methodology

**STRIDE per component** applied at every trust boundary crossing. For each threat:

- Unique Threat ID (e.g. `BLE-S-01`)
- STRIDE category: Spoofing / Tampering / Repudiation / Information Disclosure / Denial of Service / Elevation of Privilege
- Concrete attack scenario (not abstract)
- Signal Protocol mitigation status: Mitigated / Partially mitigated / Not applicable
- Likelihood: Low / Medium / High
- Impact: Low / Medium / High
- Status: Mitigated / Partially mitigated / Gap / Accepted risk

**Attack trees** (Mermaid flowcharts) for the four highest-priority threats, with AND/OR decomposition and attacker goal at root.

**Risk register** with CVSS v3.1 base scores where a realistic CVE analogue exists.

## Document Map

| File | Contents |
|------|----------|
| `00-overview.md` | System description, scope, assets, assumptions, out-of-scope |
| `01-data-flow-diagrams/` | Mermaid DFDs at system level and per transport |
| `02-trust-boundaries.md` | Enumeration of all trust boundaries |
| `03-stride-analysis/` | Per-component STRIDE tables |
| `04-attack-trees/` | Attack trees for priority threats |
| `05-mitigations.md` | Existing controls mapped to threats + gap analysis |
| `06-risk-register.md` | Likelihood x impact matrix, CVSS scores, owners |
| `07-security-roadmap.md` | Threat findings mapped to PQC/MLS/LoRa roadmap |

## Priority Threats

Highest-risk areas by architectural analysis:

1. **BLE advertising metadata leakage** — stable device/user ID hashes broadcast passively; enables presence tracking and social graph construction without breaking Signal encryption
2. **Relay server as metadata sink** — the only centralised component; operator sees connection graph, timing, and message sizes even though content is E2E encrypted
3. **QR-based linked device enrolment** — key material transfer window; no one-time-use enforcement; no binding to specific scanning device
4. **Mesh relay node traffic analysis** — compromised hop node observes routing metadata, timing, and hop counts; Sybil attack extends coverage
5. **Post-quantum gap (harvest-now-decrypt-later)** — classical-only X25519 + AES posture; ciphertext captured today is vulnerable to future quantum decryption

## Reference Material

All claims about implementation are grounded in source code. Key reference paths:

- Transport: `app/src/main/java/com/meshcipher/data/bluetooth/`, `…/wifidirect/`, `…/tor/`, `…/transport/`
- Crypto: `app/src/main/java/com/meshcipher/data/encryption/SignalProtocolManager.kt`
- Identity: `app/src/main/java/com/meshcipher/data/identity/IdentityManager.kt`
- Device linking: `app/src/main/java/com/meshcipher/presentation/linking/`, `desktopApp/…/DeviceLinkManager.kt`
- Relay: `relay-server/server.py`
- Docs: `docs/architecture.md`, `docs/cryptography.md`, `docs/networking.md`, `docs/bluetooth_mesh.md`, `docs/p2p_tor.md`
- Security: `SECURITY_AUDIT_GUIDE.md`, `SECURITY.md`
