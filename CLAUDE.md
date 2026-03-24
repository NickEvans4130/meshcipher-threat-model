# MeshCipher Threat Model

You are working on a formal security threat model for MeshCipher — a multi-transport encrypted messaging application. This project lives at `/home/sirey/Desktop/MeshCipher-Threat-Model`. The main MeshCipher codebase is at `/home/sirey/Desktop/MeshCipher` and its documentation at `/home/sirey/Desktop/MeshCipher/docs` — treat both as read-only reference material.

## Your first task

Before writing anything, explore the reference material:

1. Walk `/home/sirey/Desktop/MeshCipher` and build a mental map of the architecture — transport implementations, encryption manager, relay server config, linked device enrolment, and any existing security notes.
2. Check `/home/sirey/Desktop/MeshCipher/docs` for architecture docs, design decisions, and any prior threat notes.
3. Then scaffold the threat model repo structure below and begin populating it, starting with `00-overview.md` and the DFDs.

---

## About MeshCipher

MeshCipher is a privacy-first, offline-capable encrypted messenger with the following architecture:

**Transport layers (all carrying Signal Protocol E2E encryption):**
- Internet relay via Oracle Cloud Free Tier relay server (the one centralised component)
- Bluetooth Low Energy mesh — multi-hop, TTL-limited, flood/route hybrid
- WiFi Direct — medium-range P2P
- TOR — P2P hidden service (.onion) mode using Ed25519 keypairs; SOCKS5 proxy on localhost:9050 for relay traffic
- Reticulum/LoRa — planned future transport

**Clients:**
- Android (primary)
- Compose Desktop (Linux/Mac/Windows)

**Key security mechanisms:**
- Signal Protocol: Double Ratchet + X3DH key agreement, perfect forward secrecy, post-compromise security, deniable authentication
- Safety numbers (60-digit codes) for TOFU identity verification, QR scanning
- Linked devices via QR code enrolment — cross-device key sync
- System tray integration and TOR status indicator on desktop

**Roadmap security items (not yet implemented — treat as known gaps):**
- Post-quantum cryptography: CRYSTALS-Kyber (hybrid ECDH+Kyber, following PQXDH pattern)
- MLS protocol for group messaging
- Meshtastic/LoRa transport (Phase 10)
- ATAK plugin (Phase 11)

---

## Repo structure to create

```
/home/sirey/Desktop/MeshCipher-Threat-Model/
├── CLAUDE.md                    ← this file (copy it here so future sessions have context)
├── README.md                    ← project overview and methodology summary
├── 00-overview.md               ← system description, scope, assumptions, out-of-scope
├── 01-data-flow-diagrams/
│   ├── dfd-system-overview.md   ← top-level DFD (Level 0)
│   ├── dfd-bluetooth-mesh.md    ← BLE mesh transport detail
│   ├── dfd-wifi-direct.md
│   ├── dfd-tor.md               ← both relay-via-TOR and P2P hidden service modes
│   ├── dfd-relay-server.md      ← Oracle Cloud relay — the centralised trust boundary
│   └── dfd-linked-devices.md    ← QR enrolment and cross-device key sync flow
├── 02-trust-boundaries.md       ← explicit enumeration of every trust boundary
├── 03-stride-analysis/
│   ├── stride-signal-protocol.md
│   ├── stride-bluetooth-mesh.md
│   ├── stride-relay-server.md
│   ├── stride-tor-transport.md
│   ├── stride-wifi-direct.md
│   └── stride-linked-devices.md
├── 04-attack-trees/
│   ├── at-ble-metadata-leakage.md
│   ├── at-relay-server-compromise.md
│   ├── at-linked-device-enrolment.md
│   └── at-mesh-relay-traffic-analysis.md
├── 05-mitigations.md            ← existing controls mapped to threats + gap analysis
├── 06-risk-register.md          ← likelihood × impact, owner, status, CVSS where applicable
└── 07-security-roadmap.md       ← connect threat findings to PQC/MLS/Reticulum roadmap items
```

All diagrams should be Mermaid blocks so they render in Obsidian and GitHub.

---

## Methodology

Use **STRIDE per component**, applied at each trust boundary (not system-wide). For each threat:
- Assign a STRIDE category
- Describe the attack scenario concretely (not abstractly)
- Note whether Signal Protocol encryption mitigates it, partially mitigates it, or doesn't apply (many threats are metadata/transport-layer, not content-layer)
- Rate likelihood (Low/Medium/High) and impact (Low/Medium/High)
- Identify the mitigation status: Mitigated / Partially mitigated / Gap / Accepted risk

Use **attack trees** (Mermaid flowcharts, attacker-goal at root) for the four priority threats:
1. BLE metadata leakage / presence tracking
2. Relay server compromise (metadata exposure, availability)
3. Linked device enrolment attack (QR intercept, replay)
4. Mesh relay node traffic analysis (routing metadata, timing)

---

## Priority threats to investigate first

Based on the architecture, these are the highest-risk areas — start here before doing exhaustive STRIDE on every component:

**1. BLE advertising metadata leakage**
The mesh advertising model means any nearby device passively observes: your presence, timing patterns, device ID, and peer graph — without breaking Signal encryption. For MeshCipher's target users (activists, journalists) this is a critical OPSEC concern. Investigate: what is broadcast in BLE advertisements? Is the device/user ID rotated? Can an adversary build a social graph from passive BLE scanning?

**2. Relay server as centralised metadata sink**
The Oracle Cloud relay is the only centralised component. It cannot read message content (Signal E2E), but it sees: who connects, when, from what IP, and connection duration. Model the relay operator as a potential adversary. Also model relay availability as a DoS target.

**3. QR-based linked device enrolment**
The device linking flow is a high-value attack window — it's the moment when key material is transferred. Questions: Is the QR code one-time-use? Is there a replay window? What happens if a QR is photographed mid-enrolment? Is the enrolment channel itself encrypted/authenticated?

**4. Mesh relay node compromise**
A compromised device acting as a relay hop cannot decrypt Signal content, but can observe: source/destination device IDs, message size, timing, hop count, and routing table entries. Model a Sybil attack where an adversary operates multiple relay nodes to improve traffic analysis coverage.

**5. Post-quantum gap (harvest now, decrypt later)**
The current classical-only posture (X25519 + AES) is vulnerable to a HNDL adversary capturing ciphertext today for future quantum decryption. Document this as a formal known gap with a target remediation milestone (CRYSTALS-Kyber integration, following PQXDH pattern as Signal has done).

---

## Output conventions

- All files: Markdown, Obsidian-compatible (Mermaid renders natively)
- STRIDE tables: use markdown tables with columns: Threat ID | Category | Component | Attack Scenario | Signal Protocol mitigates? | Likelihood | Impact | Status
- Risk register: add a CVSS v3.1 base score where a realistic CVE analogue exists
- Attack trees: Mermaid `flowchart TD` with attacker goal at root, AND/OR nodes labelled
- Reference specific files from `/home/sirey/Desktop/MeshCipher` when making claims about implementation — don't assume; verify in the code

---

## Git

The repo is already initialised at `git@github.com:NickEvans4130/meshcipher-threat-model.git`. After completing each major section, commit with a descriptive message following the pattern:

```
docs(stride): add BLE mesh STRIDE analysis — 6 threats identified
docs(dfd): add Level 0 system DFD and relay server detail
docs(attack-tree): add QR enrolment attack tree
```

Push after each logical chunk of work.

---

## Session continuity

This CLAUDE.md file is the source of truth for future sessions. At the start of any new session on this project, re-read this file and the current state of the repo before doing anything. Update this file if the scope, architecture, or methodology changes significantly.
