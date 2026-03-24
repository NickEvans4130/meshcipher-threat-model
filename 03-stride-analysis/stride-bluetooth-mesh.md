# STRIDE Analysis — Bluetooth LE Mesh Transport

## Component Description

The BLE mesh transport provides multi-hop offline message delivery. Key components:
- **`BluetoothMeshManager`** — controls scanning, advertising, peer discovery, and message routing
- **`AdvertisementData`** — 130-byte advertisement packet broadcast continuously
- **`GattServerManager`** / **`GattClientManager`** — GATT-based message transfer between peers
- **`MeshMessage`** — binary message format including routing metadata (path, TTL, hop count)

**Critical characteristics:** Advertisements are passively observable by any BLE scanner. SHA-256 hashes of deviceId and userId are **stable** — the same hash is broadcast on every advertisement. The `path` field in MeshMessage is plaintext and accumulates every relay node's deviceId.

**References:** `app/.../bluetooth/BluetoothMeshManager.kt`, `app/.../bluetooth/AdvertisementData.kt`, `docs/bluetooth_mesh.md`

---

## STRIDE Threat Table

| Threat ID | Category | Component | Attack Scenario | Signal Protocol mitigates? | Likelihood | Impact | Status |
|-----------|----------|-----------|-----------------|---------------------------|------------|--------|--------|
| BLE-S-01 | Spoofing | BLE advertisement | Adversary spoofs SHA-256(deviceId) in a BLE advertisement to impersonate a known device, causing nearby nodes to add the fake device to their neighbor table and potentially route messages through it. Advertisement ECDSA signature should prevent this — but only if recipients verify the signature before acting on the advertisement. | Partially — ECDSA signature present; depends on verification | Low | Medium | Partially mitigated — ECDSA signature in advertisement; verification enforcement unclear |
| BLE-S-02 | Spoofing | GATT relay node | Adversary-controlled device acts as a legitimate relay node (no attestation required). It can relay messages normally while logging all routing metadata. Indistinguishable from honest node. | No | High | Medium | Gap — no relay node attestation |
| BLE-T-01 | Tampering | MeshMessage routing fields | Compromised relay node modifies TTL (decrement faster to kill message), hopCount, or path fields. Signal ciphertext is not affected but delivery and routing are disrupted. No cryptographic binding of routing metadata to content. | No — payload is E2E encrypted but routing fields are not | Medium | Medium | Gap — routing fields not authenticated |
| BLE-T-02 | Tampering | MeshMessage replay | Adversary captures a MeshMessage and retransmits it later. UUID-based dedup provides some protection but does not prevent replay to a different recipient's GATT server (if the UUID is not globally tracked across the mesh). | No | Low | Low | Partially mitigated — UUID dedup; TTL bounds propagation window |
| BLE-R-01 | Repudiation | BLE advertisement origin | Adversary claims they were not operating a specific device at a specific location. ECDSA signature on advertisement provides non-repudiation of advertisement origin — but this is rarely a concern for MeshCipher's use case. | N/A | N/A | N/A | Accepted |
| BLE-I-01 | Information Disclosure | BLE advertisement (presence tracking) | Any BLE-enabled device within ~30m passively collects SHA-256(deviceId) and SHA-256(userId) from advertisements. Because hashes are stable (no rotation), an adversary can: (1) build a timeline of when a specific device was present at a location; (2) correlate co-presence of multiple hashed IDs to build a social graph. No decryption required. | No — this is below the E2E encryption layer | High | High | Gap — no identifier rotation |
| BLE-I-02 | Information Disclosure | MeshMessage path field | Every relay hop appends its deviceId to the `path` field in plaintext. Any node that receives a relayed message can read the full routing path — which devices are within BLE range of each other. An adversary operating a node near the destination learns the complete path back to the origin. | No | High | High | Gap — path field is plaintext |
| BLE-I-03 | Information Disclosure | MeshMessage headers | Every relay hop can read: originDeviceId, originUserId, destinationUserId, timestamp, TTL, hopCount. These are plaintext in the MeshMessage binary format. Combined with path data, a relay node learns sender identity, recipient identity, message timing, and network topology. | No — only payload is E2E encrypted | High | High | Gap — message headers not encrypted |
| BLE-I-04 | Information Disclosure | Sybil traffic analysis | Adversary deploys multiple BLE devices at strategic locations (transit hubs, buildings). Each Sybil node acts as a relay and logs BLE-I-01, BLE-I-02, BLE-I-03 data. Correlation across nodes reconstructs message routes, social graphs, and physical movement patterns without decrypting content. | No | Medium | Critical | Gap — no Sybil resistance |
| BLE-D-01 | Denial of Service | GATT server flooding | Adversary connects to a target device's GATT server and floods the Message characteristic with crafted packets, exhausting BLE connection slots and CPU. Legitimate messages cannot be delivered. | No | Medium | Medium | Gap — no per-peer rate limiting on GATT server |
| BLE-D-02 | Denial of Service | TTL manipulation | Compromised relay node decrements TTL by more than 1 per hop, causing messages to expire before reaching destination. Targeted DoS against specific destination. | No | Low | Medium | Gap — no cryptographic TTL binding |
| BLE-D-03 | Denial of Service | Advertisement UUID collision | Static custom service UUID (`00001234-…`) is publicly known. Adversary floods BLE with devices advertising the same UUID, causing legitimate MeshCipher devices to attempt connections to adversary nodes and exhaust connection budget. | No | Low | Low | Accepted — low-sophistication attack; GATT connection failure is non-destructive |
| BLE-E-01 | Elevation of Privilege | Malicious relay node injection | Adversary-controlled relay node is accepted into the mesh (no attestation). Once in the mesh, it can selectively forward or drop messages, inject false route updates, or conduct targeted DoS against specific users. Does not elevate privileges within the Signal E2E layer. | No — E2E content is protected | Medium | Medium | Gap — open relay network |

---

## Key Observations

**Metadata leakage is the dominant risk for BLE mesh.** Signal Protocol comprehensively protects message content, but the threat model for MeshCipher's target users (activists, journalists) requires treating presence tracking and social graph inference as high-severity threats — not just medium. A passive BLE scanner at a protest venue, office building, or transit hub can build a detailed activity map without ever breaking encryption.

**Identifier rotation is absent.** The SHA-256 hashes of deviceId and userId are computed deterministically and broadcast unchanged on every advertisement. Rotating these identifiers (e.g., using epoch-based pseudonyms derived from a shared secret) would be a targeted mitigation.

**Path field represents a significant design choice.** The accumulated routing path enables loop detection and route debugging but leaks the complete peer graph to every relay node. A privacy-preserving alternative (e.g., onion-style path encoding or simply removing the path field and using TTL-based flood routing only) would eliminate BLE-I-02 and BLE-I-03.

See attack trees: `04-attack-trees/at-ble-metadata-leakage.md`, `04-attack-trees/at-mesh-relay-traffic-analysis.md`
