# Attack Tree — BLE Metadata Leakage / Presence Tracking

**Attacker goal:** Determine presence, movement patterns, and social graph of a target MeshCipher user via passive BLE observation, without decrypting any message content.

**Adversary model:** Local adversary with BLE scanning capability (commodity hardware, ~30m range). No cryptographic capability required. May be stationary (building sensor, checkpoint) or mobile (following target).

---

## Attack Tree

```mermaid
flowchart TD
    ROOT["[GOAL] Identify target's presence,\nmovement patterns, and social graph\nvia BLE observation alone"]

    ROOT --> A["[OR] Build stable identifier\nfor target device"]
    ROOT --> B["[OR] Correlate co-presence\nof multiple devices\n(social graph)"]
    ROOT --> C["[OR] Infer communication events\nfrom mesh traffic patterns"]

    %% Branch A: Stable identifier
    A --> A1["[AND] Collect BLE advertisements\nfrom target device"]
    A --> A2["[AND] Extract stable hash\nfrom advertisement"]
    A1 --> A1a["Passive BLE scan\n(no auth, any scanner within 30m)\nCOST: commodity hardware\nDEFENCE: none currently"]
    A1 --> A1b["Read service UUID\n00001234-… (public, static)\nCOST: trivial\nDEFENCE: none"]
    A2 --> A2a["Read SHA-256(deviceId)\nfrom bytes [2:34] of advertisement\nStable across all sessions\nCOST: trivial\nDEFENCE: none — no rotation"]
    A2 --> A2b["Read SHA-256(userId)\nfrom bytes [34:66] of advertisement\nStable across all sessions\nCOST: trivial\nDEFENCE: none — no rotation"]

    %% Branch B: Social graph
    B --> B1["[AND] Deploy scanner at\nknown meeting location\n(office, café, protest venue)"]
    B --> B2["[AND] Record co-presence\nof device hash pairs\nover time"]
    B --> B3["[AND] Build adjacency graph:\nhash_A ↔ hash_B ↔ hash_C"]
    B1 --> B1a["Single cheap BLE scanner\n(Raspberry Pi, ~$30)\nCOST: low\nDEFENCE: none"]
    B2 --> B2a["Passive log of\n(hash, timestamp, RSSI) tuples\nNo active interaction needed\nCOST: trivial\nDEFENCE: none"]
    B3 --> B3a["Graph inference:\nfrequently co-present hashes\nare likely communicating peers\nCOST: basic data analysis\nDEFENCE: none"]

    %% Branch C: Communication events
    C --> C1["[AND] Observe MeshMessage\nGATT transfers\n(relay node or GATT sniffer)"]
    C --> C2["[AND] Read plaintext\nMeshMessage headers"]
    C1 --> C1a["Act as relay node\n(no attestation required)\nOR sniff GATT over air\nCOST: moderate\nDEFENCE: none — open relay network"]
    C2 --> C2a["originDeviceId visible\n(plaintext in MeshMessage)"]
    C2 --> C2b["destinationUserId visible\n(plaintext in MeshMessage)"]
    C2 --> C2c["path field accumulates\nall relay deviceIds\n(plaintext)"]
    C2 --> C2d["timestamp + hopCount\nreveal send time\nand network topology"]

    %% Deanonymisation: linking hashes to real identity
    A2a --> D["[AND] Link hash to real identity"]
    D --> D1["[OR] Correlate hash with\nknown-location presence\n(target observed at home address)"]
    D --> D2["[OR] Obtain device registration\nfrom relay server\n(compelled disclosure)\nuserId → publicKey → relay account"]
    D --> D3["[OR] Physical observation\n(target seen using phone\nat time hash was recorded)"]

    classDef gap fill:#fce4ec,stroke:#c62828
    classDef mitigated fill:#e8f5e9,stroke:#2e7d32
    classDef partial fill:#fff3e0,stroke:#e65100
    class A1a,A1b,A2a,A2b,B1a,B2a,B3a,C1a gap
    class C2a,C2b,C2c,C2d gap
```

---

## Attack Scenario Narrative

**Step 1 — Deploy passive scanner.** Adversary places a Raspberry Pi with BLE adapter at a location the target is expected to visit (office building entrance, transit hub, protest venue). The scanner continuously logs `(SHA-256(deviceId), SHA-256(userId), timestamp, RSSI, messageType)` tuples from any MeshCipher advertisement (identifiable by service UUID `00001234-…`).

**Step 2 — Build presence timeline.** Over days or weeks, the adversary accumulates a timestamped record of when each stable hash was observed at the scanning location. No decryption required.

**Step 3 — Social graph construction.** By deploying multiple scanners or by analysing co-presence data from a single scanner, the adversary identifies pairs of hashes that appear together frequently. These pairs likely represent communicating peers (friends, colleagues, organising groups).

**Step 4 — Deanonymisation.** The adversary anchors one hash to a real identity by physical observation (see target at a known-location scanner, match time of observation with hash appearance). Once one node in the graph is identified, the social network reveals additional identities.

**Step 5 — Communication event inference.** If the adversary can act as a BLE relay node, they gain access to the plaintext `MeshMessage` headers — explicit sender and recipient IDs, timestamps, message sizes, and routing paths — confirming and enriching the social graph with communication events.

---

## Mitigations

| Control | Status | Notes |
|---------|--------|-------|
| SHA-256 hashing of IDs in advertisements | Implemented | Prevents direct identity disclosure but hashes are stable — does not prevent tracking |
| Identifier rotation (epoch-based pseudonyms) | Gap | Not implemented; would be the primary mitigation for presence tracking |
| Randomised service UUID per session | Gap | Static UUID `00001234-…` identifies the app to any scanner |
| Removal of `path` field from MeshMessage | Gap | Path field leaks routing graph to every relay hop |
| Encryption of MeshMessage headers | Gap | originDeviceId, destinationUserId are plaintext in every relayed message |
| Relay node attestation | Gap | No mechanism to verify relay nodes are honest |

---

## Residual Risk

Even with identifier rotation implemented, a motivated adversary with multiple scanners at strategic locations can correlate rotated identifiers using timing and RSSI patterns if the rotation period is too long or if the device moves predictably between scanner coverage areas. Rotation is a mitigation, not a complete defence against a well-resourced local adversary.
