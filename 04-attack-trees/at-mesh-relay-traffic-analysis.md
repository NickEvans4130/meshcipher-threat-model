# Attack Tree — Mesh Relay Node Traffic Analysis

**Attacker goal:** Determine the communication graph (who is messaging whom), message timing patterns, and network topology of a BLE mesh by operating one or more relay nodes — without decrypting any Signal Protocol content.

**Adversary models:**
- A: **Single malicious relay node** — one adversary-controlled device acting as a BLE relay hop
- B: **Sybil attacker** — adversary operates multiple relay nodes distributed across the mesh coverage area to increase traffic analysis coverage and enable cross-node correlation

---

## Attack Tree

```mermaid
flowchart TD
    ROOT["[GOAL] Map BLE mesh communication graph\nand infer sender-recipient relationships\nvia relay node traffic analysis"]

    ROOT --> SINGLE["[OR] Single relay node:\npartial traffic analysis"]
    ROOT --> SYBIL["[OR] Sybil attack:\nmulti-node full coverage\ntraffic analysis"]

    %% Single relay node
    SINGLE --> S1["[AND] Deploy one device\nas BLE relay node\n(no attestation required)\nCOST: commodity Android/BLE device\nDEFENCE: none — open relay network"]
    SINGLE --> S2["[AND] For every relayed MeshMessage:\nread plaintext headers"]
    S2 --> S2a["originDeviceId\n(plaintext field)\nDEFENCE: none"]
    S2 --> S2b["originUserId\n(plaintext field)\nDEFENCE: none"]
    S2 --> S2c["destinationUserId\n(plaintext field)\nDEFENCE: none"]
    S2 --> S2d["timestamp\n(plaintext field)\nDEFENCE: none"]
    S2 --> S2e["path field\n(accumulated relay deviceIds)\nDEFENCE: none — path is plaintext"]
    S2 --> S2f["hopCount + TTL\n(reveals position in\nrouting path)\nDEFENCE: none"]
    S2 --> S2g["encryptedPayload size\n(message size oracle)\nDEFENCE: none — no padding"]

    SINGLE --> S3["[AND] Correlate with passive\nBLE advertisement data\n(SHA-256 device/user ID hashes)\nMatches originDeviceId to\nadverted hash if deterministic"]

    %% Sybil attack
    SYBIL --> SYB1["[AND] Deploy N relay nodes\nat strategic locations\n(transit hubs, common areas,\nbuilding entrances)\nCOST: N × commodity devices\nDEFENCE: none — no Sybil resistance"]
    SYBIL --> SYB2["[AND] Each node independently\nlogs S2a-S2g for every\nrelayed message\nCOST: trivial logging\nDEFENCE: none"]
    SYBIL --> SYB3["[AND] Correlate observations\nacross all Sybil nodes:\nmessage UUID + path field\npinpoints full route"]
    SYB3 --> SYB3a["[AND] For each message:\nidentify which Sybil nodes\nit passed through\n→ reconstruct physical route\nof sender through coverage area\nDEFENCE: none — path field\nenables this directly"]
    SYB3 --> SYB3b["[AND] Cross-node timing analysis:\ntime delta between Sybil nodes\nreveals movement speed\nand direction\nDEFENCE: none"]
    SYB3 --> SYB3c["[AND] Communication graph:\noriginUserId → destinationUserId\npairs observed across all nodes\n→ complete social graph of\nmesh users in coverage area\nDEFENCE: none"]

    %% TTL manipulation (active attack extension)
    SYBIL --> ACTIVE["[OR] Active: TTL manipulation\n(extend or suppress delivery)"]
    ACTIVE --> ACT1["[AND] Targeted message suppression:\ncompromised relay drops messages\nto specific destinationUserId\n= targeted DoS\nCOST: trivial once relay node deployed\nDEFENCE: none — no TTL binding"]
    ACTIVE --> ACT2["[AND] TTL extension:\nrelay increments TTL to extend\nmessage propagation beyond\nintended range\nCOST: trivial\nDEFENCE: none"]
    ACTIVE --> ACT3["[AND] Replay attack:\nrelay stores and retransmits\npreviously seen MeshMessages\nat a later time (confusion, timing attack)\nCOST: trivial\nDEFENCE: UUID dedup provides\npartial protection within session"]

    %% Outcome
    SYB3c --> OUT["[OUTCOME] Adversary has:\n- Complete communication graph\n  (who messages whom)\n- Physical movement patterns\n  (route through Sybil nodes)\n- Message timing and frequency\n- Network topology map\n- Message size patterns\nWITHOUT decrypting any content"]

    classDef gap fill:#fce4ec,stroke:#c62828
    classDef partial fill:#fff3e0,stroke:#e65100
    class S1,S2a,S2b,S2c,S2d,S2e,S2f,SYB1,SYB3a,SYB3b,SYB3c,ACT1,ACT3 gap
    class S2g,ACT2 partial
```

---

## Attack Scenario Narratives

### Scenario A: Single Relay Node (Partial Coverage)

Adversary carries an Android device that participates in the BLE mesh as a relay. For every MeshMessage it relays, it logs the full header in plaintext — sender, recipient, timestamp, message size, and the routing path. Within a single venue (protest, meeting, transit hub), the adversary quickly maps which users are present and communicating. Cost: one Android device and a simple logging app. No cryptography involved.

**Coverage limitation:** Single relay node only sees messages that physically route through it. Messages between devices that don't need this relay hop are invisible.

### Scenario B: Sybil Attack (Full Coverage)

Adversary deploys 5–10 low-cost BLE devices (commodity Android phones or Raspberry Pi + BLE adapters) across a target area — e.g., at multiple entrances/exits of a building, or across key transit nodes in a city neighbourhood. Each Sybil node acts as a willing relay hop.

Because the BLE mesh uses flood/route hybrid routing (TTL=5), most messages traverse multiple hops. The probability that at least one hop is a Sybil node increases with the density of Sybil nodes. With 5 nodes spread across a mesh of 20 honest nodes, a rough estimate suggests >60% of messages traverse at least one Sybil node.

**The `path` field is the key enabler.** When a message passes through two Sybil nodes, both log the same message UUID, different timestamps, and different `path` field snapshots. Correlation by UUID reconstructs the full route and physical movement of the sender between node locations.

**Result:** Without decrypting a single byte of Signal content, the adversary produces a detailed social and movement graph of all MeshCipher users in their coverage area.

---

## Mitigations

| Control | Status | Priority | Notes |
|---------|--------|----------|-------|
| Encrypt MeshMessage routing headers | Gap | High | Prevent relay nodes from reading sender/recipient/path in cleartext |
| Remove or onion-encrypt the `path` field | Gap | High | Path field is the primary enabler for multi-node correlation |
| Relay node attestation / trust establishment | Gap | Medium | Prevent arbitrary devices from acting as relay nodes |
| Ephemeral per-message sender pseudonyms | Gap | Medium | Prevent linking individual messages to a stable identity |
| Message padding | Gap | Low | Obscures size-based inference |
| Sybil resistance (proof of work / rate limiting) | Gap | Low | Hard in an open mesh; cost-imposing mechanisms help at the margin |
