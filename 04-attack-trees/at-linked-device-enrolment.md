# Attack Tree — Linked Device Enrolment Attack

**Attacker goal:** Register an adversary-controlled device as an approved linked device on the victim's primary Android, causing all forwarded messages to also be delivered to the adversary.

**Adversary models:**
- A: **Opportunistic observer** — can briefly see the desktop screen during enrolment (shoulder surfing, shared screen)
- B: **Physical access adversary** — brief physical access to desktop or Android during or after enrolment
- C: **Network/relay adversary** — can observe relay traffic after rogue device is registered

---

## Attack Tree

```mermaid
flowchart TD
    ROOT["[GOAL] Register adversary device\nas approved linked device\non victim's Android"]

    ROOT --> QR["[OR] Obtain and use\nvalid QR code"]
    ROOT --> DB["[OR] Directly inject\nlinked_device DB record\n(requires device compromise)"]

    %% Branch 1: QR acquisition
    QR --> QR1["[OR] Photograph QR\nduring display window"]
    QR --> QR2["[OR] Screengrab shared screen\n(screen share, video call,\nremote desktop)"]
    QR --> QR3["[OR] Social engineer target\ninto sharing QR\n(send me the code so I can link)"]
    QR --> QR4["[OR] Generate fake QR\nwith adversary's own key\nand trick victim into\nscanning it (LNK-S-01)"]

    QR1 --> QR1a["[AND] Physical proximity\nto desktop screen\nduring enrolment window\nCOST: low (shoulder surf)"]
    QR1 --> QR1b["[AND] QR remains displayed\nuntil dismissed\n(no timeout/one-time-use)\nCOST: zero additional\nDEFENCE: none — GAP"]
    QR1 --> QR1c["[AND] Present photograph\nto own Android camera\nor decode QR from image\nCOST: trivial\nDEFENCE: none — timestamp not validated"]

    QR2 --> QR2a["Target shares screen\nfor remote support,\ndemo, or collaboration\nCOST: low — social engineering\nDEFENCE: user awareness"]

    QR3 --> QR3a["Pretexting attack\n('I need to link my phone')\nCOST: social engineering\nDEFENCE: user awareness"]

    QR4 --> QR4a["[AND] Adversary generates\nEC P-256 key pair\nCOST: trivial"]
    QR4 --> QR4b["[AND] Constructs valid\nDeviceLinkRequest JSON\nwith adversary publicKeyHex\nCOST: trivial\nDEFENCE: none — no authenticity\nbinding to specific desktop device"]
    QR4 --> QR4c["[AND] Presents QR to victim\non trusted-looking screen\nCOST: moderate — screen needed\nDEFENCE: user verifies device fingerprint (partial)"]

    %% Branch 2: Direct DB injection
    DB --> DB1["[AND] Root or ADB backup\naccess to Android device"]
    DB --> DB2["[AND] Modify linked_devices\nSQLCipher table\n(need SQLCipher key)"]
    DB --> DB3["[AND] Add approved=true record\nwith adversary's deviceId\nand publicKeyHex"]

    DB1 --> DB1a["ADB backup (if USB debugging\nenabled — unlikely for target user)\nOR root via exploit\nCOST: high\nDEFENCE: SQLCipher encryption;\nADB disabled in production"]
    DB2 --> DB2a["SQLCipher key stored in\nEncryptedSharedPreferences\n(AES-256-GCM, Keystore-backed)\nCOST: requires key extraction\nDEFENCE: strong — Keystore required"]

    %% Branch 3: Exploit outcome
    QR1c --> OUTCOME["[AND] Approve on adversary Android:\nScan QR on adversary device,\napprove in DeviceLinkApprovalScreen\nNO binding to victim's intended Android\nCOST: trivial\nDEFENCE: none — GAP"]
    QR2a --> OUTCOME
    QR3a --> OUTCOME
    QR4c --> OUTCOME
    DB3 --> OUTCOME

    OUTCOME --> IMPACT["[IMPACT] Adversary device\nregistered as linked device"]

    IMPACT --> I1["MessageForwardingService\nforwards all incoming messages\nto adversary device via relay\nContent: Signal E2E encrypted\n(adversary cannot decrypt)\nMetadata: timing, sender_id, sizes"]
    IMPACT --> I2["Adversary confirms:\n- when messages arrive (timing oracle)\n- sender pseudonymous IDs\n- message sizes / content type\n- communication activity patterns"]
    IMPACT --> I3["If adversary also achieves\nSignal-layer MITM (SIG-S-02)\nor session compromise:\nfull content access"]

    classDef gap fill:#fce4ec,stroke:#c62828
    classDef mitigated fill:#e8f5e9,stroke:#2e7d32
    classDef partial fill:#fff3e0,stroke:#e65100
    class QR1b,QR1c,QR4b,OUTCOME gap
    class DB2a mitigated
    class QR4c partial
```

---

## Attack Scenario Narratives

### Scenario A: Shoulder Surf + Photograph (Opportunistic, Low Sophistication)

Target is linking their laptop to their phone at a coffee shop. Adversary is seated nearby. During the ~30 seconds the QR is displayed, adversary takes a photo with their phone. Later, they decode the QR image using a free QR scanner app, extract the `meshcipher://link/…` URI, open the app on their own Android, scan their photo, and approve the device in `DeviceLinkApprovalScreen`. The entire attack requires no technical skill and no cryptographic capability. From this point, `MessageForwardingService` delivers all incoming messages to both the target's laptop and the adversary's phone.

**Key enablers:** No one-time-use nonce; `timestamp` field not validated for freshness; no binding to specific Android device.

### Scenario B: Fake QR (Active, Moderate Sophistication)

Adversary generates an EC P-256 key pair and constructs a valid `DeviceLinkRequest` JSON payload with their own `publicKeyHex`. Renders it as a QR code on their own screen. Via social engineering (pretending to be IT support, a colleague wanting to test the app), persuades the target to scan this QR. The target's `DeviceLinkApprovalScreen` shows the adversary's `deviceName` (whatever they configured) and a truncated fingerprint. If the target approves, the adversary's device is linked. The only defence is the user recognising that the fingerprint doesn't match their actual laptop.

**Key enabler:** QR validation only checks JSON structure and presence of fields; it does not verify that the QR originated from a device the user has any prior relationship with.

---

## Mitigations

| Control | Status | Priority |
|---------|--------|----------|
| One-time-use nonce in QR (server or session validated) | Gap | High |
| Timestamp freshness validation (e.g., reject if > 5 minutes old) | Gap | High |
| Desktop confirmation step (Android sends approval, desktop must confirm) | Gap | High |
| Full public key fingerprint display (vs. 24-char truncation) | Gap | Medium |
| QR expiry timer (auto-dismiss after 60s) | Gap | Medium |
| Binding QR to session (only scannable by a device that has pre-authenticated) | Gap | Low — complex UX |
