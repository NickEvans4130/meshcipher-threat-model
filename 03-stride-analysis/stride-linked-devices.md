# STRIDE Analysis — Linked Device Enrolment

## Component Description

The linked device enrolment flow transfers the desktop app's EC P-256 public key to the primary Android device via a QR code scan. Once enrolled, the Android's `MessageForwardingService` forwards all incoming messages to approved linked devices via the relay server.

**Key weaknesses identified in code review:**
- QR code content is displayed in plaintext on screen until dismissed — no one-time-use enforcement
- `timestamp` field in QR payload is present but not validated for freshness
- Any Android device can scan and approve the QR — no binding to the intended device
- Approval is unilateral (Android-side only) — desktop receives no confirmation

**References:** `desktopApp/.../DeviceLinkManager.kt`, `app/.../presentation/linking/DeviceLinkApprovalScreen.kt`, `app/.../presentation/linking/QRScannerScreen.kt`, `app/.../data/repository/LinkedDevicesRepository.kt`, `shared/.../LinkedDevice.kt`

---

## STRIDE Threat Table

| Threat ID | Category | Component | Attack Scenario | Signal Protocol mitigates? | Likelihood | Impact | Status |
|-----------|----------|-----------|-----------------|---------------------------|------------|--------|--------|
| LNK-S-01 | Spoofing | QR code device identity | Adversary generates their own `DeviceLinkRequest` QR with a chosen deviceId and their own EC P-256 public key pair. Tricks a user into scanning it (social engineering). The user's Android approves the adversary's device as a linked device. All forwarded messages go to the adversary. | Partially — forwarded messages are Signal-encrypted; adversary cannot decrypt without matching session keys | Low | High | Gap — no user-visible binding between QR and the specific desktop being linked |
| LNK-S-02 | Spoofing | QR code replay (photograph) | Adversary photographs the QR code displayed on the desktop screen (shoulder surfing, hidden camera, screengrab of shared screen). Uses the photograph to approve their own Android device as a linked device. The `timestamp` field is not validated for freshness, so old QR codes are replayable. | No | Medium | High | Gap — no one-time-use nonce; timestamp not validated |
| LNK-S-03 | Spoofing | Message forwarding impersonation | `MessageForwardingService` forwards messages from the primary Android to all `approved=true` linked devices. If an adversary device is registered (via LNK-S-01 or LNK-S-02), it receives message forwarding traffic — confirmation of sender IDs, message sizes, and timing even if it cannot decrypt content. | Partially — content is Signal E2E encrypted; metadata is exposed | Medium | High | Gap — depends on LNK-S-01/S-02 precondition |
| LNK-T-01 | Tampering | linked_devices DB (SQLCipher) | Attacker with root/ADB access modifies the `linked_devices` table — setting `approved=true` for an unrecognised device, or injecting a new record with their own deviceId and publicKey. `MessageForwardingService` then forwards messages to the injected device. | No | Low | High | Partially mitigated — SQLCipher; root or ADB backup required |
| LNK-T-02 | Tampering | QR code content in transit | QR code is transmitted via visual channel (screen → camera). No digital signature on the QR JSON payload outside the `publicKeyHex` field itself. An adversary cannot tamper with a QR mid-transmission without it being visible, but a screen capture could be edited before presentation. | N/A — physical channel; hard to tamper in-flight | Low | Low | Accepted |
| LNK-T-03 | Tampering | Message forwarding content | `MessageForwardingService` forwards Signal ciphertext. The ciphertext is AEAD-protected. A MITM at the relay layer (relay operator or TB-03 adversary) cannot modify Signal content undetected. | Yes — Signal AEAD | Low | Low | Mitigated |
| LNK-R-01 | Repudiation | Device link approval | User approves a linked device via UI. No cryptographic audit trail of the approval event that is signed by the user's identity key. Forensically, the `linkedAt` timestamp in SQLCipher DB is the only record. | N/A | Low | Low | Accepted |
| LNK-I-01 | Information Disclosure | QR code public key exposure | The QR code contains the desktop's full EC P-256 public key (`publicKeyHex`, 64 hex chars). Anyone who can photograph or screengrab the QR at any time during its display window learns the desktop device's public key. The public key is not secret, but combined with relay registration, it enables tracking of the desktop device across relay connections. | No | Medium | Low | Accepted — public keys are not secret by design |
| LNK-I-02 | Information Disclosure | Forwarded message metadata | Once a rogue device is enrolled (LNK-S-01 or LNK-S-02), it receives relay forwarding traffic — confirming message arrival times, sender_id (pseudonymous), and message sizes for the primary user's account. This is a timing oracle and presence oracle even without decryption. | Partially — content encrypted; metadata exposed | Medium | Medium | Gap — see LNK-S-02 |
| LNK-I-03 | Information Disclosure | deviceName (hostname) in QR | The QR contains `deviceName: hostname`. Hostnames often contain identifying information (user's name, organisation name). This is exposed to anyone who can read the QR. | No | Low | Low | Accepted — user controls their hostname |
| LNK-D-01 | Denial of Service | Linked device flooding | An adversary who can repeatedly scan and approve the QR (since it has no one-time-use enforcement) creates many linked device records for the primary Android. `MessageForwardingService` forwards messages to each approved device via relay — N forwarding operations per incoming message. At scale, this exhausts relay quota and device resources. | No | Low | Medium | Gap — no limit on number of linked devices visible; one-time-use nonce would prevent this |
| LNK-D-02 | Denial of Service | Linked device removal | Primary user removes a linked device from the approved list. No revocation signal is sent to the relay or to the linked device itself — the linked device's relay registration remains valid and it continues to receive messages until its JWT expires (30 days). | No | Low | Low | Accepted — JWT expiry is the de facto revocation |
| LNK-E-01 | Elevation of Privilege | Desktop software key (no hardware backing) | The desktop app generates an EC P-256 key pair in software (`java.security.KeyPairGenerator` — no hardware TEE on desktop). The private key is held in process memory and potentially persisted to disk in an application-defined location. If the desktop OS or process is compromised, the private key can be extracted. This is less protected than the Android Keystore-backed key. | No | Medium | High | Gap — desktop key is software-only; no equivalent of Android Keystore on desktop |

---

## Key Observations

**LNK-S-02 (QR photograph replay) is the highest-priority enrolment threat.** The attack is low-sophistication (a covert camera or screengrab), requires no cryptographic knowledge, and gives the attacker a persistent metadata oracle for the victim's communications. The fix — a one-time-use nonce and server-side or session-side consumption tracking — is well-understood and straightforward to implement.

**Desktop software key (LNK-E-01)** creates an asymmetry in the identity model: Android has hardware-backed keys (TEE/StrongBox), desktop has software keys. An adversary who compromises the desktop OS recovers the private key and can impersonate the linked device to the relay indefinitely. This is an accepted architectural constraint of desktop platforms, but it should be documented as a known risk.

**The approval UX shows only a 24-character fingerprint** (first 16 + last 8 chars of `publicKeyHex`). A full fingerprint display or QR-based out-of-band verification would improve the user's ability to detect rogue device enrolment.

See attack tree: `04-attack-trees/at-linked-device-enrolment.md`
