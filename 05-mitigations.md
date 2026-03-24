# 05 — Mitigations: Existing Controls and Gap Analysis

This document maps every existing security control to the threats it addresses, then enumerates the gaps requiring new work. Controls are cross-referenced to STRIDE threat IDs.

---

## Existing Controls

### MC-01: Signal Protocol E2E Encryption (libsignal-client)

**Description:** All transports carry Signal Protocol ciphertext. Double Ratchet provides per-message key evolution, perfect forward secrecy, and post-compromise security. X3DH provides authenticated key agreement. AEAD (AES-GCM) provides tamper detection on every message.

**Threats mitigated:** REL-T-01, TOR-T-01, WFD-T-02, LNK-T-03 — any attempt to tamper with message content is detected. Content confidentiality across all transports.

**Threats NOT mitigated:** All metadata threats (BLE-I-01 through BLE-I-04, REL-I-01 through REL-I-05), routing header exposure (BLE-I-02, BLE-I-03), relay operator visibility (REL-I-01), QR enrolment gaps (LNK-S-01, LNK-S-02).

**Status:** Fully implemented. `libsignal-client` is the reference implementation; correct usage verified in `SignalProtocolManager.kt`.

---

### MC-02: Android Keystore Hardware-Backed Identity Key

**Description:** EC P-256 identity key generated in Android Keystore (TEE/StrongBox). Marked non-exportable; requires biometric authentication (30s validity). Key never leaves hardware boundary.

**Threats mitigated:** SIG-I-02 (partial — Keystore prevents key extraction), SIG-E-01 (biometric gate on key use).

**Threats partially mitigated:** Physical device seizure with biometric bypass capability bypasses the gate.

**Status:** Fully implemented. `IdentityManager.kt` uses `keyManager.generateHardwareKey()` backed by `KeyStore.getInstance("AndroidKeyStore")`.

---

### MC-03: EncryptedSharedPreferences for Signal State

**Description:** All Signal Protocol state (sessions, pre-keys, identity key material) stored in `EncryptedSharedPreferences` using AES-256-GCM with a Keystore-backed master key.

**Threats mitigated:** SIG-I-02, SIG-T-01, SIG-T-02, TOR-T-02, LNK-T-01 (all require root or Keystore compromise to bypass).

**Status:** Fully implemented. `SignalProtocolStoreImpl.kt` and `EmbeddedTorManager.kt` (for ED25519 key) both use `EncryptedSharedPreferences`.

---

### MC-04: SQLCipher Database Encryption

**Description:** Room database encrypted with SQLCipher (AES-256-CBC + HMAC-SHA256 page authentication). Key is a random 32-byte secret stored in `EncryptedSharedPreferences`.

**Threats mitigated:** LNK-T-01 (linked device DB), SIG-T-02 (safety number DB), physical device access to conversation history.

**Status:** Fully implemented.

---

### MC-05: Media Encryption at Rest

**Description:** Each media file encrypted with a unique AES-256-GCM key (256-bit key, 96-bit IV). Per-file keys stored in `EncryptedSharedPreferences`. EXIF metadata stripped before encryption.

**Threats mitigated:** Media content disclosure on device seizure; GPS/device metadata leakage via image files.

**Status:** Fully implemented.

---

### MC-06: Safety Number Verification

**Description:** 60-digit safety numbers derived from iterated SHA-512 (5200 iterations) over both parties' userId + public key. Key change detection at app startup — alerts user if safety number changes for any contact.

**Threats mitigated:** SIG-S-02 (Signal MITM detected if safety numbers are verified). Automatic change detection closes the gap for previously verified contacts.

**Limitation:** TOFU — first contact has no safety number to compare against. Verification ceremony is manual and user-driven. Unverified contacts are not protected against MITM.

**Status:** Implemented. `SafetyNumberGenerator.kt` + `SafetyNumberManager.kt`.

---

### MC-07: Relay Authentication (ECDSA Challenge-Response + JWT)

**Description:** Client authenticates to relay by signing a 32-byte random challenge with their hardware identity key (`SHA256withECDSA`). Server issues HS256 JWT (30-day expiry). JWT required for all sensitive relay endpoints.

**Threats mitigated:** REL-S-02 (unauthenticated registration not possible), REL-D-01 (unauthenticated floods blocked).

**Limitations:** HS256 symmetric — relay operator holds signing secret (REL-S-01 gap). JWT expiry is 30 days — long window for token compromise.

**Status:** Implemented. `relay-server/server.py` `/api/v1/auth/*` endpoints.

---

### MC-08: Relay Rate Limiting

**Description:** Flask-Limiter applied: 200/min default, 10/min auth endpoints, 60/min relay endpoints. Per-recipient mailbox cap: 500 messages.

**Threats mitigated:** REL-D-01 (single-source flood), REL-D-02 (mailbox flooding partial).

**Limitations:** Rate limits are per-IP — distributed attacks from many IPs bypass them. No per-sender rate limit on writes to a specific recipient's mailbox.

**Status:** Implemented.

---

### MC-09: Relay Input Validation and Security Headers

**Description:** All string inputs trimmed, max 255 chars. Sender_id validated against JWT claim. Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP, `Cache-Control: no-store`. Request body size limit: 10 MB.

**Threats mitigated:** REL-E-01 (injection attacks), REL-T-02 (reduces MITM surface).

**Status:** Implemented.

---

### MC-10: ECDSA Signature on BLE Advertisements

**Description:** Each `AdvertisementData` packet includes a 64-byte ECDSA signature over the advertisement fields. Authenticates the advertisement origin.

**Threats mitigated:** BLE-S-01 (advertisement spoofing — if signature is verified before acting on the advertisement).

**Limitation:** Effectiveness depends on whether peers verify the signature before updating neighbor tables. This was not confirmed in the code review.

**Status:** Implemented in `AdvertisementData.kt`. Verification enforcement unclear.

---

### MC-11: BLE UUID-Based Message Deduplication

**Description:** Relay nodes track seen message UUIDs to prevent duplicate forwarding.

**Threats mitigated:** BLE-T-02 (replay within a session), BLE-D-02 (loop propagation).

**Limitations:** UUID dedup is session-scoped (in-memory); no persistent dedup across app restarts. Does not prevent replay to a different GATT server.

**Status:** Implemented.

---

### MC-12: Tor Support (Relay + P2P)

**Description:** Relay traffic can be routed via Orbot SOCKS5 (hides sender IP). P2P Tor hidden service provides full bilateral anonymity with no relay involvement.

**Threats mitigated:** REL-I-02 (IP logging — when Tor is enabled), TOR-I-02 (IP exposure on P2P transport).

**Limitations:** Tor relay mode is opt-in. Default mode exposes sender IP. No Tor bridge/pluggable transport support.

**Status:** Implemented. `InternetTransport.kt` + `EmbeddedTorManager.kt`.

---

### MC-13: Disappearing Messages

**Description:** Messages can be configured to auto-delete `ON_APP_CLOSE` or on a time-based schedule.

**Threats mitigated:** Reduces data available on device seizure; limits relay server retention of undelivered messages (delivered messages are flagged, not deleted immediately — retention policy unclear).

**Status:** Implemented.

---

## Gap Analysis

The following gaps have no current mitigating control. They are the primary findings of this threat model.

### GAP-01: No BLE Identifier Rotation

**Threats:** BLE-I-01, BLE-I-04 (presence tracking, social graph)
**Description:** SHA-256(deviceId) and SHA-256(userId) in BLE advertisements are stable across all sessions. Passive scanner builds a permanent device fingerprint.
**Recommended fix:** Epoch-based pseudonymous identifiers — derive advertisement IDs from a shared secret and a time epoch (e.g., hourly rotation). Contacts with the shared secret can resolve the pseudonym; passive observers cannot track across epochs.
**Complexity:** Medium — requires coordinated key derivation and epoch synchronisation across the mesh.

---

### GAP-02: Plaintext MeshMessage Routing Headers

**Threats:** BLE-I-02, BLE-I-03, at-mesh-relay-traffic-analysis
**Description:** `originDeviceId`, `originUserId`, `destinationUserId`, `path` field, `hopCount`, `TTL` are all plaintext in the binary MeshMessage format. Every relay node reads sender, recipient, and full routing path.
**Recommended fix (option A):** Encrypt the routing header with a shared group key or a per-hop onion layer. High complexity.
**Recommended fix (option B):** Remove the `path` field entirely and rely on TTL-based flood routing. Eliminates BLE-I-02 at the cost of loop detection capability. Low complexity.
**Recommended fix (option C):** Replace static device IDs in routing with ephemeral per-session pseudonyms. Medium complexity.

---

### GAP-03: No Certificate Pinning on Relay HTTPS

**Threats:** REL-T-02 (TLS MITM)
**Description:** OkHttp client has no `CertificatePinner` configured. A rogue CA can issue a valid cert for the relay domain; corporate proxies and state-level actors can intercept relay traffic.
**Recommended fix:** Add `CertificatePinner` to the OkHttp client builder with the relay server's leaf certificate or public key hash. One-line fix.
**Complexity:** Low. Already identified in `SECURITY_AUDIT_GUIDE.md`.

---

### GAP-04: HS256 JWT (Symmetric Secret)

**Threats:** REL-S-01, REL-T-03
**Description:** JWT tokens are signed with a symmetric HS256 secret held by the relay server. Server compromise = all tokens forgeable.
**Recommended fix:** Switch to RS256 or ES256 asymmetric JWT. Relay signs with private key; clients verify with public key (embedded in app). Server compromise no longer allows token forgery.
**Complexity:** Low on relay side; requires client update to use public key verification.

---

### GAP-05: QR Enrolment — No One-Time-Use Nonce

**Threats:** LNK-S-02, LNK-D-01, at-linked-device-enrolment
**Description:** QR code has no expiry and can be scanned multiple times. `timestamp` field is present but not validated for freshness.
**Recommended fix:** Generate a random one-time nonce for each enrolment session. QR includes nonce + expiry timestamp. Android validates nonce has not been used and timestamp is within the acceptance window (e.g., 5 minutes). Nonce consumed on first use.
**Complexity:** Medium — requires session state between desktop and Android, or relay-mediated nonce consumption.

---

### GAP-06: No Desktop-Side Enrolment Confirmation

**Threats:** LNK-S-01, LNK-S-02
**Description:** Android approves a linked device unilaterally. The desktop that generated the QR receives no confirmation. A rogue device can be enrolled without the desktop ever knowing.
**Recommended fix:** After Android approval, Android sends a confirmation message (signed with its identity key) to the desktop via relay. Desktop shows confirmation UI — user verifies on both sides that the link is intentional.
**Complexity:** Medium.

---

### GAP-07: Java Deserialization in WiFi Direct

**Threats:** WFD-T-01, WFD-E-01
**Description:** `ObjectInputStream.readObject()` over the WiFi Direct TCP socket. A malicious peer can send a gadget chain to achieve code execution in the app process.
**Recommended fix:** Replace `ObjectInputStream`/`ObjectOutputStream` with a typed binary format. Options: protobuf, length-prefixed byte arrays with a fixed-field binary header (no reflection required). This also simplifies the interoperability between Android and future transport implementations.
**Complexity:** Low-medium — wire protocol change; no logic change required.

---

### GAP-08: Post-Quantum Gap (Harvest-Now-Decrypt-Later)

**Threats:** Implicit across all transports — classical-only X25519 + AES
**Description:** All session keys are established via X25519 ECDH (X3DH). A quantum adversary with a sufficiently large quantum computer can break X25519 and recover historical session keys from captured ciphertext. This is the HNDL (harvest-now-decrypt-later) threat.
**Recommended fix:** CRYSTALS-Kyber hybrid (PQXDH pattern) — combine X25519 with Kyber-768 or Kyber-1024 in the key agreement. Signal has published the PQXDH specification and `libsignal-client` has begun integration. Kyber pre-key storage infrastructure is already stubbed in `SignalProtocolStoreImpl.kt` (`kyber_prekey:{id}` keys visible in code comments).
**Complexity:** High — requires `libsignal-client` version with PQXDH support, key size changes, pre-key bundle format update, relay storage for larger pre-keys.
**Timeline:** Roadmap item — see `07-security-roadmap.md`.

---

### GAP-09: No Tor Bridge / Pluggable Transport Support

**Threats:** TOR-D-03 (censorship defeats all Tor transports)
**Description:** Embedded Tor uses vanilla entry nodes. In jurisdictions that block the Tor network, all Tor-based transports fail.
**Recommended fix:** Integrate `obfs4` or Snowflake pluggable transports via `tor-android`. Allows users to configure bridges.
**Complexity:** Medium.

---

### GAP-10: Stable .onion Address (Persistent Hidden Service Key)

**Threats:** TOR-I-01 (online presence probing)
**Description:** ED25519 hidden service key is persistent, creating a stable long-term pseudonym. Any party who knows the `.onion` address can probe for online presence.
**Recommended fix:** Provide an opt-in ephemeral mode that generates a new ED25519 key per session. Contacts must be re-notified of the new address each session (or use a rendezvous mechanism).
**Complexity:** Medium — primarily a UX challenge; cryptographic change is trivial.

---

## Control Mapping Summary

| Threat ID | Control(s) | Gap? |
|-----------|-----------|------|
| SIG-S-01, SIG-S-02 | MC-06 (partial — requires user action) | Yes — TOFU |
| SIG-I-02 | MC-02, MC-03 | No (root required) |
| SIG-D-01 | — | Yes — GAP pre-key exhaustion |
| BLE-S-01 | MC-10 (partial) | Low |
| BLE-I-01 | — | Yes — GAP-01 |
| BLE-I-02, BLE-I-03 | — | Yes — GAP-02 |
| BLE-D-01 | — | Yes |
| REL-T-01 | MC-01 | No |
| REL-T-02 | — | Yes — GAP-03 |
| REL-S-01 | — | Yes — GAP-04 |
| REL-I-01 | MC-07 (pseudonymous IDs only) | Yes |
| REL-I-02 | MC-12 (opt-in Tor) | Partial |
| REL-D-01, REL-D-02 | MC-08 | Partial |
| REL-D-04 | — | Yes — single instance |
| TOR-S-02 | — | Yes |
| TOR-I-01 | — | Yes — GAP-10 |
| TOR-D-03 | — | Yes — GAP-09 |
| WFD-T-01, WFD-E-01 | — | Yes — GAP-07 |
| LNK-S-01, LNK-S-02 | MC-06 (partial) | Yes — GAP-05, GAP-06 |
| LNK-E-01 | — | Accepted (desktop platform constraint) |
| All transports | MC-01 (content) | Content: No. Metadata: Yes |
| Quantum HNDL | — | Yes — GAP-08 |
