# STRIDE Analysis — Signal Protocol Implementation

## Component Description

The Signal Protocol stack handles all message encryption/decryption across every transport. It comprises:
- **X3DH key agreement** — session establishment using identity key, signed pre-key, and one-time pre-key (PreKeyBundle)
- **Double Ratchet** — per-message key derivation providing forward secrecy and post-compromise security
- **Identity system** — EC P-256 Android Keystore key; userId is a random 32-char UUID (not derived from key)
- **Safety numbers** — 60-digit verification codes (120-decimal-digit string, SHA-512 iterated 5200×)
- **Pre-key management** — signed and one-time pre-keys stored in EncryptedSharedPreferences

Implementation: `libsignal-client` (native library, treated as cryptographically correct). Threats here target the *integration and key management* layer, not the library internals.

**References:** `app/.../encryption/SignalProtocolManager.kt`, `app/.../encryption/SignalProtocolStoreImpl.kt`, `shared/.../SafetyNumberGenerator.kt`, `app/.../identity/IdentityManager.kt`

---

## STRIDE Threat Table

| Threat ID | Category | Component | Attack Scenario | Signal Protocol mitigates? | Likelihood | Impact | Status |
|-----------|----------|-----------|-----------------|---------------------------|------------|--------|--------|
| SIG-S-01 | Spoofing | Identity / X3DH | Adversary registers a new userId at the relay using a freshly generated key pair, impersonating the target. Recipients have no pre-existing safety number and accept the session without warning. | Partially — safety number verification exposes key changes, but only if previously verified | Medium | High | Gap — TOFU; no PKI |
| SIG-S-02 | Spoofing | Safety number verification | Attacker intercepts an unverified session, performs MITM by substituting their own PreKeyBundle. Both parties think they are talking to each other but are talking to the attacker. | No — X3DH MITM is possible if safety numbers are never verified | Medium | Critical | Gap — depends on user behaviour |
| SIG-T-01 | Tampering | Pre-key store (EncryptedSharedPreferences) | Attacker with root/ADB backup access modifies or replaces pre-key records in EncryptedSharedPreferences. Causes session establishment to fail or to use attacker-injected key material. | No — pre-key store is outside Signal library's tamper detection | Low | High | Partially mitigated — AES-256-GCM protects store; root required |
| SIG-T-02 | Tampering | Safety number state (DB) | Attacker with DB access modifies `safetyNumberChangedAt` timestamp or `verifiedSafetyNumber` field to suppress the key-change warning. Victim trusts a session that has been compromised. | No | Low | High | Partially mitigated — SQLCipher; root required |
| SIG-R-01 | Repudiation | Double Ratchet / deniable auth | Signal Protocol intentionally provides deniable authentication — message transcripts are repudiable. This is a design property, not a threat. Relevant context: forensic adversaries cannot cryptographically prove message authorship. | Yes — deniability is by design | N/A | N/A | Accepted (by design) |
| SIG-I-01 | Information Disclosure | Pre-key exhaustion | Adversary exhausts all one-time pre-keys by establishing many sessions. Subsequent session initiators use the signed pre-key only (no one-time pre-key), weakening forward secrecy for those sessions. | Partially — signed pre-key sessions are still encrypted; one-time pre-key exhaustion reduces security margin | Medium | Medium | Gap — no pre-key replenishment rate limiting on relay |
| SIG-I-02 | Information Disclosure | EncryptedSharedPreferences (Signal state) | Attacker with physical access to an unlocked device extracts EncryptedSharedPreferences backing file. On Android 9+ without StrongBox, the master key may be accessible without biometric re-authentication. Grants access to session state, pre-keys, and (for non-Keystore keys) identity key material. | No — at-rest encryption is at the OS layer, not within Signal | Low | Critical | Partially mitigated — EncryptedSharedPreferences + Keystore; biometric gate on identity key ops |
| SIG-I-03 | Information Disclosure | Identity key recovery via Auto Backup | Android Auto Backup can back up the userId (stored in DataStore preferences) to Google servers. If a new device is restored from backup with the same userId but a new Keystore key, there is a userId continuity that could aid correlation. | No | Low | Low | Accepted risk — userId alone has no cryptographic value |
| SIG-D-01 | Denial of Service | Pre-key exhaustion (availability) | Adversary exhausts pre-keys — as SIG-I-01 — preventing legitimate session establishment from completing in the secure manner. Also forces re-use of signed pre-key, reducing security. | No | Medium | Medium | Gap |
| SIG-D-02 | Denial of Service | Session state corruption | Attacker with root access corrupts the Double Ratchet session state in EncryptedSharedPreferences, causing permanent "message decryption failed" errors with a specific contact until session is reset. | No | Low | Medium | Partially mitigated — SQLCipher + EncryptedSharedPreferences; root required |
| SIG-E-01 | Elevation of Privilege | Biometric bypass → Keystore key use | Attacker bypasses Android biometric authentication (e.g., via OS vulnerability or hardware bypass) to perform signing operations with the identity key — authenticate to relay, sign BLE advertisements. Does not extract private key. | No | Low | High | Accepted — hardware security is foundational assumption |
| SIG-E-02 | Elevation of Privilege | JWT HS256 secret theft | If relay server is compromised and HS256 JWT signing secret is extracted, attacker can forge JWTs for any userId, impersonating arbitrary users at the relay layer (metadata layer only — cannot forge Signal messages). | No — JWT is relay-layer auth only | Low | High | Gap — HS256 symmetric secret; no public key equivalent |

---

## Key Observations

**TOFU without verification is the central weakness.** The safety number system is correct and well-implemented (`SafetyNumberGenerator.kt` uses iterated SHA-512 for hardening), but it only provides protection *after* users complete the verification ceremony. For MeshCipher's target users (journalists, activists), unverified sessions are a significant MITM risk.

**Pre-key exhaustion is under-addressed.** The relay has a 500-message-per-recipient limit but no apparent limit on pre-key fetch requests. An adversary who can register many fake devices could exhaust one-time pre-keys.

**EncryptedSharedPreferences is the right choice** for Signal state storage, but the security of the master key depends on the Android Keystore and biometric configuration. Devices without StrongBox hardware, or where users have no biometric enrolled, have a weaker at-rest protection posture.
