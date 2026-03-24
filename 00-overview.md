# 00 — System Overview, Scope, and Assumptions

## 1. System Description

MeshCipher is a privacy-first encrypted messaging application designed for users who require communications security under adversarial conditions (journalists, activists, first responders, field teams). It provides end-to-end encrypted messaging over **multiple independent transport layers**, all carrying Signal Protocol ciphertext.

### 1.1 Clients

| Client | Platform | Status |
|--------|----------|--------|
| Android app | Android 8.0+ (API 26–34) | Primary, production |
| Compose Desktop | Linux / macOS / Windows | Companion (linked device) |

### 1.2 Transport Layers

| Transport | Range | Topology | Centralised? |
|-----------|-------|----------|-------------|
| Internet relay (HTTPS/WSS) | Global | Star (relay hub) | Yes — Oracle Cloud Free Tier |
| Internet relay via Tor (SOCKS5) | Global | Star via Tor exit | Yes (relay); Tor adds anonymity |
| P2P Tor hidden service | Global | Direct .onion-to-.onion | No |
| WiFi Direct | ~100 m | P2P (Group Owner model) | No |
| Bluetooth LE mesh | ~10–30 m per hop | Multi-hop flood/route hybrid | No |
| Reticulum/LoRa | Km-range | Mesh (planned) | No — Phase 10 roadmap |

### 1.3 Key Subsystems

- **Signal Protocol stack** — Double Ratchet + X3DH key agreement via `libsignal-client`. Provides E2E encryption, perfect forward secrecy, and post-compromise security for all transports.
- **Identity system** — EC P-256 keypair in Android Keystore (hardware-backed TEE/StrongBox). UserId is a random 32-char UUID (not derived from key). Relay authentication uses ECDSA challenge-response → HS256 JWT.
- **BLE mesh** — `AdvertisementData` packets contain SHA-256 hashes of deviceId and userId (not plaintext). `MeshMessage` format carries: originDeviceId, originUserId, destinationUserId, TTL (default 5), hopCount, path (comma-separated relay deviceIds), Signal ciphertext payload.
- **P2P Tor** — Embedded Tor daemon (Guardian Project `tor-android`). Persistent ED25519-V3 hidden service key stored in EncryptedSharedPreferences. Stable .onion address per device.
- **Relay server** — Flask/Python. Stores: sender_id (SHA-256 hash of pubkey, 32 chars), recipient_id, encrypted_content (Base64 Signal ciphertext), content_type, timestamps, IP of connecting client. JWT-authenticated; rate-limited.
- **Linked devices** — Desktop generates QR code containing `DeviceLinkRequest` (deviceId, deviceName, publicKeyHex, timestamp) encoded as `meshcipher://link/<base64url-JSON>`. Android scans, displays fingerprint, user approves; record inserted into `linked_devices` DB table.
- **Data at rest** — SQLCipher (AES-256-CBC + HMAC-SHA256). Signal protocol state and media keys in EncryptedSharedPreferences (AES-256-GCM, Keystore-backed).

---

## 2. Assets

### 2.1 Primary Assets (High Value)

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Signal Protocol identity key pair | Android Keystore (non-exportable) | Critical — compromise = permanent identity loss |
| Signal Protocol session state (Double Ratchet) | EncryptedSharedPreferences | Critical — compromise = loss of PFS for active sessions |
| Pre-keys (X3DH one-time + signed) | EncryptedSharedPreferences | High — exhaustion enables session establishment attacks |
| Message plaintext (in memory) | RAM during decryption | High |
| Message database (SQLCipher) | `files/` on device | High — all conversation history |
| Media files (encrypted) | `files/media_encrypted/` | High |
| ED25519 Tor hidden service key | EncryptedSharedPreferences | High — compromise reveals stable .onion identity |
| Safety number verification state | DB `contact_keys` table | Medium — tampering enables silent MITM |
| JWT tokens (relay auth) | Memory / OkHttp cookie jar | Medium — 30-day expiry; allows relay impersonation |
| Relay server DB | Oracle Cloud VM | High — full connection metadata graph |

### 2.2 Secondary Assets

| Asset | Sensitivity |
|-------|-------------|
| BLE neighbor table (presence data) | Medium — reveals peer graph |
| Message routing path field | Medium — reveals relay topology |
| Contact list (userId ↔ display name mapping) | Medium |
| Device link QR code (ephemeral) | High during enrolment window |

---

## 3. Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Passive network observer (ISP, national infrastructure) | Traffic analysis, metadata collection, bulk capture | Mass surveillance, HNDL |
| Active network attacker (MITM) | TLS interception, BGP hijack, DNS poisoning | Targeted interception |
| Relay server operator / Oracle Cloud | Full relay DB access, connection logs, IP addresses | Compelled disclosure, insider threat |
| Malicious BLE/mesh node operator | Passive BLE scanning, active relay node | Presence tracking, traffic analysis |
| Physical adversary | Device seizure, rubber-hose | Key extraction, forced unlock |
| Malicious app / compromised dependency | On-device code execution | Key theft, message exfiltration |
| State-level adversary (quantum-capable, future) | Harvest-now-decrypt-later (HNDL) | Long-term decryption of captured ciphertext |
| QR enrolment attacker | QR code interception (camera, screen capture) | Rogue device registration |

---

## 4. Trust Boundaries

Formally enumerated in `02-trust-boundaries.md`. Summary:

1. Android app process ↔ Android Keystore (hardware boundary)
2. Android app ↔ OS / other apps (process isolation)
3. Android app ↔ relay server (internet trust boundary)
4. Android app ↔ Tor network (anonymity network boundary)
5. Android app ↔ BLE mesh (RF/proximity boundary)
6. Android app ↔ WiFi Direct peer (RF/proximity boundary)
7. Primary Android device ↔ linked desktop device
8. Relay server ↔ Oracle Cloud infrastructure (cloud trust boundary)
9. BLE mesh node ↔ BLE mesh node (multi-hop relay boundary)

---

## 5. Assumptions

1. Signal Protocol implementation (`libsignal-client`) is cryptographically correct. Implementation-specific bugs are out of scope; the library is treated as trusted.
2. Android OS and hardware security module are not compromised at the kernel or firmware level.
3. The relay server is correctly deployed behind HTTPS with a valid TLS certificate. TLS interception between client and relay is a threat (no certificate pinning currently).
4. Users are the threat model's "trusting party" — social engineering of the end user (e.g. being tricked into scanning a malicious QR) is a valid attack surface.
5. The attacker does not have physical access to an unlocked device (physical access = game over for most properties).
6. BLE and WiFi Direct advertisements are observable by any device within radio range.

---

## 6. Out of Scope

- Signal Protocol cryptographic correctness (library-level vulnerabilities)
- Android OS kernel / TEE firmware vulnerabilities
- Oracle Cloud infrastructure attacks beyond what the relay server operator could perform
- Side-channel attacks (timing, power analysis) against hardware crypto operations
- Supply chain attacks against build toolchain or dependencies (noted but not analysed)
- Reticulum/LoRa transport (Phase 10 — not yet implemented)
- ATAK plugin (Phase 11 — not yet implemented)
- MLS group messaging protocol (roadmap — not yet implemented)

---

## 7. Security Properties and Goals

| Property | Goal | Current Status |
|----------|------|----------------|
| Confidentiality of message content | Signal E2E encryption on all transports | Achieved |
| Forward secrecy | Double Ratchet per-message key evolution | Achieved |
| Post-compromise security | Double Ratchet ratcheting | Achieved |
| Sender/recipient anonymity from relay | Tor relay mode masks IP | Partially achieved — non-Tor mode exposes IP |
| Sender/recipient anonymity from BLE observers | SHA-256 hashed IDs in advertisements | Partially achieved — hashes are stable, trackable |
| Metadata minimisation at relay | Relay sees pseudonymous IDs + sizes + timestamps | Gap — correlation attacks remain feasible |
| QR enrolment integrity | User approves device, public key in QR | Gap — no one-time-use, no replay window |
| Post-quantum confidentiality | Not implemented | Gap — HNDL vulnerability |
| Deniable authentication | Signal Protocol OTR-style deniability | Achieved |
| Device identity binding | Android Keystore hardware-backed key | Achieved on Android; desktop uses software key |
