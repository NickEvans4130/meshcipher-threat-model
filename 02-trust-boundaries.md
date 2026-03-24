# 02 — Trust Boundaries

Every trust boundary represents a point where data crosses from one trust domain to another and where an adversary may have the ability to observe, modify, or block the flow. STRIDE threats are enumerated at each boundary crossing in `03-stride-analysis/`.

---

## TB-01: Android App Process ↔ Android Keystore (Hardware)

**Description:** The Android app requests cryptographic operations from the hardware-backed Keystore (TEE or StrongBox). The private key never leaves the hardware boundary — the app passes data in, receives signed/encrypted output back.

**What crosses the boundary:** Plaintext challenges (for signing), ciphertext (for decryption), signatures and encrypted blobs (returned by hardware).

**Adversary capability at boundary:** An attacker with OS-level code execution cannot extract the private key from the TEE. However, they can call the Keystore API on behalf of the app (if they have the same UID or root) to perform signing operations.

**Protections in place:** Biometric authentication gate (30s validity window); Android Keystore non-exportable flag; hardware isolation.

**Residual risk:** Key can be used (not extracted) by any process with root or the app's UID. Biometric bypass = key use bypass.

---

## TB-02: Android App Process ↔ Android OS / Other Apps

**Description:** The app process is isolated from other apps by Android's UID-based sandboxing. Data shared via Intents, ContentProviders, or broadcast receivers crosses this boundary.

**What crosses the boundary:** QR scan results (Intent from CameraX), Bluetooth/WiFi scan results (system broadcasts), media file URIs, notification data.

**Adversary capability at boundary:** Malicious app with appropriate permissions could intercept implicit Intents, register for same broadcast events, or access ContentProvider if exported without permissions.

**Protections in place:** App uses explicit Intents for QR results; SQLCipher DB not exported; EncryptedSharedPreferences not accessible to other apps.

**Residual risk:** Notification content could leak if notification access is granted to a third-party app.

---

## TB-03: Android App ↔ Oracle Cloud Relay Server (Internet)

**Description:** The primary internet trust boundary. The app communicates with the relay over HTTPS/WSS.

**What crosses the boundary:** Authentication credentials (JWT), encrypted message payloads, sender/recipient pseudonymous IDs, content types, timestamps. The relay server also receives the client's IP address on every request.

**Adversary capability at boundary:**
- **Passive network observer (ISP, national infrastructure):** Can see TLS SNI (relay server hostname), connection duration, data volumes; cannot read payload (TLS).
- **Active MITM:** Can attempt TLS interception. Currently no certificate pinning — a rogue CA can issue a valid cert for the relay domain.
- **Relay operator:** Full access to all metadata enumerated in `dfd-relay-server.md`. Cannot read Signal-encrypted content.

**Protections in place:** TLS 1.2+; JWT authentication; rate limiting; input validation.

**Gaps:** No certificate pinning; JWT is HS256 (symmetric — relay holds the secret); no message size padding.

---

## TB-04: Android App ↔ Tor Network

**Description:** Traffic routed through the local Tor SOCKS5 proxy exits into the Tor network. This boundary provides IP anonymity but introduces Tor-specific risks.

**What crosses the boundary:** Tor cells (layered encryption); app cannot observe internal Tor routing.

**Adversary capability at boundary:**
- **Guard node:** Knows sender's real IP but not destination.
- **Exit node (relay-via-Tor mode only):** Sees destination relay server IP and connection metadata; cannot see Tor sender's IP; cannot read TLS payload.
- **Global passive adversary:** Traffic correlation attack — observe entry and exit to deanonymise if controlling both guard and exit.
- **Hidden service (P2P mode):** Both parties are protected; adversary needs to compromise the rendezvous point or perform timing correlation.

**Protections in place:** Tor onion encryption (3 layers); hidden service protocol; ephemeral circuit selection.

**Gaps:** Persistent ED25519 hidden service key creates a stable long-term pseudonym; `.onion` address reuse across sessions; timing correlation by global adversary.

---

## TB-05: Android App ↔ BLE Medium (Radio Frequency)

**Description:** BLE advertisements and GATT connections cross the RF boundary. Any BLE-capable device within ~30m range can passively observe advertisements without authentication.

**What crosses the boundary (advertisements):** SHA-256(deviceId), SHA-256(userId), messageType, service UUID, TX power, RSSI, timestamp — broadcast continuously.

**What crosses the boundary (GATT):** Full `MeshMessage` — originDeviceId, originUserId, destinationUserId, TTL, hopCount, path (plaintext routing chain), Signal ciphertext payload.

**Adversary capability at boundary:** Any BLE scanner within range can record all advertisement data. Relay nodes receive full MeshMessage headers. No authentication required to receive advertisements.

**Protections in place:** Signal E2E on payload; ECDSA signature on advertisement packets (authenticity of advertisement source).

**Gaps:** No identifier rotation (hashes are stable); service UUID is static and public; path field in MeshMessage exposes routing graph; no attestation of relay nodes.

---

## TB-06: Android App ↔ WiFi Direct Peer

**Description:** WiFi Direct creates a WPA2-secured P2P link. The Group Owner assigns IP addresses; both devices get link-local addresses.

**What crosses the boundary:** `WifiDirectMessage` objects serialized via Java `ObjectOutputStream`; Signal ciphertext payloads; file transfer chunks.

**Adversary capability at boundary:** Passive RF eavesdropping requires WPA2 PSK. Active attacker needs to be within range and successfully negotiate P2P group membership. Java deserialization of `ObjectInputStream` is a risk if attacker can inject into the stream.

**Protections in place:** WPA2 link-layer encryption; Signal E2E on content.

**Gaps:** Java Serializable deserialization surface; Group Owner IP visible to client; simultaneous active scan required (timing oracle for presence detection).

---

## TB-07: Primary Android Device ↔ Linked Desktop Device

**Description:** The enrolment trust boundary — the moment when the desktop's public key is transferred to the Android device. Subsequent message forwarding crosses this boundary via the relay.

**What crosses the boundary (enrolment):** `DeviceLinkRequest` JSON in a QR code on a screen — plaintext, visually accessible.

**What crosses the boundary (forwarding):** Signal-encrypted messages forwarded from primary Android to desktop via relay.

**Adversary capability at boundary:**
- **Visual access to enrolment screen:** Can photograph QR; can then approve their own device as a linked device on any Android.
- **Replay:** Same QR has no time-bounded one-time-use enforcement.
- **Relay (during forwarding):** Sees metadata of forwarded messages (as per TB-03).

**Protections in place:** User approval step; EC P-256 public key fingerprint displayed (partial — 24 chars).

**Gaps:** No one-time-use nonce; no timestamp freshness validation; no binding to specific Android device; no desktop confirmation of successful link.

---

## TB-08: Relay Server ↔ Oracle Cloud Infrastructure

**Description:** The relay server process runs within Oracle Cloud. The cloud provider has administrative access to the VM, network, and storage.

**What crosses the boundary:** All relay server data — the full database, logs, network traffic, environment variables (including the JWT HS256 secret).

**Adversary capability at boundary:**
- **Oracle Cloud (compelled or insider):** Full access to all metadata. Cannot read Signal-encrypted content but can access the complete communication graph.
- **VM compromise (via relay server vulnerability):** Access to DB file, JWT secret, all queued messages.

**Protections in place:** Rate limiting; input validation; security headers; DB access controlled by Flask app.

**Gaps:** JWT HS256 secret in environment — if server is compromised, all current and future tokens are forgeable; no DB encryption at rest mentioned in `server.py`; no audit logging beyond access logs.

---

## TB-09: BLE Mesh Relay Node ↔ Next Hop

**Description:** Each hop in the BLE mesh is a trust boundary. A device acting as a relay node is not authenticated or attested — any device can participate in routing.

**What crosses the boundary:** Full `MeshMessage` including plaintext routing metadata (originDeviceId, destinationUserId, path, hopCount, TTL) and Signal ciphertext.

**Adversary capability at boundary:** A compromised or adversary-controlled relay node can:
- Read all routing metadata for every message it relays
- Modify TTL, hopCount, or path fields (no cryptographic binding)
- Drop messages (DoS)
- Replay messages
- Correlate traffic across multiple controlled nodes (Sybil)

**Protections in place:** Signal E2E on payload (content cannot be read); TTL limits propagation range.

**Gaps:** No relay node attestation; routing metadata is plaintext; MeshMessage fields (TTL, hopCount, path) are not cryptographically bound to content; no Sybil resistance mechanism.

---

## Trust Boundary Summary Table

| ID | Boundary | Crossed by | Adversary at boundary can… | Gap? |
|----|----------|-----------|---------------------------|------|
| TB-01 | App ↔ Android Keystore | Crypto ops | Use key (not extract) with root | Low |
| TB-02 | App ↔ OS / other apps | Intents, broadcasts | Intercept implicit Intents; notifications | Low |
| TB-03 | App ↔ Relay server | HTTPS/WSS | See metadata graph; MITM (no pinning) | **Yes** |
| TB-04 | App ↔ Tor network | Tor cells | Timing correlation (global adversary) | Medium |
| TB-05 | App ↔ BLE medium | BLE ads + GATT | Passive presence tracking; path graph | **Yes** |
| TB-06 | App ↔ WiFi Direct peer | TCP ObjectStream | Deserialization attack | Medium |
| TB-07 | Android ↔ Linked desktop | QR visual channel | Photograph QR; rogue device enrolment | **Yes** |
| TB-08 | Relay server ↔ Oracle Cloud | VM-level access | Full metadata DB; JWT secret | **Yes** |
| TB-09 | BLE mesh hop ↔ hop | MeshMessage relay | Read routing graph; modify headers; Sybil | **Yes** |
