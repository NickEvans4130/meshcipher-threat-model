# STRIDE Analysis — WiFi Direct Transport

## Component Description

WiFi Direct provides P2P connectivity at ~100m range without infrastructure. Android OS negotiates Group Owner (GO) and client roles. MeshCipher binds a TCP `ServerSocket` on port 8988 at the GO and uses Java `ObjectInputStream`/`ObjectOutputStream` for message serialisation.

**References:** `app/.../wifidirect/`, `docs/wifi_direct.md`

---

## STRIDE Threat Table

| Threat ID | Category | Component | Attack Scenario | Signal Protocol mitigates? | Likelihood | Impact | Status |
|-----------|----------|-----------|-----------------|---------------------------|------------|--------|--------|
| WFD-S-01 | Spoofing | P2P peer identity | WiFi Direct peer negotiation uses device-level identity (Android assigns a P2P device address). No application-level authentication before the TCP connection is established. A rogue device within range can connect to the GO ServerSocket on port 8988 and present itself as any senderId. Signal session key verification at the application layer is the only check. | Partially — Signal session must be established before plaintext flows; unrecognised sender triggers new session | Low | Medium | Partially mitigated — Signal session rejects unrecognised senders at application layer |
| WFD-S-02 | Spoofing | Group Owner role | Android OS determines GO role non-deterministically. If an adversary device manages to negotiate GO role (e.g., in a three-way discovery scenario), it controls the ServerSocket and can actively intercept connections. Combined with WFD-S-01, could attempt session establishment attacks. | Partially — Signal MITM detected via safety number | Low | Medium | Partially mitigated — Signal safety number closes the loop |
| WFD-T-01 | Tampering | Java deserialization (ObjectInputStream) | `ObjectInputStream.readObject()` deserializes whatever object the peer sends. A malicious or compromised peer (or attacker who has compromised the WPA2 link) sends a crafted gadget chain targeting Android's classpath. Could execute arbitrary code in the app process. | No — operates below Signal layer | Low | Critical | Gap — Java Serializable deserialization is an unnecessary risk; should use typed binary format (protobuf, CBOR, or simple length-prefixed bytes) |
| WFD-T-02 | Tampering | Signal ciphertext in transit | WPA2 link-layer protects the TCP stream. Signal AEAD on the payload provides end-to-end tamper detection. A MITM who can break WPA2 (rare but possible with known PSK) still cannot tamper with Signal content undetected. | Yes — Signal AEAD | Low | Low | Mitigated |
| WFD-R-01 | Repudiation | Message origin | No application-level signed delivery receipt. Sender cannot prove recipient received message. Repudiation is consistent with Signal's deniability property. | N/A | N/A | N/A | Accepted |
| WFD-I-01 | Information Disclosure | Link-local IP address | `WifiP2pInfo.groupOwnerAddress` exposes the GO's IP to the client. This is a link-local address (not internet-routable) but can be used to fingerprint a device across sessions (if the same link-local IP is assigned). | No | Low | Low | Accepted — link-local addresses are session-scoped in most cases |
| WFD-I-02 | Information Disclosure | Scan timing / presence detection | Both devices must actively scan for peers simultaneously, generating WiFi probe requests observable to third-party monitoring equipment. Observer learns that a device is actively seeking WiFi Direct peers — a coarse presence signal. | No | Low | Low | Accepted |
| WFD-I-03 | Information Disclosure | Message size (unpadded) | `encryptedContent` field size reflects approximate plaintext length. No padding. Observable by any device that has compromised the WPA2 link. | Partially — Signal encrypts content; size not padded | Low | Low | Accepted |
| WFD-D-01 | Denial of Service | Port 8988 binding conflict | Another app on the GO device binds TCP port 8988 before MeshCipher. `ServerSocket` creation fails; no WiFi Direct messages can be received. | No | Low | Low | Accepted — low probability; port selection is an implementation detail |
| WFD-D-02 | Denial of Service | P2P discovery interference | Adversary device sends continuous WiFi Direct probe responses, exhausting the GO's connection slot budget. Legitimate devices cannot connect. | No | Low | Medium | Accepted — WiFi Direct infrastructure-level limitation |
| WFD-D-03 | Denial of Service | FileTransfer chunk flooding | Adversary initiates a FileTransfer and sends an extremely large number of chunks, exhausting memory or storage on the recipient device. No explicit chunk count or size limit visible in the wire protocol definition. | No | Low | Medium | Gap — no max file size or chunk count validation visible in source |
| WFD-E-01 | Elevation of Privilege | RCE via Java deserialization (WFD-T-01 escalation) | If WFD-T-01 is exploited with a working gadget chain, attacker achieves arbitrary code execution in the app process. At app's UID, attacker can access EncryptedSharedPreferences, SQLCipher DB, and call Android Keystore APIs. This is the highest-severity escalation path for the WiFi Direct transport. | No — below Signal layer | Low | Critical | Gap — see WFD-T-01 |

---

## Key Observations

**Java deserialization (WFD-T-01 / WFD-E-01) is the highest-severity finding for this transport.** `ObjectInputStream` with `Serializable` objects is a well-documented RCE surface. The WPA2 link layer provides some protection (attacker must be within range and know the PSK), but this is not a sufficient justification for using a deserialisation API that can lead to code execution. The fix is straightforward: replace `ObjectInputStream`/`ObjectOutputStream` with a typed binary protocol (e.g., simple length-prefixed byte arrays with a fixed message type header). This is documented as a gap with High remediation priority.

**WiFi Direct has no relay server involvement**, making it one of the cleanest transports from a metadata perspective. The only metadata exposed is timing and sizes to any 802.11 monitor within range — a much more constrained adversary than the relay operator.
