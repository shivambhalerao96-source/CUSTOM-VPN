# CUSTOM-VPN

A VPN built from scratch under the guidance of ProjectX.

## Current cryptographic layers

### Layer 1: Ephemeral X25519 key agreement

The client and server independently generate ephemeral X25519 key pairs and exchange only their public keys during the UDP handshake.

Both sides derive the same shared secret locally; the shared secret is never transmitted.

The Layer 1 implementation is located in:

- `crypto/handshake.h`
- `crypto/handshake.cpp`

### Layer 2: Session-key derivation

Layer 2 derives two independent symmetric session keys from the X25519 shared secret using Libsodium's `crypto_kdf_derive_from_key()` API.

```text
X25519 shared secret
        |
        v
Libsodium KDF
   |         |
   v         v
C2S key    S2C key
```

The derived keys are stored in the following structure:

```cpp
struct SessionKeys
{
    SessionKey clientToServer;
    SessionKey serverToClient;
};
```

The KDF uses the application context `CVPNKEY1` and separate subkey IDs for the client-to-server and server-to-client directions. Therefore:

- the client and server derive matching directional keys independently;
- the two directional keys are different;
- session keys are not transmitted over UDP;
- session keys are not logged or stored as strings.

Layer 2 is implemented in:

- `crypto/session_keys.h`
- `crypto/session_keys.cpp`

The client derives and retains its `SessionKeys` for the VPN session. The server stores a separate `SessionKeys` instance for each registered client.

Session-key material is wiped with Libsodium's `sodium_memzero()` when it is no longer needed.

### Layer 3: Packet encryption

Layer 3 encrypts each VPN packet with Libsodium's
`crypto_aead_xchacha20poly1305_ietf` API. The packet format is
`[nonce][ciphertext + authentication tag]`, with a fresh random nonce for
each packet. The C2S and S2C operations use the corresponding Layer 2
directional session key.

### Layer 4: Integrity and authentication

Layer 4 uses the Poly1305 authentication component already included in the
Layer 3 XChaCha20-Poly1305 AEAD operation. The receiver verifies the tag as
part of decryption and drops failures before writing anything to TUN. A
second independent Poly1305 pass is intentionally not added.

The Layer 3 and Layer 4 implementation details are documented in:

- `docs/layer3/README.md`
- `docs/layer4/README.md`

## Current scope

Layers 1 through 4 are implemented locally. Replay protection and packet
sequence numbers remain deferred to Layer 5. Key rotation is also not
implemented.

The current handshake is unauthenticated, so X25519 key agreement alone does not provide protection against a man-in-the-middle attack.

## Validation

The Layer 2 implementation has been validated by:

- compiling and linking the client and server with Libsodium;
- deriving keys independently from both sides of an X25519 exchange;
- verifying that matching directions produce equal keys;
- verifying that the two directions produce different keys.
