#ifndef CRYPTO_SESSION_KEYS_H
#define CRYPTO_SESSION_KEYS_H

#include <array>
#include <sodium.h>

#include "handshake.h"

using SessionKey =
    std::array<unsigned char, crypto_aead_chacha20poly1305_ietf_KEYBYTES>;

struct SessionKeys
{
    SessionKey clientToServer{};
    SessionKey serverToClient{};
};

// Derive independent traffic keys from the X25519 shared secret.
bool deriveSessionKeys(
    SessionKeys& sessionKeys,
    const X25519SharedSecret& sharedSecret);

// Remove all derived session-key material from memory.
void wipeSessionKeys(SessionKeys& sessionKeys);

#endif
