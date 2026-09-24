#include "session_keys.h"

namespace
{
constexpr char kSessionKeyContext[crypto_kdf_CONTEXTBYTES] = {
    'C', 'V', 'P', 'N', 'K', 'E', 'Y', '1'};
constexpr uint64_t kClientToServerSubkeyId = 1;
constexpr uint64_t kServerToClientSubkeyId = 2;

static_assert(sizeof(kSessionKeyContext) == crypto_kdf_CONTEXTBYTES);
static_assert(sizeof(X25519SharedSecret) == crypto_kdf_KEYBYTES);
static_assert(sizeof(SessionKey) == crypto_kdf_KEYBYTES);
}

bool deriveSessionKeys(
    SessionKeys& sessionKeys,
    const X25519SharedSecret& sharedSecret)
{
    wipeSessionKeys(sessionKeys);

    if (!initializeCrypto())
        return false;

    if (crypto_kdf_derive_from_key(
            sessionKeys.clientToServer.data(),
            sessionKeys.clientToServer.size(),
            kClientToServerSubkeyId,
            kSessionKeyContext,
            sharedSecret.data()) != 0)
    {
        wipeSessionKeys(sessionKeys);
        return false;
    }

    if (crypto_kdf_derive_from_key(
            sessionKeys.serverToClient.data(),
            sessionKeys.serverToClient.size(),
            kServerToClientSubkeyId,
            kSessionKeyContext,
            sharedSecret.data()) != 0)
    {
        wipeSessionKeys(sessionKeys);
        return false;
    }

    return true;
}

void wipeSessionKeys(SessionKeys& sessionKeys)
{
    sodium_memzero(
        sessionKeys.clientToServer.data(),
        sessionKeys.clientToServer.size());
    sodium_memzero(
        sessionKeys.serverToClient.data(),
        sessionKeys.serverToClient.size());
}
