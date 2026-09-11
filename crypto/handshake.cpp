#include "handshake.h"

using namespace std;

namespace
{
int hexValue(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';

    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;

    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;

    return -1;
}
}

bool initializeCrypto()
{
    return sodium_init() >= 0;
}

bool generateX25519KeyPair(X25519KeyPair& keyPair)
{
    keyPair.publicKey.fill(0);
    keyPair.privateKey.fill(0);

    if (!initializeCrypto())
        return false;

    randombytes_buf(keyPair.privateKey.data(), keyPair.privateKey.size());

    if (crypto_scalarmult_curve25519_base(
            keyPair.publicKey.data(), keyPair.privateKey.data()) != 0)
    {
        wipeX25519PrivateKey(keyPair);
        return false;
    }

    return true;
}

bool deriveX25519SharedSecret(
    X25519SharedSecret& sharedSecret,
    const X25519PrivateKey& privateKey,
    const X25519PublicKey& otherPublicKey)
{
    sharedSecret.fill(0);

    if (!initializeCrypto())
        return false;

    if (crypto_scalarmult_curve25519(
            sharedSecret.data(), privateKey.data(), otherPublicKey.data()) != 0)
    {
        wipeX25519SharedSecret(sharedSecret);
        return false;
    }

    X25519SharedSecret zeroSecret{};
    if (sodium_memcmp(
            sharedSecret.data(), zeroSecret.data(), sharedSecret.size()) == 0)
    {
        wipeX25519SharedSecret(sharedSecret);
        return false;
    }

    return true;
}

void wipeX25519PrivateKey(X25519KeyPair& keyPair)
{
    sodium_memzero(keyPair.privateKey.data(), keyPair.privateKey.size());
}

void wipeX25519SharedSecret(X25519SharedSecret& sharedSecret)
{
    sodium_memzero(sharedSecret.data(), sharedSecret.size());
}

string encodeX25519PublicKey(const X25519PublicKey& publicKey)
{
    char encodedKey[crypto_scalarmult_curve25519_BYTES * 2 + 1];

    sodium_bin2hex(
        encodedKey,
        sizeof(encodedKey),
        publicKey.data(),
        publicKey.size());

    return string(encodedKey);
}

bool decodeX25519PublicKey(
    const string& encodedKey,
    X25519PublicKey& publicKey)
{
    publicKey.fill(0);

    if (encodedKey.size() != crypto_scalarmult_curve25519_BYTES * 2)
        return false;

    for (size_t i = 0; i < publicKey.size(); i++)
    {
        int high = hexValue(encodedKey[i * 2]);
        int low = hexValue(encodedKey[i * 2 + 1]);

        if (high < 0 || low < 0)
            return false;

        publicKey[i] = static_cast<unsigned char>((high << 4) | low);
    }

    return true;
}

string sharedSecretFingerprint(const X25519SharedSecret& sharedSecret)
{
    unsigned char digest[crypto_hash_sha256_BYTES];
    char encodedDigest[17];

    if (crypto_hash_sha256(
            digest,
            sharedSecret.data(),
            sharedSecret.size()) != 0)
    {
        return "";
    }

    sodium_bin2hex(encodedDigest, sizeof(encodedDigest), digest, 8);
    return string(encodedDigest);
}
