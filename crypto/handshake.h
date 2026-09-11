#ifndef CRYPTO_HANDSHAKE_H
#define CRYPTO_HANDSHAKE_H

#include <array>
#include <sodium.h>
#include <string>

using X25519PublicKey =
    std::array<unsigned char, crypto_scalarmult_curve25519_BYTES>;
using X25519PrivateKey =
    std::array<unsigned char, crypto_scalarmult_curve25519_SCALARBYTES>;
using X25519SharedSecret =
    std::array<unsigned char, crypto_scalarmult_curve25519_BYTES>;

struct X25519KeyPair
{
    X25519PublicKey publicKey{};
    X25519PrivateKey privateKey{};
};

// Initialize Libsodium before any cryptographic operation.
bool initializeCrypto();

// Generate a fresh ephemeral X25519 private/public key pair.
bool generateX25519KeyPair(X25519KeyPair& keyPair);

// Derive the X25519 shared secret from one private key and the peer public key.
bool deriveX25519SharedSecret(
    X25519SharedSecret& sharedSecret,
    const X25519PrivateKey& privateKey,
    const X25519PublicKey& otherPublicKey);

// Remove private key and shared-secret material from memory when no longer needed.
void wipeX25519PrivateKey(X25519KeyPair& keyPair);
void wipeX25519SharedSecret(X25519SharedSecret& sharedSecret);

// Encode/decode a public key for the existing text-based UDP handshake messages.
std::string encodeX25519PublicKey(const X25519PublicKey& publicKey);
bool decodeX25519PublicKey(
    const std::string& encodedKey,
    X25519PublicKey& publicKey);

// Return a short SHA-256 fingerprint for safe shared-secret comparison in tests.
std::string sharedSecretFingerprint(const X25519SharedSecret& sharedSecret);

#endif
