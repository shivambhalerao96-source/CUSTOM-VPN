#include "../crypto/handshake.h"
#include "../crypto/packet_crypto.h"
#include "../crypto/session_keys.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace
{
bool require(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << std::endl;
    return condition;
}
}

int main()
{
    if (!require(initializeCrypto(), "Libsodium initialization"))
        return EXIT_FAILURE;

    X25519KeyPair clientKeyPair{};
    X25519KeyPair serverKeyPair{};
    X25519SharedSecret clientSecret{};
    X25519SharedSecret serverSecret{};
    SessionKeys clientKeys{};
    SessionKeys serverKeys{};

    bool ok =
        require(generateX25519KeyPair(clientKeyPair), "client key generation") &&
        require(generateX25519KeyPair(serverKeyPair), "server key generation") &&
        require(deriveX25519SharedSecret(
                    clientSecret,
                    clientKeyPair.privateKey,
                    serverKeyPair.publicKey),
                "client shared-secret derivation") &&
        require(deriveX25519SharedSecret(
                    serverSecret,
                    serverKeyPair.privateKey,
                    clientKeyPair.publicKey),
                "server shared-secret derivation") &&
        require(deriveSessionKeys(clientKeys, clientSecret), "client session-key derivation") &&
        require(deriveSessionKeys(serverKeys, serverSecret), "server session-key derivation");

    if (!ok)
    {
        wipeX25519PrivateKey(clientKeyPair);
        wipeX25519PrivateKey(serverKeyPair);
        wipeX25519SharedSecret(clientSecret);
        wipeX25519SharedSecret(serverSecret);
        wipeSessionKeys(clientKeys);
        wipeSessionKeys(serverKeys);
        return EXIT_FAILURE;
    }

    const std::string message = "layer three authenticated VPN packet";
    const std::vector<unsigned char> expected(message.begin(), message.end());
    std::vector<unsigned char> encrypted;
    std::vector<unsigned char> decrypted;
    std::vector<unsigned char> secondEncrypted;

    ok = ok && require(
        encryptVpnPacket(
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            clientKeys.clientToServer,
            encrypted),
        "C2S encryption");

    ok = ok && require(
        decryptVpnPacket(
            encrypted.data(),
            encrypted.size(),
            serverKeys.clientToServer,
            decrypted),
        "C2S decryption");

    ok = ok && require(decrypted == expected, "round-trip plaintext");

    ok = ok && require(
        encryptVpnPacket(
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            clientKeys.clientToServer,
            secondEncrypted),
        "second C2S encryption");

    ok = ok && require(
        !std::equal(
            encrypted.begin(),
            encrypted.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
            secondEncrypted.begin()),
        "fresh random nonces");

    std::vector<unsigned char> tampered = encrypted;
    tampered[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] ^= 0x01;
    ok = ok && require(
        !decryptVpnPacket(
            tampered.data(),
            tampered.size(),
            serverKeys.clientToServer,
            decrypted),
        "tampered ciphertext rejection");

    ok = ok && require(
        !decryptVpnPacket(
            encrypted.data(),
            encrypted.size(),
            serverKeys.serverToClient,
            decrypted),
        "wrong directional-key rejection");

    std::vector<unsigned char> reverseEncrypted;
    ok = ok && require(
        encryptVpnPacket(
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            serverKeys.serverToClient,
            reverseEncrypted),
        "S2C encryption");

    ok = ok && require(
        decryptVpnPacket(
            reverseEncrypted.data(),
            reverseEncrypted.size(),
            clientKeys.serverToClient,
            decrypted),
        "S2C decryption");

    ok = ok && require(decrypted == expected, "reverse-direction plaintext");

    wipeX25519PrivateKey(clientKeyPair);
    wipeX25519PrivateKey(serverKeyPair);
    wipeX25519SharedSecret(clientSecret);
    wipeX25519SharedSecret(serverSecret);
    wipeSessionKeys(clientKeys);
    wipeSessionKeys(serverKeys);

    if (ok)
    {
        std::cout << "Layer 3 local tests passed." << std::endl;
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
