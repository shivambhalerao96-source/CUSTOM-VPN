#include "../crypto/handshake.h"
#include "../crypto/packet_crypto.h"
#include "../crypto/session_keys.h"

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

    const std::string message = "Layer 4 authenticated VPN packet";
    const std::vector<unsigned char> expected(message.begin(), message.end());
    std::vector<unsigned char> encrypted;
    std::vector<unsigned char> decrypted;

    ok = require(
        encryptVpnPacket(
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            clientKeys.clientToServer,
            encrypted),
        "C2S authenticated encryption");

    ok = ok && require(
        decryptVpnPacket(
            encrypted.data(),
            encrypted.size(),
            serverKeys.clientToServer,
            decrypted),
        "C2S authentication verification");
    ok = ok && require(decrypted == expected, "C2S authenticated plaintext");

    std::vector<unsigned char> reverseEncrypted;
    ok = ok && require(
        encryptVpnPacket(
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            serverKeys.serverToClient,
            reverseEncrypted),
        "S2C authenticated encryption");
    ok = ok && require(
        decryptVpnPacket(
            reverseEncrypted.data(),
            reverseEncrypted.size(),
            clientKeys.serverToClient,
            decrypted),
        "S2C authentication verification");
    ok = ok && require(decrypted == expected, "S2C authenticated plaintext");

    std::vector<unsigned char> tamperedCiphertext = encrypted;
    tamperedCiphertext[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] ^= 0x01;
    decrypted = {0xAA};
    ok = ok && require(
        !decryptVpnPacket(
            tamperedCiphertext.data(),
            tamperedCiphertext.size(),
            serverKeys.clientToServer,
            decrypted),
        "modified ciphertext rejection");
    ok = ok && require(decrypted.empty(), "modified ciphertext plaintext is not released");

    std::vector<unsigned char> tamperedTag = encrypted;
    tamperedTag.back() ^= 0x01;
    decrypted = {0xAA};
    ok = ok && require(
        !decryptVpnPacket(
            tamperedTag.data(),
            tamperedTag.size(),
            serverKeys.clientToServer,
            decrypted),
        "modified authentication-tag rejection");
    ok = ok && require(decrypted.empty(), "modified tag plaintext is not released");

    SessionKey wrongKey = serverKeys.clientToServer;
    wrongKey[0] ^= 0x01;
    decrypted = {0xAA};
    ok = ok && require(
        !decryptVpnPacket(
            encrypted.data(),
            encrypted.size(),
            wrongKey,
            decrypted),
        "wrong session-key rejection");
    ok = ok && require(decrypted.empty(), "wrong-key plaintext is not released");

    std::vector<unsigned char> malformed = {0x01};
    ok = ok && require(
        !decryptVpnPacket(nullptr, 0, serverKeys.clientToServer, decrypted),
        "empty packet rejection");
    ok = ok && require(
        !decryptVpnPacket(
            malformed.data(),
            malformed.size(),
            serverKeys.clientToServer,
            decrypted),
        "short packet rejection");

    sodium_memzero(wrongKey.data(), wrongKey.size());
    wipeX25519PrivateKey(clientKeyPair);
    wipeX25519PrivateKey(serverKeyPair);
    wipeX25519SharedSecret(clientSecret);
    wipeX25519SharedSecret(serverSecret);
    wipeSessionKeys(clientKeys);
    wipeSessionKeys(serverKeys);

    if (ok)
    {
        std::cout << "Layer 4 local tests passed." << std::endl;
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
