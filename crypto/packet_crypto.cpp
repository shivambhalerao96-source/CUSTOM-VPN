#include "packet_crypto.h"

#include <sodium.h>

namespace
{
constexpr std::size_t kNonceBytes =
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t kAuthenticationTagBytes =
    crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr std::size_t kKeyBytes = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;

static_assert(sizeof(SessionKey) == kKeyBytes);
}

bool encryptVpnPacket(
    const unsigned char* plaintext,
    std::size_t plaintextLength,
    const SessionKey& key,
    std::vector<unsigned char>& encryptedPacket)
{
    encryptedPacket.clear();

    if (plaintext == nullptr || plaintextLength > kMaxVpnPlaintextBytes)
        return false;

    if (!initializeCrypto())
        return false;

    encryptedPacket.resize(kNonceBytes + plaintextLength + kAuthenticationTagBytes);
    unsigned char* nonce = encryptedPacket.data();
    unsigned char* ciphertext = encryptedPacket.data() + kNonceBytes;
    unsigned long long ciphertextLength = 0;

    randombytes_buf(nonce, kNonceBytes);

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext,
            &ciphertextLength,
            plaintext,
            static_cast<unsigned long long>(plaintextLength),
            nullptr,
            0,
            nullptr,
            nonce,
            key.data()) != 0)
    {
        encryptedPacket.clear();
        return false;
    }

    encryptedPacket.resize(kNonceBytes + static_cast<std::size_t>(ciphertextLength));
    if (encryptedPacket.size() > kMaxVpnUdpPayloadBytes)
    {
        encryptedPacket.clear();
        return false;
    }

    return true;
}

bool decryptVpnPacket(
    const unsigned char* encryptedPacket,
    std::size_t encryptedPacketLength,
    const SessionKey& key,
    std::vector<unsigned char>& plaintext)
{
    plaintext.clear();

    if (encryptedPacket == nullptr ||
        encryptedPacketLength < kNonceBytes + kAuthenticationTagBytes ||
        encryptedPacketLength > kMaxVpnUdpPayloadBytes)
    {
        return false;
    }

    if (!initializeCrypto())
        return false;

    const unsigned char* nonce = encryptedPacket;
    const unsigned char* ciphertext = encryptedPacket + kNonceBytes;
    const std::size_t ciphertextLength = encryptedPacketLength - kNonceBytes;
    plaintext.resize(ciphertextLength - kAuthenticationTagBytes);
    unsigned long long plaintextLength = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintextLength,
            nullptr,
            ciphertext,
            static_cast<unsigned long long>(ciphertextLength),
            nullptr,
            0,
            nonce,
            key.data()) != 0)
    {
        plaintext.clear();
        return false;
    }

    plaintext.resize(static_cast<std::size_t>(plaintextLength));
    return true;
}
