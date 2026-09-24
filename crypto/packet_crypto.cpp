#include "packet_crypto.h"

#include <sodium.h>

namespace
{
constexpr std::size_t kNonceBytes =
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t kAuthenticationTagBytes =
    crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr std::size_t kKeyBytes = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
constexpr std::size_t kSequenceBytes = sizeof(std::uint64_t);
constexpr std::size_t kSequencedHeaderBytes = kSequenceBytes + kNonceBytes;

static_assert(sizeof(SessionKey) == kKeyBytes);

void writeSequence(std::uint64_t sequence, unsigned char* output)
{
    for (std::size_t i = 0; i < kSequenceBytes; ++i)
    {
        const std::size_t shift = (kSequenceBytes - 1 - i) * 8;
        output[i] = static_cast<unsigned char>(sequence >> shift);
    }
}

std::uint64_t readSequence(const unsigned char* input)
{
    std::uint64_t sequence = 0;
    for (std::size_t i = 0; i < kSequenceBytes; ++i)
        sequence = (sequence << 8) | input[i];
    return sequence;
}
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

bool encryptSequencedVpnPacket(
    std::uint64_t sequence,
    const unsigned char* plaintext,
    std::size_t plaintextLength,
    const SessionKey& key,
    std::vector<unsigned char>& encryptedPacket)
{
    encryptedPacket.clear();

    if (sequence == 0 || plaintext == nullptr ||
        plaintextLength > kMaxVpnUdpPayloadBytes -
                              kSequencedHeaderBytes -
                              kAuthenticationTagBytes)
    {
        return false;
    }

    if (!initializeCrypto())
        return false;

    encryptedPacket.resize(
        kSequencedHeaderBytes + plaintextLength + kAuthenticationTagBytes);
    writeSequence(sequence, encryptedPacket.data());
    unsigned char* nonce = encryptedPacket.data() + kSequenceBytes;
    unsigned char* ciphertext = encryptedPacket.data() + kSequencedHeaderBytes;
    unsigned long long ciphertextLength = 0;

    randombytes_buf(nonce, kNonceBytes);

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext,
            &ciphertextLength,
            plaintext,
            static_cast<unsigned long long>(plaintextLength),
            encryptedPacket.data(),
            static_cast<unsigned long long>(kSequenceBytes),
            nullptr,
            nonce,
            key.data()) != 0)
    {
        encryptedPacket.clear();
        return false;
    }

    encryptedPacket.resize(
        kSequencedHeaderBytes + static_cast<std::size_t>(ciphertextLength));
    if (encryptedPacket.size() > kMaxVpnUdpPayloadBytes)
    {
        encryptedPacket.clear();
        return false;
    }

    return true;
}

bool decryptSequencedVpnPacket(
    const unsigned char* encryptedPacket,
    std::size_t encryptedPacketLength,
    const SessionKey& key,
    std::uint64_t& sequence,
    std::vector<unsigned char>& plaintext)
{
    sequence = 0;
    plaintext.clear();

    if (encryptedPacket == nullptr ||
        encryptedPacketLength < kSequencedHeaderBytes + kAuthenticationTagBytes ||
        encryptedPacketLength > kMaxVpnUdpPayloadBytes)
    {
        return false;
    }

    if (!initializeCrypto())
        return false;

    const std::uint64_t parsedSequence = readSequence(encryptedPacket);
    if (parsedSequence == 0)
        return false;

    const unsigned char* nonce = encryptedPacket + kSequenceBytes;
    const unsigned char* ciphertext = encryptedPacket + kSequencedHeaderBytes;
    const std::size_t ciphertextLength =
        encryptedPacketLength - kSequencedHeaderBytes;
    plaintext.resize(ciphertextLength - kAuthenticationTagBytes);
    unsigned long long plaintextLength = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintextLength,
            nullptr,
            ciphertext,
            static_cast<unsigned long long>(ciphertextLength),
            encryptedPacket,
            static_cast<unsigned long long>(kSequenceBytes),
            nonce,
            key.data()) != 0)
    {
        plaintext.clear();
        return false;
    }

    sequence = parsedSequence;
    plaintext.resize(static_cast<std::size_t>(plaintextLength));
    return true;
}
