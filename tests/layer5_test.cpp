#include "../crypto/packet_crypto.h"
#include "../crypto/replay_protection.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <vector>

namespace
{
bool require(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << std::endl;
    return condition;
}

std::vector<unsigned char> makePacket(
    std::uint64_t sequence,
    const SessionKey& key)
{
    const std::vector<unsigned char> message = {
        0x45, 0x00, 0x00, 0x1c, 0x01, 0x02, 0x03, 0x04};
    std::vector<unsigned char> packet;
    if (!encryptSequencedVpnPacket(
            sequence,
            message.data(),
            message.size(),
            key,
            packet))
    {
        return {};
    }
    return packet;
}

bool decryptAndAccept(
    const std::vector<unsigned char>& packet,
    const SessionKey& key,
    ReplayWindow& window)
{
    std::uint64_t sequence = 0;
    std::vector<unsigned char> plaintext;
    if (!decryptSequencedVpnPacket(
            packet.data(), packet.size(), key, sequence, plaintext))
    {
        return false;
    }
    return window.accept(sequence);
}
}

int main()
{
    if (!require(initializeCrypto(), "Libsodium initialization"))
        return EXIT_FAILURE;

    SessionKey key{};
    SessionKey wrongKey{};
    for (std::size_t i = 0; i < key.size(); ++i)
    {
        key[i] = static_cast<unsigned char>(0x20 + i);
        wrongKey[i] = static_cast<unsigned char>(0x80 + i);
    }

    bool ok = true;

    std::vector<unsigned char> packet1 = makePacket(1, key);
    ok = require(!packet1.empty(), "first sequenced packet encryption") && ok;
    ok = require(packet1.size() >=
                     sizeof(std::uint64_t) +
                         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                         crypto_aead_xchacha20poly1305_ietf_ABYTES,
                 "sequenced packet has fixed header and tag") && ok;

    std::uint64_t decodedSequence = 0;
    std::vector<unsigned char> plaintext;
    ok = require(
             decryptSequencedVpnPacket(
                 packet1.data(), packet1.size(), key, decodedSequence, plaintext),
             "first valid packet authentication") && ok;
    ok = require(decodedSequence == 1, "sequence serialization is network order") && ok;

    ReplayWindow sequentialWindow;
    ok = require(sequentialWindow.accept(decodedSequence), "first valid packet accepted") && ok;
    for (std::uint64_t sequence = 2; sequence <= 4; ++sequence)
    {
        std::vector<unsigned char> packet = makePacket(sequence, key);
        ok = require(
                 decryptAndAccept(packet, key, sequentialWindow),
                 "sequential packet accepted") && ok;
    }

    std::vector<unsigned char> packet2 = makePacket(2, key);
    ok = require(!decryptAndAccept(packet2, key, sequentialWindow),
                 "exact replay rejected") && ok;
    ok = require(!decryptAndAccept(packet1, key, sequentialWindow),
                 "already accepted older packet rejected") && ok;

    ReplayWindow reorderedWindow;
    std::vector<unsigned char> packet10 = makePacket(10, key);
    std::vector<unsigned char> packet12 = makePacket(12, key);
    std::vector<unsigned char> packet11 = makePacket(11, key);
    ok = require(decryptAndAccept(packet10, key, reorderedWindow),
                 "first out-of-order-window packet accepted") && ok;
    ok = require(decryptAndAccept(packet12, key, reorderedWindow),
                 "newer packet accepted") && ok;
    ok = require(decryptAndAccept(packet11, key, reorderedWindow),
                 "unseen packet inside replay window accepted") && ok;

    ReplayWindow oldWindow;
    std::vector<unsigned char> packet100 = makePacket(100, key);
    std::vector<unsigned char> packet36 = makePacket(36, key);
    ok = require(decryptAndAccept(packet100, key, oldWindow),
                 "window anchor accepted") && ok;
    ok = require(!decryptAndAccept(packet36, key, oldWindow),
                 "packet outside replay window rejected") && ok;

    std::vector<unsigned char> forgedSequence = packet1;
    // Keep the parsed sequence nonzero so this exercises AEAD AAD
    // authentication rather than only the reserved-zero check.
    forgedSequence[6] ^= 0x01;
    ReplayWindow forgedWindow;
    decodedSequence = 0;
    plaintext = {0xAA};
    ok = require(
             !decryptSequencedVpnPacket(
                 forgedSequence.data(), forgedSequence.size(), key,
                 decodedSequence, plaintext),
             "modified sequence authentication failure") && ok;
    ok = require(plaintext.empty() && decodedSequence == 0,
                 "forged sequence releases no plaintext or sequence") && ok;
    ok = require(decryptAndAccept(packet1, key, forgedWindow),
                 "unauthenticated sequence does not advance replay state") && ok;

    std::vector<unsigned char> forgedCiphertext = packet1;
    forgedCiphertext[sizeof(std::uint64_t) +
                     crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] ^= 0x01;
    ok = require(!decryptAndAccept(forgedCiphertext, key, forgedWindow),
                 "modified ciphertext authentication failure") && ok;

    std::vector<unsigned char> forgedTag = packet1;
    forgedTag.back() ^= 0x01;
    ok = require(!decryptAndAccept(forgedTag, key, forgedWindow),
                 "modified authentication tag failure") && ok;
    ok = require(!decryptAndAccept(packet1, wrongKey, forgedWindow),
                 "wrong session key authentication failure") && ok;

    std::vector<unsigned char> truncated(packet1.begin(), packet1.end() - 1);
    ok = require(!decryptAndAccept(truncated, key, forgedWindow),
                 "truncated packet rejection") && ok;
    ok = require(!decryptAndAccept({}, key, forgedWindow),
                 "empty packet rejection") && ok;

    SequenceNumberSender sender;
    std::uint64_t sequence = 0;
    ok = require(sender.nextSequence(sequence) && sequence == 1,
                 "sender starts at sequence one") && ok;

    SequenceNumberSender lastSender(std::numeric_limits<std::uint64_t>::max());
    ok = require(
             lastSender.nextSequence(sequence) &&
                 sequence == std::numeric_limits<std::uint64_t>::max(),
             "maximum sequence emitted once") && ok;
    ok = require(!lastSender.nextSequence(sequence),
                 "sequence overflow safely stops transmission") && ok;

    ReplayWindow c2sWindow;
    ReplayWindow s2cWindow;
    ok = require(c2sWindow.accept(1) && s2cWindow.accept(1),
                 "directional replay windows are independent") && ok;
    ReplayWindow newSessionWindow;
    ok = require(newSessionWindow.accept(1),
                 "new session starts with fresh replay state") && ok;

    if (ok)
    {
        std::cout << "Layer 5 local tests passed." << std::endl;
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
