#ifndef CRYPTO_PACKET_CRYPTO_H
#define CRYPTO_PACKET_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "session_keys.h"

// The largest IPv4 UDP payload that can be carried without fragmentation.
constexpr std::size_t kMaxVpnTunPacketBytes = 65535;
constexpr std::size_t kMaxVpnUdpPayloadBytes = 65507;
constexpr std::size_t kMaxVpnPlaintextBytes =
    kMaxVpnUdpPayloadBytes -
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES -
    crypto_aead_xchacha20poly1305_ietf_ABYTES;

// Original unsequenced helpers are retained for the Layer 3/4 regression
// tests. The live client/server transport uses the Layer 5 API below.
bool encryptVpnPacket(
    const unsigned char* plaintext,
    std::size_t plaintextLength,
    const SessionKey& key,
    std::vector<unsigned char>& encryptedPacket);

bool decryptVpnPacket(
    const unsigned char* encryptedPacket,
    std::size_t encryptedPacketLength,
    const SessionKey& key,
    std::vector<unsigned char>& plaintext);

// Layer 5 transport format is:
// [uint64 sequence in network byte order][nonce][ciphertext + auth tag].
// The serialized sequence is supplied as AEAD additional authenticated data.
bool encryptSequencedVpnPacket(
    std::uint64_t sequence,
    const unsigned char* plaintext,
    std::size_t plaintextLength,
    const SessionKey& key,
    std::vector<unsigned char>& encryptedPacket);

bool decryptSequencedVpnPacket(
    const unsigned char* encryptedPacket,
    std::size_t encryptedPacketLength,
    const SessionKey& key,
    std::uint64_t& sequence,
    std::vector<unsigned char>& plaintext);

#endif
