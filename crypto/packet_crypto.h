#ifndef CRYPTO_PACKET_CRYPTO_H
#define CRYPTO_PACKET_CRYPTO_H

#include <cstddef>
#include <vector>

#include "session_keys.h"

// The largest IPv4 UDP payload that can be carried without fragmentation.
constexpr std::size_t kMaxVpnTunPacketBytes = 65535;
constexpr std::size_t kMaxVpnUdpPayloadBytes = 65507;
constexpr std::size_t kMaxVpnPlaintextBytes =
    kMaxVpnUdpPayloadBytes -
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES -
    crypto_aead_xchacha20poly1305_ietf_ABYTES;

// The transport format is [nonce][ciphertext + authentication tag].
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

#endif
