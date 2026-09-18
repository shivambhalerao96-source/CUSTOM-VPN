#ifndef CRYPTO_REPLAY_PROTECTION_H
#define CRYPTO_REPLAY_PROTECTION_H

#include <cstddef>
#include <cstdint>

// A 64-packet window tolerates normal UDP reordering while keeping receiver
// state fixed-size and bounded.
constexpr std::size_t kReplayWindowSize = 64;

class SequenceNumberSender
{
public:
    SequenceNumberSender(std::uint64_t firstSequence = 1);

    // Emit the maximum value once, then fail rather than wrapping to zero.
    bool nextSequence(std::uint64_t& sequence);

private:
    std::uint64_t nextSequence_;
    bool exhausted_;
};

class ReplayWindow
{
public:
    // Sequence zero is reserved as invalid for VPN data packets.
    bool accept(std::uint64_t sequence);
    void reset();

    bool initialized() const { return initialized_; }
    std::uint64_t highestReceived() const { return highestReceived_; }
    std::uint64_t bitmap() const { return bitmap_; }

private:
    bool initialized_ = false;
    std::uint64_t highestReceived_ = 0;
    std::uint64_t bitmap_ = 0;
};

#endif
