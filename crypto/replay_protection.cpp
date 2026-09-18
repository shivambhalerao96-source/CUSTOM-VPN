#include "replay_protection.h"

#include <limits>

SequenceNumberSender::SequenceNumberSender(std::uint64_t firstSequence)
    : nextSequence_(firstSequence == 0 ? 1 : firstSequence), exhausted_(false)
{
}

bool SequenceNumberSender::nextSequence(std::uint64_t& sequence)
{
    if (exhausted_)
        return false;

    sequence = nextSequence_;
    if (nextSequence_ == std::numeric_limits<std::uint64_t>::max())
        exhausted_ = true;
    else
        ++nextSequence_;

    return true;
}

bool ReplayWindow::accept(std::uint64_t sequence)
{
    if (sequence == 0)
        return false;

    if (!initialized_)
    {
        initialized_ = true;
        highestReceived_ = sequence;
        bitmap_ = 1;
        return true;
    }

    if (sequence > highestReceived_)
    {
        const std::uint64_t advance = sequence - highestReceived_;
        if (advance >= kReplayWindowSize)
            bitmap_ = 1;
        else
            bitmap_ = (bitmap_ << advance) | 1ULL;

        highestReceived_ = sequence;
        return true;
    }

    const std::uint64_t distance = highestReceived_ - sequence;
    if (distance >= kReplayWindowSize)
        return false;

    const std::uint64_t bit = 1ULL << distance;
    if ((bitmap_ & bit) != 0)
        return false;

    bitmap_ |= bit;
    return true;
}

void ReplayWindow::reset()
{
    initialized_ = false;
    highestReceived_ = 0;
    bitmap_ = 0;
}
