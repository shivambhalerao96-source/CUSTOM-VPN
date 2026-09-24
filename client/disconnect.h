#ifndef DISCONNECT_H
#define DISCONNECT_H

#include <arpa/inet.h>
#include <mutex>

#include "../crypto/handshake.h"
#include "../crypto/replay_protection.h"
#include "../crypto/session_keys.h"

void sendDisconnectMessage(
    int sockfd,
    sockaddr_in serverAddress,
    const SessionKeys& sessionKeys,
    SequenceNumberSender& sendSequence,
    std::mutex& sequenceMutex);

void receiveDisconnectMessage(
    int sockfd,
    SessionKeys& sessionKeys,
    X25519SharedSecret& sharedSecret,
    ReplayWindow& receiveWindow);

void handleDisconnect(
    int sockfd,
    sockaddr_in serverAddress,
    SessionKeys& sessionKeys,
    X25519SharedSecret& sharedSecret,
    SequenceNumberSender& sendSequence,
    std::mutex& sequenceMutex,
    ReplayWindow& receiveWindow);
#endif
