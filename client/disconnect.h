#ifndef DISCONNECT_H
#define DISCONNECT_H

#include <arpa/inet.h>

#include "../crypto/handshake.h"
#include "../crypto/session_keys.h"

void sendDisconnectMessage(
    int sockfd,
    sockaddr_in serverAddress,
    const SessionKeys& sessionKeys);

void handleDisconnect(int sockfd, sockaddr_in serverAddress,
    SessionKeys& sessionKeys, X25519SharedSecret& sharedSecret);
#endif