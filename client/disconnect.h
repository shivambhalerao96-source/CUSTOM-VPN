#ifndef DISCONNECT_H
#define DISCONNECT_H


void handleDisconnect(int sockfd, sockaddr_in serverAddress,
    SessionKeys& sessionKeys, X25519SharedSecret& sharedSecret);
#endif