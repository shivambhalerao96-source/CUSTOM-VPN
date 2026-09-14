#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <arpa/inet.h>
#include <string>
#include "../crypto/handshake.h"
#include "../crypto/session_keys.h"
using namespace std;
void tunToServer(
    int tun_fd,
    int sockfd,
    sockaddr_in serverAddress,
    const SessionKeys& sessionKeys);
string receiveHandshake(
    int sockfd,
    const X25519KeyPair& clientKeyPair,
    X25519SharedSecret& sharedSecret,
    SessionKeys& sessionKeys);
int sendHandshake(
    int sockfd,
    sockaddr_in serverAddress,
    X25519KeyPair& clientKeyPair);

void serverToTun(
    int tun_fd,
    int sockfd,
    const SessionKeys& sessionKeys);

#endif
