#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <arpa/inet.h>
#include <string>
#include "../crypto/handshake.h"
using namespace std;
void tunToServer(int tun_fd, int sockfd, sockaddr_in serverAddress);
string receiveHandshake(
    int sockfd,
    const X25519KeyPair& clientKeyPair,
    X25519SharedSecret& sharedSecret);
int sendHandshake(
    int sockfd,
    sockaddr_in serverAddress,
    X25519KeyPair& clientKeyPair);

void serverToTun(int tun_fd, int sockfd);

#endif
