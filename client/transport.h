#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <arpa/inet.h>
#include <string>
#include "../crypto/handshake.h"
#include "../crypto/session_keys.h"
#include "../crypto/replay_protection.h"
using namespace std;

// Holds the VPN addresses the server assigns to this client during the
// handshake. IPv4 is unchanged from before; IPv6 is new. If the handshake
// fails, both fields are left empty (see receiveHandshake()).
struct VpnAssignedAddresses
{
    string ipv4;
    string ipv6;
};

void tunToServer(
    int tun_fd,
    int sockfd,
    sockaddr_in serverAddress,
    const SessionKeys& sessionKeys,
    SequenceNumberSender& sendSequence);
VpnAssignedAddresses receiveHandshake(
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
    const SessionKeys& sessionKeys,
    ReplayWindow& receiveWindow);

#endif
