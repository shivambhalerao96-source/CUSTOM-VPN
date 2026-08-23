#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <arpa/inet.h>
#include <string>
using namespace std;
void tunToServer(int tun_fd, int sockfd, sockaddr_in serverAddress);
string receiveHandshake(int sockfd);
int sendHandshake(int sockfd, sockaddr_in serverAddress);

void serverToTun(int tun_fd, int sockfd);

#endif