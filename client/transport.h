#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <arpa/inet.h>

void tunToServer(int tun_fd, int sockfd, sockaddr_in serverAddress);

void serverToTun(int tun_fd, int sockfd);

#endif