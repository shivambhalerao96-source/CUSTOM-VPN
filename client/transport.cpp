#include "transport.h"

#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;
void tunToServer(int tun_fd, int sockfd, sockaddr_in serverAddress)
{
    char buffer[65535];

    while (true)
    {
        int bytesRead = read(tun_fd, buffer, sizeof(buffer));

        if (bytesRead < 0)
        { perror("Error reading packet");
            continue;
        }

        cout << "[TUN -> SERVER] Read "<< bytesRead<< " bytes" << endl;

        int bytesSent = sendto(sockfd,buffer,bytesRead,0,(sockaddr *)&serverAddress, sizeof(serverAddress));

        if (bytesSent < 0)
        {perror("Failed to send packet");}
        else
        {cout << "[TUN -> SERVER] Sent "<< bytesSent << " bytes" << endl;}
    }
}


void serverToTun(int tun_fd, int sockfd)
{
    char buffer[65535];

    while (true)
    {
        int bytesReceived = recvfrom(sockfd,buffer, sizeof(buffer), 0,nullptr,nullptr);
        if (bytesReceived < 0)
        {
            perror("Failed to receive packet");
            continue;
        }

        cout << "[SERVER -> TUN] Received "<< bytesReceived<< " bytes" << endl;

        int bytesWritten = write(tun_fd,buffer,bytesReceived);

        if (bytesWritten < 0)
        {perror("Failed to write packet to TUN");}
        else
        {cout << "[SERVER -> TUN] Wrote "<< bytesWritten<< " bytes to TUN" << endl;}
    }
}