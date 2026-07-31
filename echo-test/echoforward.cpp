#include "echoforward.h"

#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>

using namespace std;

void startForwarding(int sockfd)
{
    char buffer[65535];

    sockaddr_in clientAddress{};
    socklen_t clientLength = sizeof(clientAddress);

    while (true)
    {
        int bytesReceived = recvfrom(sockfd,buffer,sizeof(buffer),0,(sockaddr *)&clientAddress,&clientLength);

        if (bytesReceived < 0)
        {
            perror("recvfrom failed");
            continue;
        }

        cout << "\n========== Packet Received ==========" << endl;

        cout << "Client : "<< inet_ntoa(clientAddress.sin_addr)<< ":" << ntohs(clientAddress.sin_port)<< endl;

        struct iphdr *ip = (struct iphdr *)buffer;

        cout << "Source IP      : "<< inet_ntoa(*(in_addr *)&ip->saddr)<< endl;

        cout << "Destination IP : "<< inet_ntoa(*(in_addr *)&ip->daddr)<< endl;

        cout << "Protocol       : "<< (int)ip->protocol<< endl;

        cout << "TTL            : "<< (int)ip->ttl<< endl;

        int bytesSent = sendto(sockfd,buffer,bytesReceived,0,(sockaddr *)&clientAddress, clientLength);

        if (bytesSent < 0)
        { perror("sendto failed");}
        else
        {
            cout << "Echoed "<< bytesSent<< " bytes back to client." << endl;
        }
    }
}