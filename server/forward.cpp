#include "forward.h"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <algorithm>

using namespace std;

void startForwarding(int sockfd, int tun_fd)
{
    char buffer[65535];
    sockaddr_in clientAddress{};
    socklen_t clientLength = sizeof(clientAddress);

    cout << "Unencrypted tunnel bridge initialized." << endl;
    cout << "Waiting for raw packets..." << endl;

    while (true)
    {
        // readfds is noting but a array of bits which tells if the file descriptor at that index is being monitered or not if it is being monitered go shed and read and write 
        fd_set readfds;
        FD_ZERO(&readfds);
        
        // Watch both the Socket (Client traffic) and TUN (Internet traffic)
        FD_SET(sockfd, &readfds);
        FD_SET(tun_fd, &readfds);

        int max_fd = std::max(sockfd, tun_fd) + 1;

        if (select(max_fd, &readfds, NULL, NULL, NULL) < 0)
        {
            perror("select failed");
            break;
        }

        // ==========================================
        // ROUTE 1: CLIENT -> SERVER -> INTERNET
        // ==========================================
        if (FD_ISSET(sockfd, &readfds))
        {
            int bytesReceived = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr *)&clientAddress, &clientLength);
            if (bytesReceived > 0)
            {
                // The buffer contains a raw IP packet. 
                // Write it directly into the server's OS routing engine.
                write(tun_fd, buffer, bytesReceived); 
            }
        }

        // ==========================================
        // ROUTE 2: INTERNET -> SERVER -> CLIENT
        // ==========================================
        if (FD_ISSET(tun_fd, &readfds))
        {
            int bytesRead = read(tun_fd, buffer, sizeof(buffer));
            if (bytesRead > 0)
            {
                // The buffer contains a raw reply IP packet from the internet.
                // Send it directly back to the client over UDP.
                sendto(sockfd, buffer, bytesRead, 0, (sockaddr *)&clientAddress, clientLength);
            }
        }
    }
}