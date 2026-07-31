#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "forward.h"

using namespace std;

int main()
{
    
    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    cout << "UDP socket created successfully." << endl;

    // Server address
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // Bind socket
    if (bind(sockfd,
             (sockaddr *)&serverAddress,
             sizeof(serverAddress)) < 0)
    {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    cout << "VPN Server is listening on port 8080..." << endl;

    startForwarding(sockfd);

    close(sockfd);

    return 0;
}