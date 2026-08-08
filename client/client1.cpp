#include <iostream>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../tun/setup.h"
#include "transport.h"

using namespace std;

int main()
{
    int tun_fd = create_tun_interface();

    if (tun_fd < 0)
    {
        cerr << "Failed to create TUN interface." << endl;
        return 1;
    }

    cout << "TUN interface created successfully." << endl;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    cout << "UDP socket created successfully." << endl;

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);

    inet_pton(AF_INET, "172.18.37.100", &serverAddress.sin_addr);

    thread sender(tunToServer, tun_fd, sockfd, serverAddress);
    thread receiver(serverToTun, tun_fd, sockfd);

    sender.join();
    receiver.join();

    close(sockfd);

    return 0;
}