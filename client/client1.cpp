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

    inet_pton(AF_INET, "136.70.156.216", &serverAddress.sin_addr);

    // getting the vpn ip from the server and creating the tun interface with that ip
    cout << "Sending handshake to server..." << endl;
    int st=sendHandshake(sockfd, serverAddress);
    if(st<0){
        cerr<<"Failed to send handshake"<<endl;
        return 1;
    }
    string vpn_ip = receiveHandshake(sockfd);
    if (vpn_ip.empty())
    {
        cerr << "Failed to receive handshake or server is full." << endl;
        return 1;
    }
    int tun_fd = create_tun_interface(vpn_ip);

    if (tun_fd < 0)
    {
        cerr << "Failed to create TUN interface." << endl;
        return 1;
    }

    cout << "TUN interface created successfully." << endl;

    
    thread sender(tunToServer, tun_fd, sockfd, serverAddress);
    thread receiver(serverToTun, tun_fd, sockfd);

    sender.join();
    receiver.join();
    
    close(sockfd);

    return 0;
}