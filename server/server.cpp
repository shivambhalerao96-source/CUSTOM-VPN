#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <cstring>
#include "forward.h"

using namespace std;

// Creates the Server's TUN interface and returns the file descriptor
int setup_server_tun() {
    int fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0) {
        perror("Failed to open /dev/net/tun");
        return -1;
    }

    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
    strcpy(ifr.ifr_name, "tun0");

    if(ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("Failed to set TUN interface");
        close(fd);
        return -1;
    }

    // Configure the Server's internal IP and bring it online
    system("sudo ip addr add 10.0.0.2/24 dev tun0");
    system("sudo ip link set dev tun0 up");

    return fd; 
}

int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    cout << "VPN Server listening on port 8080..." << endl;

    // 1. Create TUN interface
    int tun_fd = setup_server_tun();
    if (tun_fd < 0) {
        close(sockfd);
        return 1;
    }
    cout << "Server tun0 interface created successfully." << endl;

    // 2. Start the multiplexing bridge
    startForwarding(sockfd, tun_fd);

    close(tun_fd);
    close(sockfd);
    return 0;
}