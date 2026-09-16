#include <iostream>
#include <thread>
#include <functional>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../tun/setup.h"
#include "transport.h"

using namespace std;

int main(int argc, char* argv[])
{
    if (!initializeCrypto())
    {
        cerr << "Libsodium initialization failed." << endl;
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    cout << "UDP socket created successfully." << endl;

    sockaddr_in serverAddress{};// creates a structure which stores details about server
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);

    const char* serverIp = argc > 1 ? argv[1] : "34.145.231.1";
    if (inet_pton(AF_INET, serverIp, &serverAddress.sin_addr) != 1)
    {
        cerr << "Invalid VPN server IPv4 address: " << serverIp << endl;
        close(sockfd);
        return 1;
    }

    // getting the vpn ip from the server and creating the tun interface with that ip
    cout << "Sending handshake to server..." << endl;
    X25519KeyPair clientKeyPair;
    X25519SharedSecret sharedSecret{};
    SessionKeys sessionKeys{};

    int st = sendHandshake(sockfd, serverAddress, clientKeyPair);
    if(st<0){
        cerr<<"Failed to send handshake"<<endl;
        wipeX25519PrivateKey(clientKeyPair);
        return 1;
    }
    VpnAssignedAddresses assignedAddresses = receiveHandshake(
        sockfd,
        clientKeyPair,
        sharedSecret,
        sessionKeys);
    wipeX25519PrivateKey(clientKeyPair);
    if (assignedAddresses.ipv4.empty())
    {
        cerr << "Failed to receive handshake or server is full." << endl;
        wipeX25519SharedSecret(sharedSecret);
        wipeSessionKeys(sessionKeys);
        return 1;
    }
    int tun_fd = create_tun_interface(assignedAddresses.ipv4, assignedAddresses.ipv6);

    if (tun_fd < 0)
    {
        cerr << "Failed to create TUN interface." << endl;
        wipeX25519SharedSecret(sharedSecret);
        wipeSessionKeys(sessionKeys);
        return 1;
    }

    cout << "TUN interface created successfully." << endl;

    
    thread sender(
        tunToServer,
        tun_fd,
        sockfd,
        serverAddress,
        cref(sessionKeys));
    thread receiver(serverToTun, tun_fd, sockfd, cref(sessionKeys));

    sender.join();
    receiver.join();

    wipeX25519SharedSecret(sharedSecret);
    wipeSessionKeys(sessionKeys);
    
    close(sockfd);

    return 0;
}