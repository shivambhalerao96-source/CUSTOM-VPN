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

string receiveHandshake(
    int sockfd,
    const X25519KeyPair& clientKeyPair,
    X25519SharedSecret& sharedSecret)
{
    char buffer[65535];
    //socklen_t clientLength = sizeof(clientAddress);

    int bytesReceived = recvfrom(sockfd,buffer, sizeof(buffer), 0,nullptr,nullptr);
    if (bytesReceived < 0)
    {
        perror("Failed to receive handshake");
        return "";
    }

    string message(buffer, bytesReceived);

    if (message == "VPN_FULL")
    {
        cout << "[CLIENT -> SERVER] Received handshake of " << bytesReceived << " bytes the server has reached its capacity" << endl;
        return "";
    }

    const string prefix = "VPN_IP ";
    if (message.rfind(prefix, 0) == 0)
    {
        size_t separator = message.find(' ', prefix.size());
        if (separator == string::npos)
        {
            cerr << "Invalid server key-exchange response" << endl;
            return "";
        }

        string serverPublicKeyText = message.substr(separator + 1);
        X25519PublicKey serverPublicKey{};

        if (!decodeX25519PublicKey(serverPublicKeyText, serverPublicKey))
        {
            cerr << "Invalid server X25519 public key" << endl;
            return "";
        }

        if (!deriveX25519SharedSecret(
                sharedSecret,
                clientKeyPair.privateKey,
                serverPublicKey))
        {
            cerr << "Failed to derive the X25519 shared secret" << endl;
            return "";
        }

        cout << "VPN IP received correctly!" << std::endl;
        string vpnIP = message.substr(prefix.size(), separator - prefix.size());
        cout << "Assigned VPN IP: " << vpnIP << endl;
        cout << "X25519 key agreement completed. Shared-secret fingerprint: "
             << sharedSecretFingerprint(sharedSecret) << endl;
        return vpnIP;

    } 
    return "";
}

int sendHandshake(
    int sockfd,
    sockaddr_in serverAddress,
    X25519KeyPair& clientKeyPair)
{
    if (!generateX25519KeyPair(clientKeyPair))
    {
        cerr << "Failed to generate the client X25519 key pair" << endl;
        return -1;
    }

    string response =
        "VPN_HELLO " + encodeX25519PublicKey(clientKeyPair.publicKey);

    int bytesSent = sendto(sockfd, response.c_str(), response.size(), 0, (sockaddr*)&serverAddress, sizeof(serverAddress));

    if (bytesSent < 0)
    {
        perror("Failed to send handshake acknowledgment");
        wipeX25519PrivateKey(clientKeyPair);
        return -1;
    }
    else
    {
        cout << "[SERVER -> CLIENT] Sent handshake acknowledgment of " << bytesSent << " bytes" << endl;
    }
    return 0;
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
