#include "transport.h"
#include "../crypto/packet_crypto.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "disconnect.h"
#include <cstring>
#include <setup.h>

using namespace std;
void sendDisconnectMessage(int sockfd, sockaddr_in serverAddress,
    const SessionKeys& sessionKeys)
{
    const unsigned char* disconnectMessage = "VPN_DISCONNECT";
    // ssize_t bytesSent = send(sockfd, disconnectMessage, strlen(disconnectMessage), 0);
    // if (bytesSent < 0)
    // {
    //     perror("Failed to send disconnect message");
    // }
    // else
    // {
    //     std::cout << "Sent disconnect message to server." << std::endl;
    // }


    vector<unsigned char> encryptedPacket;
        if (!encryptVpnPacket(
                disconnectMessage,
                sizeof(disconnectMessage) - 1,  // Exclude null terminator
                sessionKeys.clientToServer,
                encryptedPacket))
        {
            cerr << "Failed to encrypt TUN packet; dropping packet" << endl;
            return;
        }

        ssize_t bytesSent = sendto(
            sockfd,
            encryptedPacket.data(),
            encryptedPacket.size(),
            0,
            (sockaddr *)&serverAddress,
            sizeof(serverAddress));

        if (bytesSent < 0)
        {perror("Failed to send packet");}
        else if (static_cast<size_t>(bytesSent) != encryptedPacket.size())
        {cerr << "Failed to send complete encrypted packet" << endl;}
        else
        {cout << "[TUN -> SERVER] Sent "<< bytesSent << " bytes" << endl;}
    }

    void receiveDisconnectMessage(int sockfd,SessionKeys& sessionKeys,
        X25519SharedSecret& sharedSecret)
    {

       
        unsigned char buffer[65535];
         while(1){
        int bytesReceived = recv(sockfd, buffer, sizeof(buffer), 0);
        if (bytesReceived < 0)
        {
            perror("Failed to receive packet");
            return;
        }

        vector<unsigned char> plaintext;
        if (!decryptVpnPacket(
                buffer,
                static_cast<size_t>(bytesReceived),
                sessionKeys.serverToClient,
                plaintext))
        {
            cerr << "Server-to-client packet authentication failed; dropping packet" << endl;
            return;
        }

        string message(plaintext.begin(), plaintext.end());
        if (message == "VPN_DISCONNECT")
        {
            cout << "Received disconnect message from server." << endl;
            wipeX25519SharedSecret(sharedSecret);
            wipeSessionKeys(sessionKeys);
            cout << "Wiped shared secret and session keys." << endl;
            close(sockfd);
            close_tun();
            exit(0);
        }
    }
    }

    void handleDisconnect(int sockfd, sockaddr_in serverAddress,
     SessionKeys& sessionKeys, X25519SharedSecret& sharedSecret)
    {
        sendDisconnectMessage(sockfd, serverAddress, sessionKeys);
        receiveDisconnectMessage(sockfd, sessionKeys, sharedSecret);
        cout << "Disconnected from server." << endl;
    }

   
