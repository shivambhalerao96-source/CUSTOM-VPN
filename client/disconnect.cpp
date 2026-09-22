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
#include "../tun/setup.h"

using namespace std;
void sendDisconnectMessage(
    int sockfd,
    sockaddr_in serverAddress,
    const SessionKeys& sessionKeys,
    SequenceNumberSender& sendSequence,
    mutex& sequenceMutex)
{
    const unsigned char disconnectMessage[] = "VPN_DISCONNECT";
    uint64_t sequence = 0;
    {
        lock_guard<mutex> lock(sequenceMutex);
        if (!sendSequence.nextSequence(sequence))
        {
            cerr << "Client-to-server sequence space exhausted; cannot disconnect cleanly" << endl;
            return;
        }
    }

    vector<unsigned char> encryptedPacket;
        if (!encryptSequencedVpnPacket(
                sequence,
                disconnectMessage,
                sizeof(disconnectMessage) - 1,
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

    void receiveDisconnectMessage(
        int sockfd,
        SessionKeys& sessionKeys,
        X25519SharedSecret& sharedSecret,
        ReplayWindow& receiveWindow)
    {

       
        unsigned char buffer[65535];
         while(1){
        int bytesReceived = recvfrom(
            sockfd,
            buffer,
            sizeof(buffer),
            0,
            nullptr,
            nullptr);
        if (bytesReceived < 0)
        {
            perror("Failed to receive packet");
            return;
        }

        vector<unsigned char> plaintext;
        uint64_t sequence = 0;
        if (!decryptSequencedVpnPacket(
                buffer,
                static_cast<size_t>(bytesReceived),
                sessionKeys.serverToClient,
                sequence,
                plaintext))
        {
            cerr << "Server-to-client packet authentication failed; dropping packet" << endl;
            return;
        }

        if (!receiveWindow.accept(sequence))
        {
            cerr << "Server-to-client replay detected; dropping packet" << endl;
            continue;
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

    void handleDisconnect(
        int sockfd,
        sockaddr_in serverAddress,
        SessionKeys& sessionKeys,
        X25519SharedSecret& sharedSecret,
        SequenceNumberSender& sendSequence,
        mutex& sequenceMutex,
        ReplayWindow& receiveWindow)
    {
        sendDisconnectMessage(
            sockfd,
            serverAddress,
            sessionKeys,
            sendSequence,
            sequenceMutex);
        receiveDisconnectMessage(
            sockfd,
            sessionKeys,
            sharedSecret,
            receiveWindow);
        cout << "Disconnected from server." << endl;
    }

   
