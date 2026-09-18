#include "transport.h"
#include "../crypto/packet_crypto.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;
void tunToServer(
    int tun_fd,
    int sockfd,
    sockaddr_in serverAddress,
    const SessionKeys& sessionKeys,
    SequenceNumberSender& sendSequence)
{
    unsigned char buffer[65535];

    while (true)
    {
        int bytesRead = read(tun_fd, buffer, sizeof(buffer));

        if (bytesRead < 0)
        { perror("Error reading packet");
            continue;
        }

        uint64_t sequence = 0;
        if (!sendSequence.nextSequence(sequence))
        {
            cerr << "Client-to-server sequence space exhausted; dropping packet" << endl;
            continue;
        }

        vector<unsigned char> encryptedPacket;
        if (!encryptSequencedVpnPacket(
                sequence,
                buffer,
                static_cast<size_t>(bytesRead),
                sessionKeys.clientToServer,
                encryptedPacket))
        {
            cerr << "Failed to encrypt TUN packet; dropping packet" << endl;
            continue;
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
}

VpnAssignedAddresses receiveHandshake(
    int sockfd,
    const X25519KeyPair& clientKeyPair,
    X25519SharedSecret& sharedSecret,
    SessionKeys& sessionKeys)
{
    char buffer[65535];
    //socklen_t clientLength = sizeof(clientAddress);

    int bytesReceived = recvfrom(sockfd,buffer, sizeof(buffer), 0,nullptr,nullptr);
    if (bytesReceived < 0)
    {
        perror("Failed to receive handshake");
        return {};
    }

    string message(buffer, bytesReceived);

    if (message == "VPN_FULL")
    {
        cout << "[CLIENT -> SERVER] Received handshake of " << bytesReceived << " bytes the server has reached its capacity" << endl;
        return {};
    }

    const string prefix = "VPN_IP ";
    if (message.rfind(prefix, 0) == 0)
    {
        // Wire format is now "VPN_IP <ipv4> <ipv6> <server-pubkey-hex>".
        // Tokenizing on whitespace instead of the old single find(' ')
        // split lets us add the IPv6 field without disturbing anything
        // else about the handshake.
        istringstream fieldStream(message.substr(prefix.size()));
        string vpnIPv4;
        string vpnIPv6;
        string serverPublicKeyText;

        if (!(fieldStream >> vpnIPv4 >> vpnIPv6 >> serverPublicKeyText))
        {
            cerr << "Invalid server key-exchange response" << endl;
            return {};
        }

        X25519PublicKey serverPublicKey{};

        if (!decodeX25519PublicKey(serverPublicKeyText, serverPublicKey))
        {
            cerr << "Invalid server X25519 public key" << endl;
            return {};
        }

        if (!deriveX25519SharedSecret(
                sharedSecret,
                clientKeyPair.privateKey,
                serverPublicKey))
        {
            cerr << "Failed to derive the X25519 shared secret" << endl;
            return {};
        }

        if (!deriveSessionKeys(sessionKeys, sharedSecret))
        {
            cerr << "Failed to derive session keys" << endl;
            wipeX25519SharedSecret(sharedSecret);
            return {};
        }

        cout << "VPN IP received correctly!" << std::endl;
        cout << "Assigned VPN IPv4: " << vpnIPv4 << endl;
        cout << "Assigned VPN IPv6: " << vpnIPv6 << endl;
        cout << "X25519 key agreement completed. Shared-secret fingerprint: "
             << sharedSecretFingerprint(sharedSecret) << endl;

        return VpnAssignedAddresses{vpnIPv4, vpnIPv6};

    } 
    return {};
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


void serverToTun(
    int tun_fd,
    int sockfd,
    const SessionKeys& sessionKeys,
    ReplayWindow& receiveWindow)
{
    unsigned char buffer[kMaxVpnTunPacketBytes];

    while (true)
    {
        int bytesReceived = recvfrom(sockfd,buffer, sizeof(buffer), 0,nullptr,nullptr);
        if (bytesReceived < 0)
        {
            perror("Failed to receive packet");
            continue;
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
            continue;
        }

        if (!receiveWindow.accept(sequence))
        {
            cerr << "Server-to-client replay detected; dropping packet" << endl;
            continue;
        }

        ssize_t bytesWritten = write(tun_fd, plaintext.data(), plaintext.size());

        if (bytesWritten < 0)
        {perror("Failed to write packet to TUN");}
        else if (static_cast<size_t>(bytesWritten) != plaintext.size())
        {cerr << "Failed to write complete packet to TUN" << endl;}
        else
        {cout << "[SERVER -> TUN] Wrote "<< bytesWritten<< " bytes to TUN" << endl;}
    }
}
