#include <iostream>
#include <atomic>
#include <thread>
#include <functional>
#include <mutex>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../tun/setup.h"
#include "transport.h"
#include "disconnect.h"
#include "../crypto/packet_crypto.h"
#include "../tor/tor_bridge.h"
#include "../tor/tor_config.h"
#include "../tor/tor_manager.h"

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

    sockaddr_in serverAddress{};// creates a structure which stores details about server
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);

    const char* serverIp = argc > 1 ? argv[1] : "";
    //serverIp= "35.226.148.101"; // hardcoded for testing
    if( serverIp[0] == '\0') {
        cerr << "Please provide the VPN server IPv4 address as a command-line argument." << endl;
        close(sockfd);
        return 1;
    }
    if (inet_pton(AF_INET, serverIp, &serverAddress.sin_addr) != 1)
    {
        cerr << "Invalid VPN server IPv4 address: " << serverIp << endl;
        close(sockfd);
        return 1;
    }

    // getting the vpn ip from the server and creating the tun interface with that ip
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
    int tun_fd = create_tun_interface(
        assignedAddresses.ipv4,
        assignedAddresses.ipv6,
        serverIp);

    if (tun_fd < 0)
    {
        cerr << "Failed to create TUN interface." << endl;
        wipeX25519SharedSecret(sharedSecret);
        wipeSessionKeys(sessionKeys);
        return 1;
    }

    if (assignedAddresses.activeClients >= 0 && assignedAddresses.clientCapacity > 0)
    {
        cout << "VPN_LOAD " << assignedAddresses.activeClients << ' '
             << assignedAddresses.clientCapacity << endl;
    }
    cout << "VPN_CONNECTED" << endl;

    std::atomic<bool> stopRequested{false};
    SequenceNumberSender clientToServerSequence;
    std::mutex clientToServerSequenceMutex;
    ReplayWindow serverToClientReplay;

    thread sender(
        tunToServer,
        tun_fd,
        sockfd,
        serverAddress,
        cref(sessionKeys),
        ref(stopRequested),
        ref(clientToServerSequence),
        ref(clientToServerSequenceMutex));
    thread receiver(
        serverToTun,
        tun_fd,
        sockfd,
        cref(sessionKeys),
        ref(stopRequested),
        ref(serverToClientReplay));

    auto sendEncryptedCommand = [&](const string& cmdText) -> bool {
        uint64_t sequence = 0;
        {
            lock_guard<mutex> lock(clientToServerSequenceMutex);
            if (!clientToServerSequence.nextSequence(sequence))
            {
                cerr << "Client-to-server sequence space exhausted" << endl;
                return false;
            }
        }

        vector<unsigned char> encryptedPacket;
        if (!encryptSequencedVpnPacket(
                sequence,
                reinterpret_cast<const unsigned char*>(cmdText.data()),
                cmdText.size(),
                sessionKeys.clientToServer,
                encryptedPacket))
        {
            cerr << "Failed to encrypt control packet" << endl;
            return false;
        }

        ssize_t bytesSent = sendto(
            sockfd,
            encryptedPacket.data(),
            encryptedPacket.size(),
            0,
            (sockaddr*)&serverAddress,
            sizeof(serverAddress));

        return (bytesSent == static_cast<ssize_t>(encryptedPacket.size()));
    };

    thread control([&]() {
        string command;
        while (!stopRequested.load())
        {
            if (!getline(cin, command))
                break;

            if (command == "disconnect")
            {
                customvpn::TorBridge::getInstance().stop();
                sendDisconnectMessage(
                    sockfd,
                    serverAddress,
                    sessionKeys,
                    clientToServerSequence,
                    clientToServerSequenceMutex);
                stopRequested.store(true);
                shutdown(sockfd, SHUT_RDWR);
                close(sockfd);
                close(tun_fd);
                break;
            }
            else if (command == "tor on")
            {
                auto cfg = customvpn::TorConfig::fromEnvironment();
                sendEncryptedCommand("VPN_TOR_ON");
                customvpn::TorBridge::getInstance().start(
                    cfg.clientBridgeHost,
                    cfg.clientBridgePort,
                    cfg.serverVpnIp,
                    cfg.socksPort);
            }
            else if (command == "tor off")
            {
                sendEncryptedCommand("VPN_TOR_OFF");
                customvpn::TorBridge::getInstance().stop();
            }
            else if (command == "tor status")
            {
                sendEncryptedCommand("VPN_TOR_STATUS");
            }
        }
    });

    sender.join();
    receiver.join();
    control.join();

    wipeX25519SharedSecret(sharedSecret);
    wipeSessionKeys(sessionKeys);

    if (sockfd >= 0)
        close(sockfd);

    return 0;
}
