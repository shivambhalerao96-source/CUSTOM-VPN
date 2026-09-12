#include "forward.h"
#include "../crypto/handshake.h"
#include "../crypto/packet_crypto.h"
#include "../crypto/session_keys.h"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <algorithm>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iomanip>
#include <cctype>
#include <unordered_map>
#include <string>
#include <sstream>
#include <vector>

using namespace std;
struct ClientInfo {
    sockaddr_in address;
    string vpnIP;
    X25519SharedSecret sharedSecret;
    SessionKeys sessionKeys;

    ~ClientInfo()
    {
        wipeX25519SharedSecret(sharedSecret);
        wipeSessionKeys(sessionKeys);
    }
};

unordered_map<string, ClientInfo> vpn_ip;// maps the vpn_ip to client info 
string allocateVPNIP()
{// here we are allocating the vpn ip address to the client and we are checking if the ip address is already allocated or not if it is allocated we will return the next available ip address
    for (int i = 1; i <= 254; i++)
    {
        string ip = "10.0.0." + to_string(i);

        if (ip == "10.0.0.2")
            continue; // Server's TUN IP

        if (vpn_ip.find(ip) == vpn_ip.end())
            return ip;
    }

    return "";
}

// void printPayload(const unsigned char* data, int len)
// {
//     if (len <= 0)
//     {
//         cout << "Application Data : None" << endl;
//         return;
//     }

//     cout << "Application Data (HEX): ";
//     for (int i = 0; i < len; i++)
//         cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
//     cout << dec << endl;

//     cout << "Application Data (ASCII): ";
//     for (int i = 0; i < len; i++)
//         cout << (isprint(data[i]) ? (char)data[i] : '.');
//     cout << endl;
// }

// void printPacketInfo(const char* buffer, int bytes)
// {
//     if (bytes < (int)sizeof(iphdr))
//     {
//         cout << "Invalid/short IP packet." << endl;
//         return;
//     }

//     iphdr* ip = (iphdr*)buffer;

//     if (ip->version == 6)
//     {
//         cout << "IPv6 packet received - inspection not implemented yet." << endl;
//         return;
//     }

//     if (ip->version != 4)
//     {
//         cout << "Unknown IP version - ignoring packet." << endl;
//         return;
//     }

//     int ipHeaderLen = ip->ihl * 4;

//     if (ipHeaderLen < 20 || ipHeaderLen > bytes)
//     {
//         cout << "Invalid IP header." << endl;
//         return;
//     }

//     char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
//     inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
//     inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

//     cout << "\n--- IP PACKET ---" << endl;
//     cout << "Source IP      : " << src << endl;
//     cout << "Destination IP : " << dst << endl;
//     cout << "Protocol       : " << (int)ip->protocol;

//     if (ip->protocol == IPPROTO_TCP)
//         cout << " (TCP)";
//     else if (ip->protocol == IPPROTO_UDP)
//         cout << " (UDP)";
//     else if (ip->protocol == IPPROTO_ICMP)
//         cout << " (ICMP)";
//     else
//         cout << " (Other)";

//     cout << endl;
//     cout << "TTL            : " << (int)ip->ttl << endl;
//     cout << "Total Length   : " << ntohs(ip->tot_len) << " bytes" << endl;

//     int ipTotalLen = ntohs(ip->tot_len);
//     if (ipTotalLen > bytes)
//         ipTotalLen = bytes;

//     unsigned char* transport =
//         (unsigned char*)buffer + ipHeaderLen;

//     int transportLen = ipTotalLen - ipHeaderLen;

//     if (ip->protocol == IPPROTO_TCP)
//     {
//         if (transportLen < (int)sizeof(tcphdr))
//         {
//             cout << "Invalid TCP packet." << endl;
//             return;
//         }

//         tcphdr* tcp = (tcphdr*)transport;
//         int tcpHeaderLen = tcp->doff * 4;

//         if (tcpHeaderLen < 20 || tcpHeaderLen > transportLen)
//         {
//             cout << "Invalid TCP header." << endl;
//             return;
//         }

//         cout << "Source Port    : " << ntohs(tcp->source) << endl;
//         cout << "Destination Port: " << ntohs(tcp->dest) << endl;

//         cout << "TCP Flags      : ";
//         if (tcp->syn) cout << "SYN ";
//         if (tcp->ack) cout << "ACK ";
//         if (tcp->fin) cout << "FIN ";
//         if (tcp->rst) cout << "RST ";
//         if (tcp->psh) cout << "PSH ";
//         if (tcp->urg) cout << "URG ";
//         cout << endl;

//         unsigned char* payload = transport + tcpHeaderLen;
//         int payloadLen = transportLen - tcpHeaderLen;

//         cout << "Data Length    : " << payloadLen << " bytes" << endl;
//         printPayload(payload, payloadLen);
//     }
//     else if (ip->protocol == IPPROTO_UDP)
//     {
//         if (transportLen < (int)sizeof(udphdr))
//         {
//             cout << "Invalid UDP packet." << endl;
//             return;
//         }

//         udphdr* udp = (udphdr*)transport;

//         cout << "Source Port    : " << ntohs(udp->source) << endl;
//         cout << "Destination Port: " << ntohs(udp->dest) << endl;
//         cout << "UDP Length     : " << ntohs(udp->len) << " bytes" << endl;

//         unsigned char* payload =
//             transport + sizeof(udphdr);

//         int payloadLen =
//             transportLen - sizeof(udphdr);

//         cout << "Data Length    : " << payloadLen << " bytes" << endl;
//         printPayload(payload, payloadLen);
//     }
//     else
//     {
//         cout << "IP Payload Length: "
//              << transportLen << " bytes" << endl;
//     }

//     cout << "-----------------" << endl;
// }

bool handleHandshake(int sockfd, const char* buffer, int bytesReceived, sockaddr_in& clientAddress, socklen_t clientLength)
{
    string message(buffer, bytesReceived);
    const string prefix = "VPN_HELLO ";

    if (message.rfind("VPN_HELLO", 0) != 0)
        return false;

    if (message.rfind(prefix, 0) != 0)
    {
        cerr << "Client X25519 public key is missing" << endl;
        string response = "VPN_HANDSHAKE_FAILED";
        sendto(sockfd, response.c_str(), response.size(), 0,
               (sockaddr*)&clientAddress, clientLength);
        return true;
    }

    X25519PublicKey clientPublicKey{};
    if (!decodeX25519PublicKey(message.substr(prefix.size()), clientPublicKey))
    {
        cerr << "Invalid client X25519 public key" << endl;
        string response = "VPN_HANDSHAKE_FAILED";
        sendto(sockfd, response.c_str(), response.size(), 0,
               (sockaddr*)&clientAddress, clientLength);
        return true;
    }

    // Check whether this client already exists
    for (auto& [vpnIP, client] : vpn_ip)
    {
        if (client.address.sin_addr.s_addr ==
                clientAddress.sin_addr.s_addr &&
            client.address.sin_port ==
                clientAddress.sin_port)
        {
            cout << "Client already registered as "
                 << vpnIP << endl;

            //string response = "VPN_IP " + vpnIP;

            return true;
        }
    }

    // Allocate a new VPN IP
    string vpnIP = allocateVPNIP();

    if (vpnIP.empty())
    {
        string response = "VPN_FULL";

        sendto(
            sockfd,
            response.c_str(),
            response.size(),
            0,
            (sockaddr*)&clientAddress,
            clientLength
        );

        return true;
    }

    X25519KeyPair serverKeyPair;
    if (!generateX25519KeyPair(serverKeyPair))
    {
        cerr << "Failed to generate the server X25519 key pair" << endl;
        string response = "VPN_HANDSHAKE_FAILED";
        sendto(sockfd, response.c_str(), response.size(), 0,
               (sockaddr*)&clientAddress, clientLength);
        return true;
    }

    // Store client information
    ClientInfo client{};

    client.address = clientAddress;
    client.vpnIP = vpnIP;

    if (!deriveX25519SharedSecret(
            client.sharedSecret,
            serverKeyPair.privateKey,
            clientPublicKey))
    {
        cerr << "Failed to derive the X25519 shared secret" << endl;
        wipeX25519PrivateKey(serverKeyPair);
        string response = "VPN_HANDSHAKE_FAILED";
        sendto(sockfd, response.c_str(), response.size(), 0,
               (sockaddr*)&clientAddress, clientLength);
        return true;
    }

    if (!deriveSessionKeys(client.sessionKeys, client.sharedSecret))
    {
        cerr << "Failed to derive session keys" << endl;
        wipeX25519PrivateKey(serverKeyPair);
        string response = "VPN_HANDSHAKE_FAILED";
        sendto(sockfd, response.c_str(), response.size(), 0,
               (sockaddr*)&clientAddress, clientLength);
        return true;
    }

    vpn_ip.emplace(vpnIP, client);

    cout << "New VPN client registered" << endl;
    cout << "VPN IP : " << vpnIP << endl;

    char ip[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        &clientAddress.sin_addr,
        ip,
        sizeof(ip)
    );

    cout << "Real IP: " << ip
         << ":" << ntohs(clientAddress.sin_port)
         << endl;

    // Send assigned VPN IP
    string response =
        "VPN_IP " + vpnIP + " " +
        encodeX25519PublicKey(serverKeyPair.publicKey);

    sendto(
        sockfd,
        response.c_str(),
        response.size(),
        0,
        (sockaddr*)&clientAddress,
        clientLength
    );

    cout << "X25519 key agreement completed. Shared-secret fingerprint: "
         << sharedSecretFingerprint(client.sharedSecret) << endl;
    wipeX25519PrivateKey(serverKeyPair);

    return true;
}

void startForwarding(int sockfd, int tun_fd)
{
    unsigned char buffer[kMaxVpnTunPacketBytes];
    sockaddr_in clientAddress{};
    socklen_t clientLength = sizeof(clientAddress);

    cout << "encrypted tunnel bridge initialized." << endl;
    cout << "Waiting for raw packets..." << endl;

    while (true)
    {
        // readfds is noting but a array of bits which tells if the file descriptor at that index is being monitered or not if it is being monitered go shed and read and write 
        fd_set readfds;
        FD_ZERO(&readfds);

        FD_SET(sockfd, &readfds);
        FD_SET(tun_fd, &readfds);

        int max_fd = max(sockfd, tun_fd) + 1;

        if (select(max_fd, &readfds, NULL, NULL, NULL) < 0)
        {
            perror("select failed");
            break;
        }

        // Client -> Server -> TUN
        if (FD_ISSET(sockfd, &readfds))
        {
            clientLength = sizeof(clientAddress);
            int bytesReceived = recvfrom(
                sockfd, buffer, sizeof(buffer), 0,
                (sockaddr*)&clientAddress, &clientLength);

            if (bytesReceived > 0)
            {
                cout << "\n[CLIENT -> SERVER]" << endl;
                
                string message(
                    reinterpret_cast<const char*>(buffer),
                    bytesReceived);
                // handling the initial handshake with client 
               if (message.rfind("VPN_HELLO", 0) == 0)
                {          
                    handleHandshake(
                        sockfd,
                        reinterpret_cast<const char*>(buffer),
                        bytesReceived,
                        clientAddress,
                        clientLength
                        );

                    continue;
                }   

                else
                {
                    auto client = find_if(
                        vpn_ip.begin(),
                        vpn_ip.end(),
                        [&](const auto& entry)
                        {
                            return entry.second.address.sin_addr.s_addr ==
                                       clientAddress.sin_addr.s_addr &&
                                   entry.second.address.sin_port ==
                                       clientAddress.sin_port;
                        });

                    if (client == vpn_ip.end())
                    {
                        cerr << "Received packet from an unregistered client; dropping packet" << endl;
                        continue;
                    }

                    vector<unsigned char> plaintext;
                    if (!decryptVpnPacket(
                            buffer,
                            static_cast<size_t>(bytesReceived),
                            client->second.sessionKeys.clientToServer,
                            plaintext))
                    {
                        cerr << "Client-to-server packet authentication failed; dropping packet" << endl;
                        continue;
                    }

                    ssize_t bytesWritten = write(
                        tun_fd,
                        plaintext.data(),
                        plaintext.size());

                    if (bytesWritten < 0)
                        perror("Failed to write decrypted packet to TUN");
                    else if (static_cast<size_t>(bytesWritten) != plaintext.size())
                        cerr << "Failed to write complete decrypted packet to TUN" << endl;
                }
            }
        }

        // TUN -> Server -> Client
        if (FD_ISSET(tun_fd, &readfds))
        {
            int bytesRead = read(tun_fd, buffer, sizeof(buffer));

            if (bytesRead > 0)
            {
                cout << "\n[SERVER/TUN -> CLIENT]" << endl;

                if (bytesRead < static_cast<int>(sizeof(iphdr)))
                {
                    cerr << "Short/malformed IPv4 packet from TUN; dropping packet." << endl;
                    continue;
                }

                iphdr* ipHeader = reinterpret_cast<iphdr*>(buffer);
                int ipHeaderLength = ipHeader->ihl * 4;

                if (ipHeader->version != 4 ||
                    ipHeaderLength < static_cast<int>(sizeof(iphdr)) ||
                    ipHeaderLength > bytesRead)
                {
                    cerr << "Malformed IPv4 packet from TUN; dropping packet." << endl;
                    continue;
                }

                char destinationIP[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &ipHeader->daddr,
                              destinationIP, sizeof(destinationIP)) == nullptr)
                {
                    cerr << "Could not determine TUN packet destination; dropping packet." << endl;
                    continue;
                }

                auto client = vpn_ip.find(destinationIP);
                if (client == vpn_ip.end())
                {
                    cerr << "No registered client for VPN IP "
                         << destinationIP << "; dropping packet." << endl;
                    continue;
                }

                vector<unsigned char> encryptedPacket;
                if (!encryptVpnPacket(
                        buffer,
                        static_cast<size_t>(bytesRead),
                        client->second.sessionKeys.serverToClient,
                        encryptedPacket))
                {
                    cerr << "Failed to encrypt server-to-client packet; dropping packet" << endl;
                    continue;
                }

                ssize_t bytesSent = sendto(
                    sockfd,
                    encryptedPacket.data(),
                    encryptedPacket.size(),
                    0,
                    (sockaddr*)&client->second.address,
                    sizeof(client->second.address));

                if (bytesSent < 0)
                    perror("Failed to send encrypted packet to client");
                else if (static_cast<size_t>(bytesSent) != encryptedPacket.size())
                    cerr << "Failed to send complete encrypted packet to client" << endl;
            }
        }
    }
}
