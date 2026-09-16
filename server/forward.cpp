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
#include <netinet/ip6.h>
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
    string vpnIPv6;
    X25519SharedSecret sharedSecret;
    SessionKeys sessionKeys;

    ~ClientInfo()
    {
        wipeX25519SharedSecret(sharedSecret);
        wipeSessionKeys(sessionKeys);
    }
};

unordered_map<string, ClientInfo> vpn_ip;// maps the vpn_ip to client info 

// Maps a client's VPN IPv6 address back to the VPN IPv4 address used as the
// key in vpn_ip above. This keeps ClientInfo (and its secret-wiping
// destructor) stored in exactly one place; the IPv6 map is just a second
// index onto the same records, so nothing about session-key ownership or
// lifetime changes.
unordered_map<string, string> vpn_ipv6_to_ipv4;

// ULA (Unique Local Address) /64 prefix used for the VPN's internal IPv6
// addressing, analogous to the 10.0.0.0/24 used for IPv4. This range is not
// globally routable by itself -- getting it out to the real IPv6 Internet
// is handled by NAT66 (ip6tables MASQUERADE) on the server, set up in
// server.cpp, exactly the way MASQUERADE already does it for the IPv4 range.
static const string kVpnIPv6Prefix = "fd00:dead:beef::";

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

// Derives this client's VPN IPv6 address from the IPv4 address it was just
// allocated, by reusing the same host id (the last IPv4 octet) inside the
// IPv6 /64 range. Because it's derived from an already-uniquely-allocated
// IPv4 address, it's automatically unique too -- no separate IPv6 allocation
// table or free-list is needed, and allocateVPNIP() above stays untouched.
string deriveVpnIPv6FromIPv4(const string& vpnIPv4)
{
    size_t lastDot = vpnIPv4.find_last_of('.');
    if (lastDot == string::npos)
        return "";

    string hostIdText = vpnIPv4.substr(lastDot + 1);
    int hostId = 0;
    try
    {
        hostId = stoi(hostIdText);
    }
    catch (...)
    {
        return "";
    }

    ostringstream oss;
    oss << kVpnIPv6Prefix << hex << hostId;
    return oss.str();
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

    // Derive the paired VPN IPv6 address from the IPv4 one that was just
    // allocated (see deriveVpnIPv6FromIPv4 for why this is safe/unique).
    string vpnIPv6 = deriveVpnIPv6FromIPv4(vpnIP);

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
    client.vpnIPv6 = vpnIPv6;

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
    if (!vpnIPv6.empty())
        vpn_ipv6_to_ipv4[vpnIPv6] = vpnIP;

    cout << "New VPN client registered" << endl;
    cout << "VPN IPv4 : " << vpnIP << endl;
    cout << "VPN IPv6 : " << vpnIPv6 << endl;

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

    // Send assigned VPN IPs. Wire format: "VPN_IP <ipv4> <ipv6> <server-pubkey-hex>".
    string response =
        "VPN_IP " + vpnIP + " " + vpnIPv6 + " " +
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

                    // Note: this direction never needed to inspect the IP
                    // version before (IPv4 or IPv6) -- the client is already
                    // identified by its real UDP source address/port above,
                    // so the decrypted packet (whichever family it is) is
                    // simply handed to the kernel via the TUN device, which
                    // auto-detects v4 vs v6 from the packet itself in
                    // IFF_NO_PI mode. No change needed here for IPv6.
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

                if (bytesRead < 1)
                {
                    cerr << "Empty packet from TUN; dropping packet." << endl;
                    continue;
                }

                // This direction is the one place that has to tell IPv4 and
                // IPv6 apart: the server multiplexes many clients over one
                // TUN device, so it needs the packet's destination address
                // to look up which client to encrypt-and-send it to. The
                // top nibble of the first byte is the IP version for both
                // families, so we branch on that before touching either
                // header struct.
                unsigned char ipVersion = static_cast<unsigned char>((buffer[0] >> 4) & 0x0F);
                string destinationIP; // key into vpn_ip, resolved below for either family

                if (ipVersion == 4)
                {
                    // ---- Existing IPv4 path, unchanged ----
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

                    char destinationIPv4[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, &ipHeader->daddr,
                                  destinationIPv4, sizeof(destinationIPv4)) == nullptr)
                    {
                        cerr << "Could not determine TUN packet destination; dropping packet." << endl;
                        continue;
                    }

                    destinationIP = destinationIPv4;
                }
                else if (ipVersion == 6)
                {
                    // ---- New IPv6 path ----
                    // TCP/UDP/ICMPv6 all live inside this same IPv6 payload;
                    // we don't need to special-case them here because (just
                    // like the IPv4 path) we only need the outer IPv6
                    // header's destination address to pick a client -- the
                    // whole packet, whatever transport protocol it carries,
                    // is forwarded encrypted as-is.
                    if (bytesRead < static_cast<int>(sizeof(ip6_hdr)))
                    {
                        cerr << "Short/malformed IPv6 packet from TUN; dropping packet." << endl;
                        continue;
                    }

                    ip6_hdr* ip6Header = reinterpret_cast<ip6_hdr*>(buffer);

                    char destinationIPv6[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, &ip6Header->ip6_dst,
                                  destinationIPv6, sizeof(destinationIPv6)) == nullptr)
                    {
                        cerr << "Could not determine IPv6 TUN packet destination; dropping packet." << endl;
                        continue;
                    }

                    auto ipv6Entry = vpn_ipv6_to_ipv4.find(destinationIPv6);
                    if (ipv6Entry == vpn_ipv6_to_ipv4.end())
                    {
                        cerr << "No registered client for VPN IPv6 "
                             << destinationIPv6 << "; dropping packet." << endl;
                        continue;
                    }

                    destinationIP = ipv6Entry->second; // the client's IPv4 key in vpn_ip
                }
                else
                {
                    cerr << "Unknown/unsupported IP version (" << (int)ipVersion
                         << ") from TUN; dropping packet." << endl;
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