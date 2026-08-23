#include "forward.h"
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

using namespace std;
struct ClientInfo {
    sockaddr_in address;
    string vpnIP;
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

void printPayload(const unsigned char* data, int len)
{
    if (len <= 0)
    {
        cout << "Application Data : None" << endl;
        return;
    }

    cout << "Application Data (HEX): ";
    for (int i = 0; i < len; i++)
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
    cout << dec << endl;

    cout << "Application Data (ASCII): ";
    for (int i = 0; i < len; i++)
        cout << (isprint(data[i]) ? (char)data[i] : '.');
    cout << endl;
}

void printPacketInfo(const char* buffer, int bytes)
{
    if (bytes < (int)sizeof(iphdr))
    {
        cout << "Invalid/short IP packet." << endl;
        return;
    }

    iphdr* ip = (iphdr*)buffer;

    if (ip->version == 6)
    {
        cout << "IPv6 packet received - inspection not implemented yet." << endl;
        return;
    }

    if (ip->version != 4)
    {
        cout << "Unknown IP version - ignoring packet." << endl;
        return;
    }

    int ipHeaderLen = ip->ihl * 4;

    if (ipHeaderLen < 20 || ipHeaderLen > bytes)
    {
        cout << "Invalid IP header." << endl;
        return;
    }

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

    cout << "\n--- IP PACKET ---" << endl;
    cout << "Source IP      : " << src << endl;
    cout << "Destination IP : " << dst << endl;
    cout << "Protocol       : " << (int)ip->protocol;

    if (ip->protocol == IPPROTO_TCP)
        cout << " (TCP)";
    else if (ip->protocol == IPPROTO_UDP)
        cout << " (UDP)";
    else if (ip->protocol == IPPROTO_ICMP)
        cout << " (ICMP)";
    else
        cout << " (Other)";

    cout << endl;
    cout << "TTL            : " << (int)ip->ttl << endl;
    cout << "Total Length   : " << ntohs(ip->tot_len) << " bytes" << endl;

    int ipTotalLen = ntohs(ip->tot_len);
    if (ipTotalLen > bytes)
        ipTotalLen = bytes;

    unsigned char* transport =
        (unsigned char*)buffer + ipHeaderLen;

    int transportLen = ipTotalLen - ipHeaderLen;

    if (ip->protocol == IPPROTO_TCP)
    {
        if (transportLen < (int)sizeof(tcphdr))
        {
            cout << "Invalid TCP packet." << endl;
            return;
        }

        tcphdr* tcp = (tcphdr*)transport;
        int tcpHeaderLen = tcp->doff * 4;

        if (tcpHeaderLen < 20 || tcpHeaderLen > transportLen)
        {
            cout << "Invalid TCP header." << endl;
            return;
        }

        cout << "Source Port    : " << ntohs(tcp->source) << endl;
        cout << "Destination Port: " << ntohs(tcp->dest) << endl;

        cout << "TCP Flags      : ";
        if (tcp->syn) cout << "SYN ";
        if (tcp->ack) cout << "ACK ";
        if (tcp->fin) cout << "FIN ";
        if (tcp->rst) cout << "RST ";
        if (tcp->psh) cout << "PSH ";
        if (tcp->urg) cout << "URG ";
        cout << endl;

        unsigned char* payload = transport + tcpHeaderLen;
        int payloadLen = transportLen - tcpHeaderLen;

        cout << "Data Length    : " << payloadLen << " bytes" << endl;
        printPayload(payload, payloadLen);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        if (transportLen < (int)sizeof(udphdr))
        {
            cout << "Invalid UDP packet." << endl;
            return;
        }

        udphdr* udp = (udphdr*)transport;

        cout << "Source Port    : " << ntohs(udp->source) << endl;
        cout << "Destination Port: " << ntohs(udp->dest) << endl;
        cout << "UDP Length     : " << ntohs(udp->len) << " bytes" << endl;

        unsigned char* payload =
            transport + sizeof(udphdr);

        int payloadLen =
            transportLen - sizeof(udphdr);

        cout << "Data Length    : " << payloadLen << " bytes" << endl;
        printPayload(payload, payloadLen);
    }
    else
    {
        cout << "IP Payload Length: "
             << transportLen << " bytes" << endl;
    }

    cout << "-----------------" << endl;
}

bool handleHandshake(int sockfd, const char* buffer, int bytesReceived, sockaddr_in& clientAddress, socklen_t clientLength)
{
    string message(buffer, bytesReceived);

    if (message != "VPN_HELLO")
        return false;

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

    // Store client information
    ClientInfo client;

    client.address = clientAddress;
    client.vpnIP = vpnIP;

    vpn_ip[vpnIP] = client;

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
    string response = "VPN_IP " + vpnIP;

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

void startForwarding(int sockfd, int tun_fd)
{
    char buffer[65535];
    sockaddr_in clientAddress{};
    socklen_t clientLength = sizeof(clientAddress);

    cout << "Unencrypted tunnel bridge initialized." << endl;
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
            int bytesReceived = recvfrom(
                sockfd, buffer, sizeof(buffer), 0,
                (sockaddr*)&clientAddress, &clientLength);

            if (bytesReceived > 0)
            {
                cout << "\n[CLIENT -> SERVER]" << endl;
                printPacketInfo(buffer, bytesReceived);
                    string message(buffer, bytesReceived);
                // handling the initial handshake with client 
               if (message == "VPN_HELLO")
                {          
                    handleHandshake(
                        sockfd,
                        buffer,
                        bytesReceived,
                        clientAddress,
                        clientLength
                        );

                    continue;
                }   

                else write(tun_fd, buffer, bytesReceived);
            }
        }

        // TUN -> Server -> Client
        if (FD_ISSET(tun_fd, &readfds))
        {
            int bytesRead = read(tun_fd, buffer, sizeof(buffer));

            if (bytesRead > 0)
            {
                cout << "\n[SERVER/TUN -> CLIENT]" << endl;
                printPacketInfo(buffer, bytesRead);

                sendto(
                    sockfd, buffer, bytesRead, 0,
                    (sockaddr*)&clientAddress, clientLength);
            }
        }
    }
}