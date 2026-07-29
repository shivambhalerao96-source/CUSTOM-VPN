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
#include <cstdio>
#include <array>
#include <string>

using namespace std;

// Finds the name of the interface used for the default route (e.g. eth0, ens5)
// so we know which interface to NAT traffic out of.
string get_default_interface() {
    array<char, 256> buf{};
    string result;

    // "ip route show default" prints a line like:
    // default via 172.31.0.1 dev eth0 proto dhcp ...
    FILE* pipe = popen("ip route show default | awk '{print $5; exit}'", "r");
    if (!pipe) {
        return "";
    }
    if (fgets(buf.data(), buf.size(), pipe) != nullptr) {
        result = buf.data();
    }
    pclose(pipe);

    // Strip trailing newline
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

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

    // --- The part that was missing: actually let the kernel route tunnel traffic out ---

    // 1. Enable IP forwarding so the kernel forwards packets between tun0 and
    //    the internet-facing interface instead of dropping them.
    system("sudo sysctl -w net.ipv4.ip_forward=1");

    // 2. Figure out which interface actually reaches the internet (e.g. eth0).
    string wan_if = get_default_interface();
    if (wan_if.empty()) {
        cerr << "Warning: could not auto-detect the internet-facing interface. "
                "NAT/MASQUERADE was not configured; outbound traffic will not "
                "reach the internet. Set it manually, e.g.:\n"
                "  sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE\n";
        return fd;
    }
    cout << "Detected internet-facing interface: " << wan_if << endl;

    // 3. NAT (MASQUERADE) so packets leaving on wan_if get the server's public
    //    IP as their source, and replies get translated back to the client's
    //    tunnel IP (10.0.0.1) automatically via conntrack.
    string masqCmd = "sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o " + wan_if + " -j MASQUERADE";
    system(masqCmd.c_str());

    // 4. Make sure the FORWARD chain actually allows this traffic through
    //    (some setups default the FORWARD policy to DROP).
    string fwdOutCmd = "sudo iptables -A FORWARD -i tun0 -o " + wan_if + " -j ACCEPT";
    string fwdInCmd  = "sudo iptables -A FORWARD -i " + wan_if + " -o tun0 -m state --state ESTABLISHED,RELATED -j ACCEPT";
    system(fwdOutCmd.c_str());
    system(fwdInCmd.c_str());

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