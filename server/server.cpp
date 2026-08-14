#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include "forward.h"

using namespace std;

static string g_extIface;          // external interface used for NAT (e.g. eth0)
static bool g_natConfigured = false;

// Runs a shell command and captures its stdout (used to auto-detect the
// interface that currently has the default route, e.g. "eth0").
static string run_and_capture(const string& cmd) {
    string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return result;

    char buf[256];
    while (fgets(buf, sizeof(buf), pipe) != nullptr)
        result += buf;
    pclose(pipe);

    // trim trailing whitespace/newline
    while (!result.empty() && isspace((unsigned char)result.back()))
        result.pop_back();

    return result;
}

// Detects the network interface used to reach the internet, e.g.:
//   default via 203.0.113.1 dev eth0 ...
static string detect_external_iface() {
    string iface = run_and_capture(
        "ip route show default | awk '{for(i=1;i<=NF;i++) if ($i==\"dev\") print $(i+1)}' | head -n1");

    if (iface.empty())
        cout << "Warning: could not auto-detect external interface. "
                "NAT/forwarding will not be configured automatically." << endl;
    else
        cout << "Detected external interface: " << iface << endl;

    return iface;
}

// Enables kernel IP forwarding, and sets up NAT (MASQUERADE) + FORWARD
// rules so traffic entering tun0 can go out to the internet via extIface,
// and return traffic can come back in.
static void setup_nat_forwarding(const string& extIface) {
    if (extIface.empty())
        return;

    // Enable IP forwarding in the kernel
    system("sudo sysctl -w net.ipv4.ip_forward=1");

    // NAT: rewrite source address of tunnel traffic to the server's public IP
    string masqCmd = "sudo iptables -t nat -A POSTROUTING -o " + extIface + " -j MASQUERADE";
    system(masqCmd.c_str());

    // Allow forwarding from tun0 -> external interface
    string fwdOutCmd = "sudo iptables -A FORWARD -i tun0 -o " + extIface + " -j ACCEPT";
    system(fwdOutCmd.c_str());

    // Allow established/related return traffic back in
    string fwdInCmd = "sudo iptables -A FORWARD -i " + extIface +
                       " -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT";
    system(fwdInCmd.c_str());

    g_natConfigured = true;
    cout << "IP forwarding enabled and NAT rules configured (tun0 <-> "
         << extIface << ")." << endl;
}

// Removes the iptables rules added above. Best-effort; safe to call even
// if setup_nat_forwarding() was never called or partially failed.
static void teardown_nat_forwarding() {
    if (!g_natConfigured || g_extIface.empty())
        return;

    string masqCmd = "sudo iptables -t nat -D POSTROUTING -o " + g_extIface + " -j MASQUERADE";
    system(masqCmd.c_str());

    string fwdOutCmd = "sudo iptables -D FORWARD -i tun0 -o " + g_extIface + " -j ACCEPT";
    system(fwdOutCmd.c_str());

    string fwdInCmd = "sudo iptables -D FORWARD -i " + g_extIface +
                       " -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT";
    system(fwdInCmd.c_str());

    cout << "NAT/forwarding rules removed." << endl;
}

static void handle_sigint(int) {
    teardown_nat_forwarding();
    exit(0);
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

    // Auto-detect the interface facing the internet, then enable
    // forwarding + NAT so tunnel traffic can actually reach it.
    g_extIface = detect_external_iface();
    setup_nat_forwarding(g_extIface);

    return fd; 
}

int main() {
    // Ensure NAT/iptables rules are cleaned up if the server is killed
    // with Ctrl+C, rather than left behind on the system.
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

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

    teardown_nat_forwarding();
    close(tun_fd);
    close(sockfd);
    return 0;
}