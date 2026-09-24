#ifndef TOR_CONFIG_H
#define TOR_CONFIG_H

#include <string>

namespace customvpn
{

struct TorConfig
{
    bool enabled = false;
    std::string socksHost = "0.0.0.0"; // Bind to all interfaces so client on 10.0.0.2 can connect
    int socksPort = 9050;              // Standard Tor SOCKS port, configurable
    std::string dataDir = "/tmp/custom_vpn_tor_data";
    std::string torBinaryPath = "";    // Auto-detected if empty
    std::string clientBridgeHost = "127.0.0.1";
    int clientBridgePort = 9050;       // Local bridge port on client
    std::string serverVpnIp = "10.0.0.2"; // Server TUN IP

    static TorConfig fromEnvironment();
    static std::string detectTorBinary();
};

} // namespace customvpn

#endif // TOR_CONFIG_H
