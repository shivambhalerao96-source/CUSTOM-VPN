#include "tor_config.h"

#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <sstream>
#include <array>
#include <memory>

namespace customvpn
{

std::string TorConfig::detectTorBinary()
{
    const std::vector<std::string> standardPaths = {
        "tor/bin/tor",
        "./tor/bin/tor",
        "../tor/bin/tor",
        "/usr/bin/tor",
        "/usr/local/bin/tor",
        "/bin/tor",
        "/usr/sbin/tor"
    };

    for (const auto& path : standardPaths)
    {
        if (access(path.c_str(), X_OK) == 0)
        {
            return path;
        }
    }

    // Fall back to searching PATH via 'which tor'
    std::array<char, 256> buffer{};
    std::string result;
    struct PipeCloser { void operator()(FILE* f) const { if (f) pclose(f); } };
    std::unique_ptr<FILE, PipeCloser> pipe(popen("which tor 2>/dev/null", "r"));
    if (pipe)
    {
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
        {
            result += buffer.data();
        }
        while (!result.empty() && (result.back() == '\n' || result.back() == '\r' || result.back() == ' '))
        {
            result.pop_back();
        }
        if (!result.empty() && access(result.c_str(), X_OK) == 0)
        {
            return result;
        }
    }

    return "";
}

TorConfig TorConfig::fromEnvironment()
{
    TorConfig config;

    const char* envEnabled = std::getenv("TOR_ENABLED");
    if (envEnabled)
    {
        std::string val(envEnabled);
        config.enabled = (val == "1" || val == "true" || val == "TRUE" || val == "on" || val == "yes");
    }

    const char* envHost = std::getenv("TOR_SOCKS_HOST");
    if (envHost && envHost[0] != '\0')
    {
        config.socksHost = envHost;
    }

    const char* envPort = std::getenv("TOR_SOCKS_PORT");
    if (envPort && envPort[0] != '\0')
    {
        try
        {
            int p = std::stoi(envPort);
            if (p > 0 && p <= 65535)
                config.socksPort = p;
        }
        catch (...)
        {
        }
    }

    const char* envDataDir = std::getenv("TOR_DATA_DIR");
    if (envDataDir && envDataDir[0] != '\0')
    {
        config.dataDir = envDataDir;
    }

    const char* envBinary = std::getenv("TOR_BINARY_PATH");
    if (envBinary && envBinary[0] != '\0' && access(envBinary, X_OK) == 0)
    {
        config.torBinaryPath = envBinary;
    }
    else
    {
        config.torBinaryPath = detectTorBinary();
    }

    const char* envBridgePort = std::getenv("TOR_BRIDGE_PORT");
    if (envBridgePort && envBridgePort[0] != '\0')
    {
        try
        {
            int p = std::stoi(envBridgePort);
            if (p > 0 && p <= 65535)
                config.clientBridgePort = p;
        }
        catch (...)
        {
        }
    }

    const char* envServerIp = std::getenv("TOR_SERVER_VPN_IP");
    if (envServerIp && envServerIp[0] != '\0')
    {
        config.serverVpnIp = envServerIp;
    }

    return config;
}

} // namespace customvpn
