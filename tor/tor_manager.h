#ifndef TOR_MANAGER_H
#define TOR_MANAGER_H

#include "tor_config.h"

#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include <sys/types.h>

namespace customvpn
{

enum class TorStatus
{
    Disabled,
    Starting,
    Connecting,
    Connected,
    Error
};

std::string torStatusToString(TorStatus status);
TorStatus stringToTorStatus(const std::string& statusStr);

class TorManager
{
public:
    static TorManager& getInstance();

    explicit TorManager(const TorConfig& config = TorConfig::fromEnvironment());
    ~TorManager();

    // Non-copyable
    TorManager(const TorManager&) = delete;
    TorManager& operator=(const TorManager&) = delete;

    // Process lifecycle
    bool detectTorInstalled(std::string* outPath = nullptr);
    bool startTor();
    bool stopTor();

    // Status queries
    TorStatus getStatus() const;
    std::string getStatusString() const;
    std::string getErrorMessage() const;
    bool isConnected() const;

    // Config accessors
    const TorConfig& getConfig() const;
    void setConfig(const TorConfig& config);
    int getSocksPort() const;
    std::string getSocksHost() const;

private:
    bool isSocksPortReachable(const std::string& host, int port, int timeoutMs = 250);
    void monitorStartup();

    TorConfig m_config;
    mutable std::mutex m_mutex;
    std::atomic<TorStatus> m_status{TorStatus::Disabled};
    std::string m_errorMessage;
    pid_t m_childPid{-1};
    bool m_weStartedTor{false};
    std::thread m_monitorThread;
    std::atomic<bool> m_stopMonitor{false};
    std::string m_pidFile;
    std::string m_logFile;
};

} // namespace customvpn

#endif // TOR_MANAGER_H
