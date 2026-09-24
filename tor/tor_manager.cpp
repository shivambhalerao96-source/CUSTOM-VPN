#include "tor_manager.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

namespace customvpn
{

std::string torStatusToString(TorStatus status)
{
    switch (status)
    {
    case TorStatus::Disabled:
        return "TOR_DISABLED";
    case TorStatus::Starting:
        return "TOR_STARTING";
    case TorStatus::Connecting:
        return "TOR_CONNECTING";
    case TorStatus::Connected:
        return "TOR_CONNECTED";
    case TorStatus::Error:
        return "TOR_ERROR";
    }
    return "TOR_DISABLED";
}

TorStatus stringToTorStatus(const std::string& statusStr)
{
    if (statusStr == "TOR_STARTING")
        return TorStatus::Starting;
    if (statusStr == "TOR_CONNECTING")
        return TorStatus::Connecting;
    if (statusStr == "TOR_CONNECTED")
        return TorStatus::Connected;
    if (statusStr == "TOR_ERROR")
        return TorStatus::Error;
    return TorStatus::Disabled;
}

TorManager& TorManager::getInstance()
{
    static TorManager instance;
    return instance;
}

TorManager::TorManager(const TorConfig& config)
    : m_config(config)
{
    m_pidFile = "/tmp/custom_vpn_tor_" + std::to_string(m_config.socksPort) + ".pid";
    m_logFile = "/tmp/custom_vpn_tor_" + std::to_string(m_config.socksPort) + ".log";
}

TorManager::~TorManager()
{
    stopTor();
}

bool TorManager::detectTorInstalled(std::string* outPath)
{
    std::string bin = m_config.torBinaryPath;
    if (bin.empty())
    {
        bin = TorConfig::detectTorBinary();
        if (!bin.empty())
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_config.torBinaryPath = bin;
        }
    }

    if (!bin.empty() && access(bin.c_str(), X_OK) == 0)
    {
        if (outPath)
            *outPath = bin;
        return true;
    }

    return false;
}

TorStatus TorManager::getStatus() const
{
    return m_status.load();
}

std::string TorManager::getStatusString() const
{
    return torStatusToString(m_status.load());
}

std::string TorManager::getErrorMessage() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_errorMessage;
}

bool TorManager::isConnected() const
{
    return m_status.load() == TorStatus::Connected;
}

const TorConfig& TorManager::getConfig() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

void TorManager::setConfig(const TorConfig& config)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
    m_pidFile = "/tmp/custom_vpn_tor_" + std::to_string(m_config.socksPort) + ".pid";
    m_logFile = "/tmp/custom_vpn_tor_" + std::to_string(m_config.socksPort) + ".log";
}

int TorManager::getSocksPort() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config.socksPort;
}

std::string TorManager::getSocksHost() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config.socksHost;
}

bool TorManager::isSocksPortReachable(const std::string& host, int port, int timeoutMs)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return false;

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(static_cast<uint16_t>(port));

    std::string connectHost = (host == "0.0.0.0") ? "127.0.0.1" : host;
    if (inet_pton(AF_INET, connectHost.c_str(), &target.sin_addr) <= 0)
    {
        close(sock);
        return false;
    }

    int res = connect(sock, reinterpret_cast<sockaddr*>(&target), sizeof(target));
    if (res < 0 && errno != EINPROGRESS)
    {
        close(sock);
        return false;
    }

    if (res != 0)
    {
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(sock, &writeSet);

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        int selectRes = select(sock + 1, nullptr, &writeSet, nullptr, &tv);
        if (selectRes <= 0)
        {
            close(sock);
            return false;
        }

        int socketError = 0;
        socklen_t len = sizeof(socketError);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &socketError, &len) < 0 || socketError != 0)
        {
            close(sock);
            return false;
        }
    }

    close(sock);
    return true;
}

bool TorManager::startTor()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_status == TorStatus::Connected || m_status == TorStatus::Starting || m_status == TorStatus::Connecting)
    {
        return true;
    }

    if (m_monitorThread.joinable())
    {
        m_stopMonitor = true;
        m_monitorThread.join();
        m_stopMonitor = false;
    }

    std::string torBin;
    if (!detectTorInstalled(&torBin))
    {
        m_status = TorStatus::Error;
        m_errorMessage = "Tor is not installed on the system";
        std::cerr << "[ TOR ] Failed to start Tor: " << m_errorMessage << std::endl;
        return false;
    }

    // Check if an existing Tor daemon is already running on the configured SOCKS port
    if (isSocksPortReachable(m_config.socksHost, m_config.socksPort, 200))
    {
        m_weStartedTor = false;
        m_status = TorStatus::Connected;
        m_errorMessage.clear();
        std::cout << "[ TOR ] SOCKS proxy ready on " << m_config.socksHost << ":" << m_config.socksPort << std::endl;
        std::cout << "[ TOR ] Tor connected" << std::endl;
        return true;
    }

    std::cout << "[ TOR ] Starting Tor..." << std::endl;
    m_status = TorStatus::Starting;
    m_errorMessage.clear();

    // Ensure data directory exists with strict permissions (0700 required by Tor)
    std::string dataDir = m_config.dataDir;
    mkdir(dataDir.c_str(), 0700);
    chmod(dataDir.c_str(), 0700);

    // Fork child process to run tor
    pid_t pid = fork();
    if (pid < 0)
    {
        m_status = TorStatus::Error;
        m_errorMessage = "Failed to fork process for Tor";
        std::cerr << "[ TOR ] Failed to start Tor: " << m_errorMessage << std::endl;
        return false;
    }

    if (pid == 0)
    {
        // In child process
        // Redirect stdout/stderr to logfile
        int logFd = open(m_logFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (logFd >= 0)
        {
            dup2(logFd, STDOUT_FILENO);
            dup2(logFd, STDERR_FILENO);
            close(logFd);
        }

        int devNull = open("/dev/null", O_RDONLY);
        if (devNull >= 0)
        {
            dup2(devNull, STDIN_FILENO);
            close(devNull);
        }

        std::string socksArg = m_config.socksHost + ":" + std::to_string(m_config.socksPort);

        std::vector<const char*> args = {
            torBin.c_str(),
            "--SocksPort", socksArg.c_str(),
            "--DataDirectory", dataDir.c_str(),
            "--PidFile", m_pidFile.c_str(),
            "--RunAsDaemon", "0",
            nullptr
        };

        execvp(torBin.c_str(), const_cast<char* const*>(args.data()));
        _exit(127);
    }

    // In parent process
    m_childPid = pid;
    m_weStartedTor = true;
    m_status = TorStatus::Connecting;
    std::cout << "[ TOR ] Connecting..." << std::endl;

    m_stopMonitor = false;
    m_monitorThread = std::thread(&TorManager::monitorStartup, this);

    return true;
}

void TorManager::monitorStartup()
{
    // Wait up to 30 seconds for Tor SOCKS port to be ready
    const int maxWaitSeconds = 30;
    const auto startTime = std::chrono::steady_clock::now();

    while (!m_stopMonitor.load())
    {
        // Check if child exited
        if (m_childPid > 0)
        {
            int status = 0;
            pid_t res = waitpid(m_childPid, &status, WNOHANG);
            if (res == m_childPid)
            {
                // Child died
                std::lock_guard<std::mutex> lock(m_mutex);
                m_status = TorStatus::Error;
                m_childPid = -1;
                m_weStartedTor = false;

                // Read last lines of log if available
                std::string logTail;
                std::ifstream log(m_logFile);
                if (log.is_open())
                {
                    std::string line;
                    while (std::getline(log, line))
                    {
                        if (line.find("[warn]") != std::string::npos || line.find("[err]") != std::string::npos)
                            logTail = line;
                    }
                }

                if (logTail.empty())
                    logTail = "process exited unexpectedly";

                m_errorMessage = logTail;
                std::cerr << "[ TOR ] Failed to start Tor: " << m_errorMessage << std::endl;
                return;
            }
        }

        // Check if SOCKS port is listening
        if (isSocksPortReachable(m_config.socksHost, m_config.socksPort, 200))
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_status = TorStatus::Connected;
            m_errorMessage.clear();
            std::cout << "[ TOR ] SOCKS proxy ready on " << m_config.socksHost << ":" << m_config.socksPort << std::endl;
            std::cout << "[ TOR ] Tor connected" << std::endl;
            return;
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime).count();

        if (elapsed >= maxWaitSeconds)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_status = TorStatus::Error;
            m_errorMessage = "Tor startup timed out after " + std::to_string(maxWaitSeconds) + " seconds";
            std::cerr << "[ TOR ] Failed to start Tor: " << m_errorMessage << std::endl;
            return;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

bool TorManager::stopTor()
{
    m_stopMonitor = true;
    if (m_monitorThread.joinable())
    {
        m_monitorThread.join();
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_status == TorStatus::Disabled && m_childPid <= 0)
    {
        return true;
    }

    if (m_weStartedTor && m_childPid > 0)
    {
        kill(m_childPid, SIGTERM);

        // Wait up to 3 seconds for clean exit
        int status = 0;
        bool exited = false;
        for (int i = 0; i < 30; ++i)
        {
            pid_t res = waitpid(m_childPid, &status, WNOHANG);
            if (res == m_childPid)
            {
                exited = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!exited)
        {
            kill(m_childPid, SIGKILL);
            waitpid(m_childPid, &status, 0);
        }

        unlink(m_pidFile.c_str());
        m_childPid = -1;
        m_weStartedTor = false;
    }

    m_status = TorStatus::Disabled;
    m_errorMessage.clear();
    std::cout << "[ TOR ] Tor disabled" << std::endl;

    return true;
}

} // namespace customvpn
