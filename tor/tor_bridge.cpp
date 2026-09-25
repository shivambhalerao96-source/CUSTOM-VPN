#include "tor_bridge.h"

#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <vector>

namespace customvpn
{

TorBridge& TorBridge::getInstance()
{
    static TorBridge instance;
    return instance;
}

TorBridge::TorBridge() = default;

TorBridge::~TorBridge()
{
    stop();
}

bool TorBridge::isRunning() const
{
    return m_running.load();
}

int TorBridge::getLocalPort() const
{
    return m_localPort;
}

std::string TorBridge::getTargetHost() const
{
    return m_targetHost;
}

int TorBridge::getTargetPort() const
{
    return m_targetPort;
}

bool TorBridge::start(const std::string& localHost, int localPort,
                      const std::string& targetHost, int targetPort)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_running.load())
    {
        return true;
    }

    m_localHost = localHost;
    m_localPort = localPort;
    m_targetHost = targetHost;
    m_targetPort = targetPort;

    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0)
    {
        return false;
    }

    int opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(static_cast<uint16_t>(localPort));
    if (inet_pton(AF_INET, localHost.c_str(), &bindAddr.sin_addr) <= 0)
    {
        close(listenFd);
        return false;
    }

    if (bind(listenFd, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) < 0)
    {
        close(listenFd);
        return false;
    }

    if (listen(listenFd, 16) < 0)
    {
        close(listenFd);
        return false;
    }

    m_listenFd = listenFd;
    m_running.store(true);

    m_acceptThread = std::thread(&TorBridge::acceptLoop, this, listenFd, targetHost, targetPort);

    std::cout << "[ TOR ] Local bridge active on " << localHost << ":" << localPort
              << " -> " << targetHost << ":" << targetPort << std::endl;

    return true;
}

void TorBridge::stop()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_running.load())
        return;

    m_running.store(false);

    if (m_listenFd >= 0)
    {
        close(m_listenFd);
        m_listenFd = -1;
    }

    if (m_acceptThread.joinable())
    {
        m_acceptThread.join();
    }
}

void TorBridge::acceptLoop(int listenFd, const std::string& targetHost, int targetPort)
{
    while (m_running.load())
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(listenFd, &readSet);

        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 200000; // 200ms

        int res = select(listenFd + 1, &readSet, nullptr, nullptr, &tv);
        if (res <= 0 || !FD_ISSET(listenFd, &readSet))
        {
            continue;
        }

        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        int clientFd = accept(listenFd, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
        if (clientFd < 0)
        {
            continue;
        }

        // Connect to target
        int targetFd = socket(AF_INET, SOCK_STREAM, 0);
        if (targetFd < 0)
        {
            close(clientFd);
            continue;
        }

        sockaddr_in targetAddr{};
        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = htons(static_cast<uint16_t>(targetPort));
        if (inet_pton(AF_INET, targetHost.c_str(), &targetAddr.sin_addr) <= 0 ||
            connect(targetFd, reinterpret_cast<sockaddr*>(&targetAddr), sizeof(targetAddr)) < 0)
        {
            std::cerr << "[ TOR BRIDGE ] Connection failed to " << targetHost << ":" << targetPort
                      << " - " << strerror(errno) << std::endl;
            close(clientFd);
            close(targetFd);
            continue;
        }

        // Spawn detached relay thread
        std::thread([clientFd, targetFd]() {
            relayBidirectional(clientFd, targetFd);
        }).detach();
    }
}

void TorBridge::relayBidirectional(int clientFd, int targetFd)
{
    std::vector<unsigned char> buffer(16384);

    while (true)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(clientFd, &readSet);
        FD_SET(targetFd, &readSet);

        int maxFd = std::max(clientFd, targetFd) + 1;
        timeval tv{};
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int res = select(maxFd, &readSet, nullptr, nullptr, &tv);
        if (res < 0)
            break;
        if (res == 0)
            continue;

        if (FD_ISSET(clientFd, &readSet))
        {
            ssize_t bytes = read(clientFd, buffer.data(), buffer.size());
            if (bytes <= 0)
                break;
            if (write(targetFd, buffer.data(), bytes) != bytes)
                break;
        }

        if (FD_ISSET(targetFd, &readSet))
        {
            ssize_t bytes = read(targetFd, buffer.data(), buffer.size());
            if (bytes <= 0)
                break;
            if (write(clientFd, buffer.data(), bytes) != bytes)
                break;
        }
    }

    close(clientFd);
    close(targetFd);
}

} // namespace customvpn
