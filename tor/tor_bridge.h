#ifndef TOR_BRIDGE_H
#define TOR_BRIDGE_H

#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>

namespace customvpn
{

class TorBridge
{
public:
    static TorBridge& getInstance();

    TorBridge();
    ~TorBridge();

    // Start forwarding localPort -> targetHost:targetPort
    bool start(const std::string& localHost, int localPort,
               const std::string& targetHost, int targetPort);

    // Stop forwarding
    void stop();

    bool isRunning() const;
    int getLocalPort() const;
    std::string getTargetHost() const;
    int getTargetPort() const;

private:
    void acceptLoop(int listenFd, const std::string& targetHost, int targetPort);
    static void relayBidirectional(int clientFd, int targetFd);

    std::atomic<bool> m_running{false};
    std::string m_localHost{"127.0.0.1"};
    int m_localPort{9050};
    std::string m_targetHost{"10.0.0.2"};
    int m_targetPort{9050};

    int m_listenFd{-1};
    std::thread m_acceptThread;
    std::mutex m_mutex;
};

} // namespace customvpn

#endif // TOR_BRIDGE_H
