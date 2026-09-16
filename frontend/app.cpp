#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QProcess>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace
{
QString localIpv4Address()
{
    ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0)
        return QStringLiteral("Unavailable");

    QString address = QStringLiteral("Unavailable");
    for (ifaddrs* interface = interfaces; interface != nullptr; interface = interface->ifa_next)
    {
        if (interface->ifa_addr == nullptr ||
            interface->ifa_addr->sa_family != AF_INET ||
            QString::fromLocal8Bit(interface->ifa_name) == QStringLiteral("lo"))
            continue;

        char buffer[INET_ADDRSTRLEN] = {};
        const auto* addressInfo = reinterpret_cast<sockaddr_in*>(interface->ifa_addr);
        if (inet_ntop(AF_INET, &addressInfo->sin_addr, buffer, sizeof(buffer)) != nullptr)
            address = QString::fromLatin1(buffer);
        break;
    }
    freeifaddrs(interfaces);
    return address;
}

quint64 interfaceBytes()
{
    std::ifstream stats("/proc/net/dev");
    std::string line;
    quint64 total = 0;
    while (std::getline(stats, line))
    {
        const auto separator = line.find(':');
        if (separator == std::string::npos)
            continue;

        std::istringstream values(line.substr(separator + 1));
        quint64 received = 0;
        quint64 transmitted = 0;
        values >> received;
        for (int column = 1; column < 8; ++column)
        {
            quint64 ignored = 0;
            values >> ignored;
        }
        values >> transmitted;
        total += received + transmitted;
    }
    return total;
}
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QWidget window;

    window.setWindowTitle("Custom VPN");
    window.resize(760, 500);
    window.setStyleSheet(R"(
        QWidget { background: #101820; color: #f2f5f7; font-family: "DejaVu Sans"; }
        QLabel#title { font-size: 28px; font-weight: 700; color: #ffffff; }
        QLabel#subtitle { color: #8fa4b3; font-size: 13px; }
        QGroupBox { border: 1px solid #263744; border-radius: 8px; margin-top: 12px; padding: 14px; }
        QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; color: #8fa4b3; }
        QLabel.metric { background: #182630; border: 1px solid #263744; border-radius: 8px; padding: 16px; }
        QLabel.metricValue { color: #62d6b5; font-size: 20px; font-weight: 700; }
        QComboBox { background: #182630; border: 1px solid #385160; border-radius: 5px; padding: 9px; }
        QPushButton { border: 0; border-radius: 5px; padding: 10px 18px; font-weight: 700; }
        QPushButton#run { background: #62d6b5; color: #10201d; }
        QPushButton#close { background: #263744; color: #f2f5f7; }
        QPushButton:disabled { background: #263744; color: #6e818d; }
    )");

    auto* root = new QVBoxLayout(&window);
    auto* title = new QLabel("Custom VPN");
    title->setObjectName("title");
    root->addWidget(title);
    auto* subtitle = new QLabel("Secure tunnel control and connection telemetry");
    subtitle->setObjectName("subtitle");
    root->addWidget(subtitle);

    auto* controls = new QGroupBox("Connection");
    auto* controlsLayout = new QHBoxLayout(controls);
    auto* server = new QComboBox;
    server->addItem("USA VPN  •  34.145.231.1", "34.145.231.1");
    server->addItem("Europe VPN  •  8.228.37.190", "8.228.37.190");
    server->addItem("Local development  •  127.0.0.1", "127.0.0.1");
    QString selectedServerIp = server->currentData().toString();
    QObject::connect(server, &QComboBox::currentIndexChanged, &window,
                     [&selectedServerIp, server](int index) {
        selectedServerIp = server->itemData(index).toString();
    });
    controlsLayout->addWidget(server, 1);
    auto* runButton = new QPushButton("Run VPN");
    runButton->setObjectName("run");
    auto* closeButton = new QPushButton("Close");
    closeButton->setObjectName("close");
    controlsLayout->addWidget(runButton);
    controlsLayout->addWidget(closeButton);
    root->addWidget(controls);

    auto* dashboard = new QGroupBox("Live dashboard");
    auto* metrics = new QGridLayout(dashboard);
    auto addMetric = [metrics](const QString& name, int row, int column) {
        auto* label = new QLabel(name + "\n--");
        label->setProperty("class", "metric");
        label->setObjectName(name);
        label->setMinimumHeight(82);
        metrics->addWidget(label, row, column);
        return label;
    };
    auto* speed = addMetric("Internet speed", 0, 0);
    auto* ipv4 = addMetric("IPv4 address", 0, 1);
    auto* location = addMetric("Geographic location", 1, 0);
    auto* status = addMetric("VPN status", 1, 1);
    root->addWidget(dashboard);
    root->addStretch();

    auto* client = new QProcess(&window);
    client->setProgram(QCoreApplication::applicationDirPath() + "/vpn_client");
    // client->setWorkingDirectory(QCoreApplication::applicationDirPath());
    auto* geoLookup = new QProcess(&window);
    location->setText("Geographic location\nLooking up...");
    geoLookup->start("curl", {"--silent", "--max-time", "5", "https://ipapi.co/json/"});
    QObject::connect(geoLookup, &QProcess::finished, &window,
                     [=](int, QProcess::ExitStatus) {
        const QJsonObject data = QJsonDocument::fromJson(geoLookup->readAllStandardOutput())
                                     .object();
        const QString city = data.value("city").toString();
        const QString country = data.value("country_name").toString();
        const QString place = city.isEmpty() || country.isEmpty()
            ? QStringLiteral("Unavailable")
            : city + ", " + country;
        location->setText("Geographic location\n" + place);
    });
    auto refreshMetrics = new QTimer(&window);
    quint64 previousBytes = interfaceBytes();
    refreshMetrics->setInterval(1000);
    QObject::connect(refreshMetrics, &QTimer::timeout, &window, [=, &previousBytes]() mutable {
        const quint64 currentBytes = interfaceBytes();
        const double megabits = (currentBytes - previousBytes) * 8.0 / 1000000.0;
        previousBytes = currentBytes;
        speed->setText(QStringLiteral("Internet speed\n%1 Mbps").arg(megabits, 0, 'f', 2));
        ipv4->setText("IPv4 address\n" + localIpv4Address());
    });
    refreshMetrics->start();

    QObject::connect(runButton, &QPushButton::clicked, &window, [=, &selectedServerIp]() {
        if (client->state() != QProcess::NotRunning)
            return;
        client->start(client->program(), {selectedServerIp});
        status->setText("VPN status\nConnecting...");
        runButton->setEnabled(false);
        server->setEnabled(false);
    });
    QObject::connect(client, &QProcess::started, &window, [=]() {
        status->setText("VPN status\nConnected");
    });
    QObject::connect(client, &QProcess::finished, &window, [=](int, QProcess::ExitStatus) {
        status->setText("VPN status\nDisconnected");
        runButton->setEnabled(true);
        server->setEnabled(true);
    });
    QObject::connect(closeButton, &QPushButton::clicked, &window, [&]() {
        if (client->state() != QProcess::NotRunning)
            client->terminate();
        window.close();
    });

    window.show();

    return app.exec();
}