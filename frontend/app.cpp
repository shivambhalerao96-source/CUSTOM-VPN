#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QGridLayout>
#include <QGraphicsDropShadowEffect>
#include <QGraphicsOpacityEffect>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QPropertyAnimation>
#include <QProcess>
#include <QPlainTextEdit>
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
QString resolveClientBinaryPath()
{
    const QString appDir = QCoreApplication::applicationDirPath();
    const QString currentDir = QDir::currentPath();
    const QStringList candidates = {
        QDir(appDir).absoluteFilePath("vpn_client"),
        QDir(currentDir).absoluteFilePath("vpn_client"),
        QDir(currentDir).filePath("../vpn_client"),
        QDir(appDir).filePath("../vpn_client"),
        QDir::cleanPath(appDir + "/../vpn_client")
    };

    for (const QString& candidate : candidates)
    {
        if (!candidate.isEmpty() && QFileInfo(candidate).exists())
            return candidate;
    }

    return QString();
}

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
    window.resize(820, 680);
    window.setStyleSheet(R"(
        QWidget { background: #050505; color: #f5eeee; font-family: "DejaVu Sans"; }
        QLabel#eyebrow { color: #e05252; font-size: 11px; font-weight: 700; letter-spacing: 2px; }
        QLabel#title { font-size: 32px; font-weight: 700; color: #ffffff; }
        QLabel#subtitle { color: #aa9292; font-size: 13px; }
        QGroupBox { background: #120909; border: 1px solid #442020; border-radius: 14px; margin-top: 14px; padding: 18px; }
        QGroupBox::title { subcontrol-origin: margin; left: 16px; padding: 0 7px; color: #c7a4a4; font-size: 12px; font-weight: 700; }
        QLabel[class="metric"] { background: #180b0b; border: 1px solid #4a2424; border-radius: 12px; padding: 16px; color: #c7a4a4; font-size: 12px; }
        QLabel[class="metric"]:hover { background: #2a1010; border-color: #d94b4b; color: #f5eeee; }
        QComboBox { background: #180b0b; border: 1px solid #633030; border-radius: 10px; padding: 11px 14px; min-height: 20px; color: #f5eeee; }
        QComboBox:hover { border-color: #d94b4b; }
        QComboBox:focus { border: 2px solid #e05252; padding: 10px 13px; }
        QComboBox::drop-down { border: 0; width: 28px; }
        QComboBox QAbstractItemView { background: #180b0b; border: 1px solid #633030; selection-background-color: #642424; padding: 5px; }
        QPushButton { border: 0; border-radius: 10px; padding: 11px 20px; min-width: 105px; font-weight: 700; }
        QPushButton#run { background: #c93434; color: #ffffff; }
        QPushButton#run:hover { background: #e05252; padding: 12px 21px; }
        QPushButton#run:focus { border: 2px solid #f5eeee; }
        QPushButton#run:pressed { background: #982525; padding-top: 13px; padding-bottom: 9px; }
        QPushButton#close { background: #442020; color: #f5eeee; }
        QPushButton#close:hover { background: #6b2b2b; padding: 12px 21px; }
        QPushButton#close:focus { border: 2px solid #e05252; }
        QPushButton#close:pressed { background: #2b1414; padding-top: 13px; padding-bottom: 9px; }
    )");

    auto* root = new QVBoxLayout(&window);
    root->setContentsMargins(28, 24, 28, 28);
    root->setSpacing(8);
    auto* eyebrow = new QLabel("PRIVATE NETWORK / CONTROL CENTER");
    eyebrow->setObjectName("eyebrow");
    root->addWidget(eyebrow);
    auto* title = new QLabel("Custom VPN");
    title->setObjectName("title");
    root->addWidget(title);
    auto* subtitle = new QLabel("Secure tunnel control and connection telemetry");
    subtitle->setObjectName("subtitle");
    root->addWidget(subtitle);

    auto* controls = new QGroupBox("Connection");
    auto* controlsLayout = new QHBoxLayout(controls);
    auto* server = new QComboBox;
    server->addItem("USA VPN  •  35.226.148.101", "35.226.148.101");
    server->addItem("Europe VPN  •  34.105.188.210", "34.105.188.210");
    server->addItem("Asia VPN  •  34.84.46.243", "34.84.46.243");
    QString selectedServerIp = server->currentData().toString();
    QObject::connect(server, &QComboBox::currentIndexChanged, &window,
                     [&selectedServerIp, server](int index) {
        selectedServerIp = server->itemData(index).toString();
    });
    controlsLayout->addWidget(server, 1);
    auto* runButton = new QPushButton("Run VPN");
    runButton->setObjectName("run");
    auto* closeButton = new QPushButton("Disconnect");
    closeButton->setObjectName("close");
    runButton->setToolTip("Start the VPN connection");
    closeButton->setToolTip("Disconnect from the VPN server");
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
    // // debugging output for kernel messages and client logs

    // auto* outputGroup = new QGroupBox("Kernel output");
    // auto* outputLayout = new QVBoxLayout(outputGroup);
    // auto* output = new QPlainTextEdit;
    // output->setReadOnly(true);
    // output->setPlaceholderText("VPN client output will appear here...");
    // output->setMinimumHeight(150);
    // output->setStyleSheet(
    //     "QPlainTextEdit { background: #080606; border: 1px solid #442020; "
    //     "border-radius: 8px; padding: 8px; color: #e8caca; "
    //     "font-family: monospace; font-size: 12px; }");
    // outputLayout->addWidget(output);
    // root->addWidget(outputGroup);
    // // end debugging output
    root->addStretch();

    auto addShadow = [](QWidget* widget, const QColor& color, int blurRadius) {
        auto* shadow = new QGraphicsDropShadowEffect(widget);
        shadow->setBlurRadius(blurRadius);
        shadow->setOffset(0, 8);
        shadow->setColor(color);
        widget->setGraphicsEffect(shadow);
    };
    addShadow(controls, QColor(0, 0, 0, 70), 22);
    addShadow(runButton, QColor(98, 214, 181, 65), 18);

    auto* dashboardOpacity = new QGraphicsOpacityEffect(dashboard);
    dashboardOpacity->setOpacity(0.0);
    dashboard->setGraphicsEffect(dashboardOpacity);
    auto* dashboardIntro = new QPropertyAnimation(dashboardOpacity, "opacity", &window);
    dashboardIntro->setDuration(650);
    dashboardIntro->setStartValue(0.0);
    dashboardIntro->setEndValue(1.0);
    dashboardIntro->setEasingCurve(QEasingCurve::OutCubic);
    dashboardIntro->start(QAbstractAnimation::DeleteWhenStopped);

    auto* refreshMetrics = new QTimer(&window);
    QObject::connect(refreshMetrics, &QTimer::timeout, &window, [=]() {
        const auto bytes = interfaceBytes();
        speed->setText(QStringLiteral("Internet speed\n%1 KiB/s").arg(bytes / 1024));
        ipv4->setText(QStringLiteral("IPv4 address\n%1").arg(localIpv4Address()));
    });

    auto* client = new QProcess(&window);
    const QString clientBinary = resolveClientBinaryPath();
    if (clientBinary.isEmpty())
    {
        status->setText("VPN status\nBinary missing");
        runButton->setEnabled(false);
        closeButton->setEnabled(false);
    }
    else
    {
        client->setProgram(clientBinary);
    }
    // client->setProcessChannelMode(QProcess::MergedChannels);
    // QObject::connect(client, &QProcess::readyReadStandardOutput, &window, [=]() {
    //     output->appendPlainText(QString::fromLocal8Bit(client->readAllStandardOutput()));
    // });
    // auto* geoLookup = new QProcess(&window);
    // location->setText("Geographic location\nLooking up...");
    // geoLookup->start("curl", {"--silent", "--max-time", "5", "https://ipapi.co/json/"});
    // QObject::connect(geoLookup, &QProcess::finished, &window,
    //                  [=](int, QProcess::ExitStatus) {
    //     const QJsonObject data = QJsonDocument::fromJson(geoLookup->readAllStandardOutput())
    //                                  .object();
    //     const QString city = data.value("city").toString();
    //     const QString country = data.value("country_name").toString();
    //     const QString place = city.isEmpty() || country.isEmpty()
    //         ? QStringLiteral("Unavailable")
    //         : city + ", " + country;
    //     location->setText("Not implemented yet");
    // });
    location->setText("Location Not implemented yet");
    speed->setText(QStringLiteral("Internet speed\n--"));
    ipv4->setText(QStringLiteral("IPv4 address\n%1").arg(localIpv4Address()));
    //refreshMetrics->start(1000);

    QObject::connect(runButton, &QPushButton::clicked, &window, [=, &selectedServerIp]() {
        if (client->state() != QProcess::NotRunning)
            return;
        client->start(client->program(), {selectedServerIp});
        status->setText("VPN status\nConnecting...");
        server->setEnabled(false);
    });
    QObject::connect(client, &QProcess::started, &window, [=]() {
        status->setText("VPN status\nConnected");
    });
    QObject::connect(client, &QProcess::finished, &window, [=](int, QProcess::ExitStatus) {
        status->setText("VPN status\nDisconnected");
        server->setEnabled(true);
    });
    QObject::connect(closeButton, &QPushButton::clicked, &window, [&]() {
        if (client->state() != QProcess::NotRunning)
        {
            status->setText("VPN status\nDisconnecting...");
            client->write("disconnect\n");
            client->closeWriteChannel();
        }
    });

    window.show();

    return app.exec();
}