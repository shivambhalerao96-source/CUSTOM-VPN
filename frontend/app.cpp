#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QGridLayout>
#include <QGraphicsDropShadowEffect>
#include <QGraphicsOpacityEffect>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QNetworkAccessManager>
#include <QNetworkDiskCache>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPainter>
#include <QPropertyAnimation>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <cstdio>
#include <cmath>
#include <fstream>
#include <functional>
#include <sstream>
#include <vector>

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

using LocationCallback = std::function<void(double, double, const QString&)>;
using LocationFailureCallback = std::function<void()>;

void requestIpLocation(QNetworkAccessManager* network,
                       QObject* context,
                       const QString& ip,
                       LocationCallback onSuccess,
                       LocationFailureCallback onFailure)
{
    const QString endpoint = ip.isEmpty()
        ? QStringLiteral("https://ipapi.co/json/")
        : QStringLiteral("https://ipapi.co/%1/json/").arg(ip);
    QNetworkRequest request{QUrl(endpoint)};
    request.setHeader(QNetworkRequest::UserAgentHeader,
                      QStringLiteral("CustomVPN/1.0"));
    QNetworkReply* reply = network->get(request);
    QObject::connect(reply, &QNetworkReply::finished, context, [reply,
                                                                 onSuccess,
                                                                 onFailure]() {
        if (reply->error() != QNetworkReply::NoError)
        {
            onFailure();
            reply->deleteLater();
            return;
        }

        const QJsonDocument document = QJsonDocument::fromJson(reply->readAll());
        const QJsonObject data = document.object();
        const QJsonValue latitude = data.value(QStringLiteral("latitude"));
        const QJsonValue longitude = data.value(QStringLiteral("longitude"));
        if (!latitude.isDouble() || !longitude.isDouble())
        {
            onFailure();
            reply->deleteLater();
            return;
        }

        const QString city = data.value(QStringLiteral("city")).toString();
        const QString country = data.value(QStringLiteral("country_name")).toString();
        const QString place = city.isEmpty() || country.isEmpty()
            ? (city.isEmpty() ? country : city)
            : city + QStringLiteral(", ") + country;
        onSuccess(latitude.toDouble(), longitude.toDouble(), place);
        reply->deleteLater();
    });
}

QIcon statusDotIcon(const QColor& color)
{
    QPixmap pixmap(14, 14);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(QPen(QColor(QStringLiteral("#f5eeee")), 1));
    painter.setBrush(color);
    painter.drawEllipse(QRectF(2, 2, 10, 10));
    return QIcon(pixmap);
}

class LocationMapWidget final : public QWidget
{
public:
    explicit LocationMapWidget(QWidget* parent = nullptr)
        : QWidget(parent), m_tileNetwork(this)
    {
        setMinimumSize(300, 210);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

        auto* cache = new QNetworkDiskCache(this);
        const QString cachePath = QStandardPaths::writableLocation(
            QStandardPaths::CacheLocation) + QStringLiteral("/custom-vpn-map");
        QDir().mkpath(cachePath);
        cache->setCacheDirectory(cachePath);
        cache->setMaximumCacheSize(64 * 1024 * 1024);
        m_tileNetwork.setCache(cache);
    }

    void setLoading(const QString& message = QStringLiteral("Finding your location..."))
    {
        m_hasLocation = false;
        m_message = message;
        update();
    }

    void setUnavailable(const QString& reason = QStringLiteral("Location unavailable"))
    {
        m_hasLocation = false;
        m_message = reason;
        update();
    }

    void setLocation(double latitude, double longitude, const QString& place)
    {
        if (!std::isfinite(latitude) || !std::isfinite(longitude) ||
            latitude < -85.0511 || latitude > 85.0511 ||
            longitude < -180.0 || longitude > 180.0)
        {
            setUnavailable();
            return;
        }

        constexpr double pi = 3.14159265358979323846;
        const double scale = static_cast<double>(1 << m_zoom);
        m_centerWorldX = (longitude + 180.0) / 360.0 * scale * kTileSize;
        const double latitudeRadians = latitude * pi / 180.0;
        m_centerWorldY = (1.0 - std::asinh(std::tan(latitudeRadians)) / pi) /
                         2.0 * scale * kTileSize;
        m_place = place.isEmpty() ? QStringLiteral("Unknown location") : place;
        m_hasLocation = true;
        m_message.clear();
        requestTiles();
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter painter(this);
        painter.setRenderHint(QPainter::SmoothPixmapTransform);
        painter.fillRect(rect(), QColor(QStringLiteral("#e7e1d5")));

        if (!m_hasLocation)
        {
            painter.setPen(QColor(QStringLiteral("#c7a4a4")));
            painter.drawText(rect(), Qt::AlignCenter, m_message);
            return;
        }

        const double left = m_centerWorldX - width() / 2.0;
        const double top = m_centerWorldY - height() / 2.0;
        for (int tileX = m_firstTileX; tileX <= m_firstTileX + 2; ++tileX)
        {
            for (int tileY = m_firstTileY; tileY <= m_firstTileY + 2; ++tileY)
            {
                const auto tile = m_tiles.constFind(tileKey(tileX, tileY));
                if (tile == m_tiles.constEnd())
                    continue;

                const QRectF target(tileX * kTileSize - left,
                                    tileY * kTileSize - top,
                                    kTileSize,
                                    kTileSize);
                painter.drawImage(target, tile.value());
            }
        }

        // A small marker at the center keeps the map useful even when the
        // provider's raster tile has no marker layer of its own.
        const QPointF marker(width() / 2.0, height() / 2.0);
        painter.setPen(QPen(Qt::white, 2));
        painter.setBrush(QColor(QStringLiteral("#d23838")));
        painter.drawEllipse(marker, 7, 7);

        painter.setPen(Qt::white);
        painter.setBrush(QColor(0, 0, 0, 165));
        const QRectF placeBackground(8, 8, qMin(width() - 16, 260), 28);
        painter.drawRoundedRect(placeBackground, 6, 6);
        painter.drawText(placeBackground.adjusted(10, 0, -10, 0),
                         Qt::AlignVCenter | Qt::AlignLeft, m_place);

        painter.setPen(QColor(QStringLiteral("#252525")));
        painter.setBrush(QColor(255, 255, 255, 220));
        const QRectF attribution(width() - 190, height() - 24, 182, 18);
        painter.drawRect(attribution);
        painter.drawText(attribution, Qt::AlignCenter,
                         QStringLiteral("© OpenStreetMap contributors"));
    }

private:
    static constexpr int kTileSize = 256;
    static constexpr int m_zoom = 5;

    static QString tileKey(int x, int y)
    {
        return QString::number(x) + QLatin1Char(':') + QString::number(y);
    }

    void requestTiles()
    {
        const int tileCount = 1 << m_zoom;
        m_firstTileX = static_cast<int>(std::floor(m_centerWorldX / kTileSize)) - 1;
        m_firstTileY = static_cast<int>(std::floor(m_centerWorldY / kTileSize)) - 1;
        m_tiles.clear();

        for (int tileX = m_firstTileX; tileX <= m_firstTileX + 2; ++tileX)
        {
            for (int tileY = m_firstTileY; tileY <= m_firstTileY + 2; ++tileY)
            {
                if (tileY < 0 || tileY >= tileCount)
                    continue;

                const int wrappedX = ((tileX % tileCount) + tileCount) % tileCount;
                const QUrl url(QStringLiteral("https://tile.openstreetmap.org/%1/%2/%3.png")
                                   .arg(m_zoom)
                                   .arg(wrappedX)
                                   .arg(tileY));
                QNetworkRequest request(url);
                request.setHeader(QNetworkRequest::UserAgentHeader,
                                  QStringLiteral("CustomVPN/1.0"));
                QNetworkReply* reply = m_tileNetwork.get(request);
                const QString key = tileKey(tileX, tileY);
                QObject::connect(reply, &QNetworkReply::finished, this,
                                 [this, reply, key]() {
                    if (reply->error() == QNetworkReply::NoError)
                    {
                        const QImage image = QImage::fromData(reply->readAll());
                        if (!image.isNull())
                            m_tiles.insert(key, image);
                    }
                    reply->deleteLater();
                    update();
                });
            }
        }
    }

    QNetworkAccessManager m_tileNetwork;
    QHash<QString, QImage> m_tiles;
    double m_centerWorldX = 0.0;
    double m_centerWorldY = 0.0;
    int m_firstTileX = 0;
    int m_firstTileY = 0;
    QString m_place;
    QString m_message = QStringLiteral("Finding your location...");
    bool m_hasLocation = false;
};

struct ServerState
{
    QString name;
    QString ip;
    int latencyMs = -1;
    bool probeFinished = false;
    int activeClients = -1;
    int clientCapacity = -1;
    bool recommended = false;
};

}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QWidget window;

    window.setWindowTitle("Custom VPN");
    window.resize(820, 760);
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
        QPushButton#tor { background: #3d2244; color: #f5eeee; border: 1px solid #663377; }
        QPushButton#tor:hover { background: #552f60; border-color: #8844aa; }
        QPushButton#tor:pressed { background: #281430; }
        QPushButton#tor:disabled { background: #1a121d; color: #665566; border-color: #332233; }
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
    std::vector<ServerState> serverStates = {
        {QStringLiteral("USA VPN"), QStringLiteral("35.226.148.101")},
        {QStringLiteral("Europe VPN"), QStringLiteral("34.105.188.210")},
        {QStringLiteral("Asia VPN"), QStringLiteral("34.84.46.243")}
    };
    for (const ServerState& state : serverStates)
        server->addItem(statusDotIcon(QColor(QStringLiteral("#8c8585"))),
                        state.name + QStringLiteral("  •  ") + state.ip,
                        state.ip);

    auto refreshServerItems = [&]() {
        int recommendedIndex = -1;
        for (int index = 0; index < static_cast<int>(serverStates.size()); ++index)
        {
            if (serverStates[index].latencyMs < 0)
                continue;
            if (recommendedIndex < 0 ||
                serverStates[index].latencyMs < serverStates[recommendedIndex].latencyMs)
                recommendedIndex = index;
        }

        for (int index = 0; index < static_cast<int>(serverStates.size()); ++index)
        {
            ServerState& state = serverStates[index];
            state.recommended = index == recommendedIndex;

            QColor dotColor(QStringLiteral("#8c8585"));
            QString connectivity = QStringLiteral("Checking connectivity...");
            if (state.probeFinished && state.latencyMs < 0)
            {
                dotColor = QColor(QStringLiteral("#d23838"));
                connectivity = QStringLiteral("Unavailable");
            }
            else if (state.latencyMs >= 0 && state.latencyMs < 80)
            {
                dotColor = QColor(QStringLiteral("#45c46b"));
                connectivity = QStringLiteral("Excellent · %1 ms").arg(state.latencyMs);
            }
            else if (state.latencyMs >= 0 && state.latencyMs < 180)
            {
                dotColor = QColor(QStringLiteral("#e4b33f"));
                connectivity = QStringLiteral("Fair · %1 ms").arg(state.latencyMs);
            }
            else if (state.latencyMs >= 0)
            {
                dotColor = QColor(QStringLiteral("#d23838"));
                connectivity = QStringLiteral("Slow · %1 ms").arg(state.latencyMs);
            }

            QString load = QStringLiteral("Load: unavailable");
            if (state.activeClients >= 0 && state.clientCapacity > 0)
            {
                const int loadPercent = qBound(
                    0, state.activeClients * 100 / state.clientCapacity, 100);
                load = QStringLiteral("Load: %1/%2 active (%3%)")
                           .arg(state.activeClients)
                           .arg(state.clientCapacity)
                           .arg(loadPercent);
            }

            QString label = state.name + QStringLiteral("  •  ") + state.ip;
            if (state.recommended)
                label += QStringLiteral("  |  Recommended");
            label += QStringLiteral("  |  ") + connectivity +
                     QStringLiteral("  |  ") + load;
            server->setItemIcon(index, statusDotIcon(dotColor));
            server->setItemText(index, label);
        }
    };
    refreshServerItems();
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

    auto* torGroup = new QGroupBox("TOR MODE");
    auto* torLayout = new QVBoxLayout(torGroup);
    torLayout->setSpacing(8);

    auto* torHeaderLayout = new QHBoxLayout();
    auto* torStatusLabel = new QLabel("Status: Disabled");
    torStatusLabel->setObjectName("torStatus");
    torStatusLabel->setStyleSheet("color: #aa9292; font-size: 13px; font-weight: 700;");

    auto* torButton = new QPushButton("Enable Tor");
    torButton->setObjectName("tor");
    torButton->setToolTip("Toggle Tor Mode through the encrypted VPN tunnel");
    torButton->setEnabled(false);

    torHeaderLayout->addWidget(torStatusLabel, 1);
    torHeaderLayout->addWidget(torButton);
    torLayout->addLayout(torHeaderLayout);

    auto* torNotice = new QLabel("Tor Mode routes supported traffic through the Tor network.");
    torNotice->setStyleSheet("color: #8c8585; font-size: 11px;");
    torLayout->addWidget(torNotice);

    auto* torHint = new QLabel("Use Tor Browser to access Onion Services.");
    torHint->setStyleSheet("color: #c7a4a4; font-size: 11px; font-style: italic;");
    torLayout->addWidget(torHint);

    root->addWidget(torGroup);

    // A single ICMP probe gives the user a real, lightweight connectivity
    // signal before choosing a server. It is not presented as server load;
    // load is shown only when the VPN server reports active sessions.
    for (int index = 0; index < static_cast<int>(serverStates.size()); ++index)
    {
        auto* probe = new QProcess(&window);
        probe->setProperty("serverIndex", index);
        QObject::connect(probe, &QProcess::finished, &window,
                         [&, probe](int, QProcess::ExitStatus) {
            const int serverIndex = probe->property("serverIndex").toInt();
            const QString probeOutput = QString::fromLocal8Bit(
                probe->readAllStandardOutput() + probe->readAllStandardError());
            const QRegularExpression timePattern(
                QStringLiteral("time[=<]([0-9]+(?:\\.[0-9]+)?)\\s*ms"));
            const QRegularExpressionMatch match = timePattern.match(probeOutput);

            serverStates[serverIndex].probeFinished = true;
            serverStates[serverIndex].latencyMs = match.hasMatch()
                ? qRound(match.captured(1).toDouble())
                : -1;
            refreshServerItems();
            probe->deleteLater();
        });
        probe->start(QStringLiteral("ping"), {
            QStringLiteral("-c"), QStringLiteral("1"),
            QStringLiteral("-W"), QStringLiteral("1"),
            serverStates[index].ip
        });
    }

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
    auto* locationMap = new LocationMapWidget;
    locationMap->setObjectName("locationMap");
    metrics->addWidget(locationMap, 1, 0);
    auto* status = addMetric("VPN status", 1, 1);
    metrics->setColumnStretch(0, 1);
    metrics->setColumnStretch(1, 1);
    metrics->setRowStretch(1, 1);
    root->addWidget(dashboard);
    root->addStretch();

    auto addShadow = [](QWidget* widget, const QColor& color, int blurRadius) {
        auto* shadow = new QGraphicsDropShadowEffect(widget);
        shadow->setBlurRadius(blurRadius);
        shadow->setOffset(0, 8);
        shadow->setColor(color);
        widget->setGraphicsEffect(shadow);
    };
    addShadow(controls, QColor(0, 0, 0, 70), 22);
    addShadow(torGroup, QColor(0, 0, 0, 70), 22);
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
    quint64 previousBytes = interfaceBytes();
    QElapsedTimer speedClock;
    speedClock.start();
    QObject::connect(refreshMetrics, &QTimer::timeout, &window, [=, &previousBytes, &speedClock]() {
        const quint64 bytes = interfaceBytes();
        const qint64 elapsedMs = speedClock.elapsed();
        const quint64 delta = bytes >= previousBytes ? bytes - previousBytes : 0;
        const double speedKiB = elapsedMs > 0
            ? static_cast<double>(delta) * 1000.0 / elapsedMs / 1024.0
            : 0.0;
        previousBytes = bytes;
        speedClock.restart();
        speed->setText(QStringLiteral("Internet speed\n%1 KiB/s")
                           .arg(speedKiB, 0, 'f', 1));
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
    client->setProcessChannelMode(QProcess::MergedChannels);
    bool vpnConnected = false;
    bool torModeEnabled = false;
    bool userLocationReady = false;
    double userLatitude = 0.0;
    double userLongitude = 0.0;
    QString userPlace;
    QString clientOutputBuffer;

    auto updateTorUiState = [&](const QString& torState, const QString& torDetail) {
        if (torState == QStringLiteral("TOR_CONNECTED"))
        {
            torModeEnabled = true;
            torStatusLabel->setText("Status: Connected ✓");
            torStatusLabel->setStyleSheet("color: #45c46b; font-size: 13px; font-weight: 700;");
            torStatusLabel->setToolTip("");
            torButton->setText("Disable Tor");
            torButton->setEnabled(true);
        }
        else if (torState == QStringLiteral("TOR_CONNECTING") || torState == QStringLiteral("TOR_STARTING"))
        {
            torModeEnabled = true;
            torStatusLabel->setText("Status: Connecting...");
            torStatusLabel->setStyleSheet("color: #e4b33f; font-size: 13px; font-weight: 700;");
            torStatusLabel->setToolTip("");
            torButton->setText("Disable Tor");
            torButton->setEnabled(true);
        }
        else if (torState == QStringLiteral("TOR_DISABLED"))
        {
            torModeEnabled = false;
            torStatusLabel->setText("Status: Disabled");
            torStatusLabel->setStyleSheet("color: #aa9292; font-size: 13px; font-weight: 700;");
            torStatusLabel->setToolTip("");
            torButton->setText("Enable Tor");
            torButton->setEnabled(vpnConnected);
        }
        else if (torState == QStringLiteral("TOR_ERROR"))
        {
            torModeEnabled = false;
            torStatusLabel->setText("Status: Error ✗");
            torStatusLabel->setStyleSheet("color: #d23838; font-size: 13px; font-weight: 700;");
            if (!torDetail.isEmpty())
                torStatusLabel->setToolTip(torDetail);
            torButton->setText("Enable Tor");
            torButton->setEnabled(vpnConnected);
        }
    };

    auto* geoLookup = new QNetworkAccessManager(&window);
    requestIpLocation(
        geoLookup,
        &window,
        QString(),
        [&](double latitude, double longitude, const QString& place) {
            userLatitude = latitude;
            userLongitude = longitude;
            userPlace = place;
            userLocationReady = true;
            if (!vpnConnected)
                locationMap->setLocation(latitude, longitude, place);
        },
        [&]() {
            if (!vpnConnected)
                locationMap->setUnavailable();
        });

    QObject::connect(client, &QProcess::readyReadStandardOutput, &window, [&]() {
        // Drain client output so a verbose VPN process cannot block on a full
        // pipe now that the debug output panel is intentionally not shown.
        clientOutputBuffer += QString::fromLocal8Bit(client->readAllStandardOutput());

        const QRegularExpression loadPattern(
            QStringLiteral("VPN_LOAD\\s+(\\d+)\\s+(\\d+)"));
        const QRegularExpressionMatch loadMatch = loadPattern.match(clientOutputBuffer);
        if (loadMatch.hasMatch())
        {
            const int serverIndex = server->currentIndex();
            if (serverIndex >= 0 && serverIndex < static_cast<int>(serverStates.size()))
            {
                serverStates[serverIndex].activeClients = loadMatch.captured(1).toInt();
                serverStates[serverIndex].clientCapacity = loadMatch.captured(2).toInt();
                refreshServerItems();
            }
        }

        const QRegularExpression torPattern(
            QStringLiteral("TOR_STATUS\\s+([A-Z_]+)(?:\\s+([^\\r\\n]*))?"));
        const QRegularExpressionMatch torMatch = torPattern.match(clientOutputBuffer);
        if (torMatch.hasMatch())
        {
            updateTorUiState(torMatch.captured(1), torMatch.captured(2));
        }

        if (!vpnConnected && clientOutputBuffer.contains(QStringLiteral("VPN_CONNECTED")))
        {
            vpnConnected = true;
            torButton->setEnabled(true);
            status->setText("VPN status\nConnected");
            locationMap->setLoading(QStringLiteral("Locating VPN server..."));

            const QString connectedServerIp = selectedServerIp;
            requestIpLocation(
                geoLookup,
                &window,
                connectedServerIp,
                [&, connectedServerIp](double latitude, double longitude,
                                       const QString& place) {
                    if (vpnConnected && selectedServerIp == connectedServerIp)
                        locationMap->setLocation(latitude, longitude, place);
                },
                [&, connectedServerIp]() {
                    if (vpnConnected && selectedServerIp == connectedServerIp)
                        locationMap->setUnavailable(QStringLiteral("VPN server location unavailable"));
                });
        }

        if (clientOutputBuffer.size() > 4096)
            clientOutputBuffer.remove(0, clientOutputBuffer.size() - 1024);
    });
    locationMap->setLoading();
    speed->setText(QStringLiteral("Internet speed\n--"));
    ipv4->setText(QStringLiteral("IPv4 address\n%1").arg(localIpv4Address()));
    refreshMetrics->start(1000);

    QObject::connect(runButton, &QPushButton::clicked, &window, [=, &selectedServerIp]() {
        if (client->state() != QProcess::NotRunning)
            return;
        client->start(client->program(), {selectedServerIp});
        status->setText("VPN status\nConnecting...");
        server->setEnabled(false);
    });
    QObject::connect(client, &QProcess::finished, &window, [&](int, QProcess::ExitStatus) {
        vpnConnected = false;
        torModeEnabled = false;
        torStatusLabel->setText("Status: Disabled");
        torStatusLabel->setStyleSheet("color: #aa9292; font-size: 13px; font-weight: 700;");
        torStatusLabel->setToolTip("");
        torButton->setText("Enable Tor");
        torButton->setEnabled(false);
        status->setText("VPN status\nDisconnected");
        server->setEnabled(true);
        if (userLocationReady)
            locationMap->setLocation(userLatitude, userLongitude, userPlace);
        else
            locationMap->setLoading();
    });
    QObject::connect(closeButton, &QPushButton::clicked, &window, [&]() {
        if (client->state() != QProcess::NotRunning)
        {
            status->setText("VPN status\nDisconnecting...");
            client->write("disconnect\n");
            client->closeWriteChannel();
        }
    });
    QObject::connect(torButton, &QPushButton::clicked, &window, [&]() {
        if (!vpnConnected || client->state() == QProcess::NotRunning)
            return;

        if (!torModeEnabled)
        {
            torStatusLabel->setText("Status: Connecting...");
            torStatusLabel->setStyleSheet("color: #e4b33f; font-size: 13px; font-weight: 700;");
            torButton->setEnabled(false);
            client->write("tor on\n");
        }
        else
        {
            torStatusLabel->setText("Status: Disabling...");
            torStatusLabel->setStyleSheet("color: #aa9292; font-size: 13px; font-weight: 700;");
            torButton->setEnabled(false);
            client->write("tor off\n");
        }
    });

    window.show();

    return app.exec();
}
