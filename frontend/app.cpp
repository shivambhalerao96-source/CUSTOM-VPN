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

    void setLoading()
    {
        m_hasLocation = false;
        m_message = QStringLiteral("Finding your location...");
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
    QObject::connect(client, &QProcess::readyReadStandardOutput, &window, [=]() {
        // Drain client output so a verbose VPN process cannot block on a full
        // pipe now that the debug output panel is intentionally not shown.
        client->readAllStandardOutput();
    });

    locationMap->setLoading();
    auto* geoLookup = new QNetworkAccessManager(&window);
    QNetworkRequest geoRequest(QUrl(QStringLiteral("https://ipapi.co/json/")));
    geoRequest.setHeader(QNetworkRequest::UserAgentHeader,
                         QStringLiteral("CustomVPN/1.0"));
    QNetworkReply* geoReply = geoLookup->get(geoRequest);
    QObject::connect(geoReply, &QNetworkReply::finished, &window, [=]() {
        if (geoReply->error() != QNetworkReply::NoError)
        {
            locationMap->setUnavailable();
            geoReply->deleteLater();
            return;
        }

        const QJsonDocument document = QJsonDocument::fromJson(geoReply->readAll());
        const QJsonObject data = document.object();
        const QJsonValue latitudeValue = data.value(QStringLiteral("latitude"));
        const QJsonValue longitudeValue = data.value(QStringLiteral("longitude"));
        if (!latitudeValue.isDouble() || !longitudeValue.isDouble())
        {
            locationMap->setUnavailable();
            geoReply->deleteLater();
            return;
        }

        const QString city = data.value(QStringLiteral("city")).toString();
        const QString country = data.value(QStringLiteral("country_name")).toString();
        const QString place = city.isEmpty() || country.isEmpty()
            ? country
            : city + QStringLiteral(", ") + country;
        locationMap->setLocation(latitudeValue.toDouble(), longitudeValue.toDouble(), place);
        geoReply->deleteLater();
    });
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
