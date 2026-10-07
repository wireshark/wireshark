/* software_update.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/software_update.h"
#include "ui/qt/utils/software_update_backend.h"

#include "app/application_flavor.h"
#include "epan/prefs.h"

#include "ui/qt/utils/workspace_state.h"

#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QXmlStreamReader>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>

/**
 * AppCast URL override for testing purposes.
 *
 * This can be used to point the update framework to a custom appcast URL,
 * e.g. a local test server, instead of the default one. This is only
 * intended for testing and should not be used in production builds.
 *
 * To use this, the script tools/appcast_server.py can be used to start a
 * local test server that serves a custom appcast.
 *
 * Example call:
 *  > python3 tools/appcast_server.py --title "Wireshark" --version 4.7.1  \
 *      --release-notes "https://www.wireshark.org/docs/relnotes/wireshark-4.6.0.html" \
 *      --port 9999
 */
//#define UPDATE_TEST
#ifdef UPDATE_TEST
    /* Use a local test server for the appcast URL */
    #define APPCAST_URL "http://localhost:9999/appcast.xml"
    /* Override the update check interval to 5 seconds for testing purposes. */
    // #define TIMEOUT_OVERRIDE 5000
#endif /* if */

static const QString SPARKLE_NS = QStringLiteral("http://www.andymatuschak.org/xml-namespaces/sparkle");

void ShutdownEvent::accept() {
    accepted_ = true;
    rejected_ = false;
    reason_.clear();
}

void ShutdownEvent::reject(const QString& reason) {
    rejected_ = true;
    accepted_ = false;
    reason_ = reason;
}

bool ShutdownEvent::isAccepted() const {
    return accepted_ && !rejected_;
}

QString ShutdownEvent::reason() const {
    return reason_;
}

SoftwareUpdate* SoftwareUpdate::instance_{nullptr};
QMutex SoftwareUpdate::mutex_;
QMutex SoftwareUpdate::updateMutex_;

SoftwareUpdate::SoftwareUpdate(QObject *parent)
    : QObject(parent),
    updateCheckTimer_(new QTimer(this)),
    networkAccessManager_(new QNetworkAccessManager(this)),
    backend_(SoftwareUpdateBackend::create())
{
    connect(networkAccessManager_, &QNetworkAccessManager::finished,
            this, &SoftwareUpdate::onNetworkReplyFinished);
    connect(updateCheckTimer_, &QTimer::timeout,
            this, &SoftwareUpdate::checkForUpdates);

}

SoftwareUpdate::~SoftwareUpdate()
{
    instance_ = nullptr;
}

SoftwareUpdate* SoftwareUpdate::instance()
{
    mutex_.lock();
    if (instance_ == nullptr) {
        instance_ = new SoftwareUpdate();
    }
    mutex_.unlock();
    return instance_;
}

void SoftwareUpdate::init(bool runWithoutSilentCheck)
{
    /* Disable automatic updates for PortableApps installations */
    /*
     * XXX Flatpak, Snap and AppImage are not detected here. They are updated
     * by their own tooling (flatpak update, snapd refresh, AppImageUpdate),
     * not through us. On Linux they currently fall through to the PackageKit
     * backend, which finds no package owning the executable and therefore
     * never reports an update. Detecting them explicitly (FLATPAK_ID or
     * /.flatpak-info, SNAP, APPIMAGE environment variables) would allow
     * pointing the user to the right update mechanism instead.
     */
    if (!backend_ || WorkspaceState::isPortableApplication()) {
        return;
    }

    const QUrl appcastUrl = backend_->supportsAppcast() ? updateUrl() : QUrl();
    backend_->init(appcastUrl, runWithoutSilentCheck);

    /** Start the automatic update check if enabled in preferences */
    if (prefs.gui_update_enabled && !runWithoutSilentCheck) {
        startAutoCheck(prefs.gui_update_interval);
    }
}

QString SoftwareUpdate::info()
{
    /* Called while building the feature list, possibly before the application object exists */
    QScopedPointer<SoftwareUpdateBackend> backend(SoftwareUpdateBackend::create());
    return backend ? backend->info() : QString();
}

bool SoftwareUpdate::plattformSupported()
{
    return instance()->backend_ != nullptr;
}

QUrl SoftwareUpdate::updateUrl() const
{
    QUrl updateUrl;

    Q_ASSERT_X(backend_ && backend_->supportsAppcast(), "SoftwareUpdate::updateUrl", "only appcast backends have an update URL");
    if (backend_ && backend_->supportsAppcast()) {
        const auto _prefix = "update";
        const auto _version = 0;
        const auto _locale = "en-US";

        const char *_arch = nullptr;
    #if defined(__x86_64__) || defined(_M_X64)
        _arch = "x86-64";
    #elif defined(__arm64__) || defined(_M_ARM64)
        _arch = "arm64";
    #endif
        Q_ASSERT_X(_arch, "SoftwareUpdate::updateUrl", "appcast updates exist only for x86-64 and arm64");
        if (!_arch) {
            return updateUrl;
        }

        const auto _baseurl = "https://www.wireshark.org/";

        QString _urlPath = QString(_prefix) + "/" +
            QString::number(_version) + "/" +
            QString(application_flavor_name_proper()) + "/" +
            QString(application_version()) + "/" +
            backend_->osName() + "/" +
            QString(_arch) + "/"+ QString(_locale) + "/" +
            ((prefs.gui_update_channel == UPDATE_CHANNEL_DEVELOPMENT) ? "development" : "stable") + ".xml";

        updateUrl = _baseurl + _urlPath;
    }

    #ifdef UPDATE_TEST
        updateUrl = QUrl(APPCAST_URL);
        qDebug() << "Using appcast override URL:" << updateUrl.toString();
        return updateUrl;
    #endif /* if */

    return updateUrl;
}

void SoftwareUpdate::performUIUpdate()
{
    /* Skip update check for PortableApps installations */
    if (WorkspaceState::isPortableApplication()) {
        return;
    }

    SoftwareUpdate *su = instance();
    if (su->backend_) {
        su->backend_->performUIUpdate();
    }
}

void SoftwareUpdate::cleanup()
{
    stopAutoCheck();
    if (backend_) {
        backend_->cleanup();
    }
}

void SoftwareUpdate::startAutoCheck(int intervalSeconds)
{
    /* Skip update check for PortableApps installations */
    if (!backend_ || WorkspaceState::isPortableApplication()) {
        return;
    }
    if (intervalSeconds <= 0) {
        intervalSeconds = prefs.gui_update_interval;
    }
    updateMutex_.lock();
    auto msec = intervalSeconds * 1000;
#if defined(UPDATE_TEST) && defined(TIMEOUT_OVERRIDE)
    qDebug() << "Overriding auto check interval to" << TIMEOUT_OVERRIDE << "milliseconds for testing purposes.";
    msec = TIMEOUT_OVERRIDE;
#endif /* if */
    if (msec != updateCheckTimer_->interval() || !updateCheckTimer_->isActive()) {
        if (updateCheckTimer_->isActive()) {
            updateCheckTimer_->stop();
        }

        updateCheckTimer_->start(msec);
    }
    updateMutex_.unlock();
}

void SoftwareUpdate::stopAutoCheck()
{
    updateMutex_.lock();
    if (updateCheckTimer_->isActive()) {
        updateCheckTimer_->stop();
    }
    updateMutex_.unlock();
}

bool SoftwareUpdate::isAutoCheckEnabled() const
{
    return updateCheckTimer_->isActive();
}

void SoftwareUpdate::checkForUpdates()
{
    /* If the backend handles updates itself (returning true on checkForUpdates)
     * or does not support the appcast, skip the appcast check */
    if (!backend_) {
        return;
    }

    /* Held across both paths so a check never starts while another one is being started */
    QMutexLocker locker(&updateMutex_);
    if (backend_->checkForUpdates() || !backend_->supportsAppcast()) {
        return;
    }

    /* The previous appcast request has not finished yet */
    if (pendingReply_) {
        return;
    }

    QNetworkRequest request(updateUrl());
    QString userAgent = QString("%1 Update Check/%2").arg(application_flavor_name_proper()).arg(application_version());
    request.setHeader(QNetworkRequest::UserAgentHeader, userAgent);

    // Bypass caches to always get the latest appcast
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);

    pendingReply_ = networkAccessManager_->get(request);

#if defined(UPDATE_TEST)
    qDebug() << "Checking for updates at:" << updateUrl().toString();
#endif /* if */
}

QList<AppcastItem> SoftwareUpdate::parseAppcast(const QByteArray &data) const
{
    QList<AppcastItem> items;
    QXmlStreamReader xml(data);
    AppcastItem current;
    bool inItem = false;

    while (!xml.atEnd() && !xml.hasError()) {
        const auto token = xml.readNext();

        if (token == QXmlStreamReader::StartElement) {
            if (xml.name() == QStringLiteral("item")) {
                inItem = true;
                current = AppcastItem();
            } else if (inItem) {
                if (xml.name() == QStringLiteral("title")) {
                    current.title = xml.readElementText();

                } else if (xml.name() == QStringLiteral("version")
                           && xml.namespaceUri() == SPARKLE_NS) {
                    // <sparkle:version>
                    current.version = QVersionNumber::fromString(
                        xml.readElementText());

                } else if (xml.name() == QStringLiteral("shortVersionString")
                           && xml.namespaceUri() == SPARKLE_NS) {
                    current.shortVersion = QVersionNumber::fromString(
                        xml.readElementText());

                } else if (xml.name() == QStringLiteral("releaseNotesLink")
                           && xml.namespaceUri() == SPARKLE_NS) {
                    current.releaseNotesUrl = QUrl(xml.readElementText().trimmed());

                } else if (xml.name() == QStringLiteral("enclosure")) {
                    const auto attrs = xml.attributes();
                    current.downloadUrl = QUrl(attrs.value(QStringLiteral("url")).toString());
                    current.length = attrs.value(QStringLiteral("length")).toLongLong();
                    current.edSignature = attrs.value(SPARKLE_NS,
                        QStringLiteral("edSignature")).toString();

                    // Version can also live on the enclosure
                    if (current.version.isNull()) {
                        current.version = QVersionNumber::fromString(
                            attrs.value(SPARKLE_NS, QStringLiteral("version")).toString());
                    }
                    if (current.shortVersion.isNull()) {
                        current.shortVersion = QVersionNumber::fromString(
                            attrs.value(SPARKLE_NS,
                                QStringLiteral("shortVersionString")).toString());
                    }

                    // OS filter attribute
                    const auto osAttr = attrs.value(SPARKLE_NS,
                        QStringLiteral("os")).toString();
                    if (!osAttr.isEmpty()) {
                        current.os = osAttr;
                    }
                }
            }
        } else if (token == QXmlStreamReader::EndElement) {
            if (xml.name() == QStringLiteral("item") && inItem) {
                inItem = false;
                if (!current.version.isNull()) {
                    items.append(current);
                }
            }
        }
    }

    if (xml.hasError()) {
        qWarning("SoftwareUpdate: XML parse error: %s",
                 qPrintable(xml.errorString()));
    }

    return items;
}

void SoftwareUpdate::onNetworkReplyFinished(QNetworkReply* reply)
{
    reply->deleteLater();
    updateMutex_.lock();
    pendingReply_ = nullptr;
    updateMutex_.unlock();

    if (reply->error() != QNetworkReply::NoError) {
        emit updateCheckFailed(reply->errorString());
        return;
    }

    const QByteArray data = reply->readAll();
    const QList<AppcastItem> items = parseAppcast(data);

    if (items.isEmpty()) {
        return;
    }

    #if QT_VERSION >= QT_VERSION_CHECK(6, 4, 0)
        qsizetype suffix;
    #else
        int suffix;
    #endif

    const QString target_os = backend_->osName();

    QVersionNumber bestVersion = QVersionNumber::fromString("0.0.0");
    QString bestReleaseNotes;
    for (const auto &item : items) {
        // Filter by OS: empty os means "all platforms"
        if (!item.os.isEmpty() && item.os.compare(target_os, Qt::CaseInsensitive) != 0) {
            continue;
        }

        if (item.version > bestVersion) {
            bestVersion = item.version;
            bestReleaseNotes = item.releaseNotesUrl.toString();
        }
    }

#if defined(UPDATE_TEST)
    qDebug() << "Best version found in appcast:" << bestVersion.toString();
#endif /* if */

    QVersionNumber appVersion = QVersionNumber::fromString(QString(application_version()), &suffix);
    if (bestVersion > appVersion) {
        emit updateAvailable(bestVersion.toString(), bestReleaseNotes);
    }
}
