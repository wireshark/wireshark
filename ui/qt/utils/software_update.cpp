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

#include "app/application_flavor.h"
#include "epan/prefs.h"

#include "ui/language.h"
#include "ui/qt/main_application.h"
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

#ifdef HAVE_SOFTWARE_UPDATE
    #if !defined(__x86_64__) && !defined(_M_X64) && !defined(__arm64__) && !defined(_M_ARM64)
        #error Software updates are only be defined for x86-64 or arm64.
    #endif /* if */

    #if !defined(_WIN32) && !defined(__APPLE__)
        #error Software updates are only be defined for Windows or macOS.
    #endif /* if */

    #ifdef _WIN32
        #include <winsparkle.h>
        #define SU_OSNAME "Windows"
    #elif defined(__APPLE__)
        #include <ui/macosx/sparkle_bridge.h>
        #define SU_OSNAME "macOS"
    #endif /* if */

#endif /* HAVE_SOFTWARE_UPDATE */

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
    networkAccessManager_(new QNetworkAccessManager(this))
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
    #ifdef HAVE_SOFTWARE_UPDATE
        /* Disable automatic updates for PortableApps installations */
        if (WorkspaceState::isPortableApplication()) {
            return;
        }

        /** Initialize software updates. */
        QUrl updateUrl = this->updateUrl();

        #ifdef _WIN32
            /*
            * According to the WinSparkle 0.5 documentation these must be called
            * once, before win_sparkle_init. We can't update them dynamically when
            * our preferences change.
            */
            QString regKey = QString("Software\\%1\\WinSparkle Settings").arg(application_flavor_name_proper());

            win_sparkle_set_registry_path(regKey.toUtf8().constData());
            win_sparkle_set_appcast_url(updateUrl.toString().toUtf8().constData());
            if (prefs.gui_update_enabled && runWithoutSilentCheck) {
                win_sparkle_set_automatic_check_for_updates(1);
                win_sparkle_set_update_check_interval(prefs.gui_update_interval);
            } else {
                win_sparkle_set_automatic_check_for_updates(0);
            }
            win_sparkle_set_update_cancelled_callback(&SoftwareUpdate::softwareUpdateEngaged);
            win_sparkle_set_update_postponed_callback(&SoftwareUpdate::softwareUpdateEngaged);
            win_sparkle_set_update_skipped_callback(&SoftwareUpdate::softwareUpdateEngaged);
            win_sparkle_set_update_dismissed_callback(&SoftwareUpdate::softwareUpdateEngaged);
            win_sparkle_set_can_shutdown_callback(&SoftwareUpdate::softwareUpdateCanShutdownCallback);
            win_sparkle_set_shutdown_request_callback(&SoftwareUpdate::shutdownRequestCallback);
            const char* ws_language = get_language_used();
            if ((ws_language != NULL) && (strcmp(ws_language, USE_SYSTEM_LANGUAGE) != 0)) {
                win_sparkle_set_lang(ws_language);
            }
            win_sparkle_init();
        #elif defined(__APPLE__)

            if (runWithoutSilentCheck && prefs.gui_update_enabled) {
                SparkleBridge::updateInit(updateUrl.toString().toUtf8().constData(), prefs.gui_update_enabled, prefs.gui_update_interval);
            } else {
                SparkleBridge::updateInit(updateUrl.toString().toUtf8().constData(), false, 0);
            }

            SparkleBridge::setUpdateCallbacks(
                // engage callback
                []() {
                    emit SoftwareUpdate::instance()->updateEngaged();
                },
                // postpone callback — save documents, then proceed
                [](void (*proceed)(void *ctx), void *ctx) {
                    emit instance_->updateEngaged();

                    ShutdownEvent shutdownEvent;
                    emit instance_->appShutdownRequested(&shutdownEvent);

                    if (shutdownEvent.isAccepted()) {
                        proceed(ctx);
                    }
                },
                // will-relaunch callback — final cleanup
                []() {
                    qInfo() << "Sparkle is about to relaunch the application.";
                }
            );

        #endif /* if */

    /** Start the automatic update check if enabled in preferences */
    if (prefs.gui_update_enabled && !runWithoutSilentCheck) {
        startAutoCheck(prefs.gui_update_interval);
    }
    #else
        Q_UNUSED(runWithoutSilentCheck);
    #endif /** HAVE_SOFTWARE_UPDATE */
}

QString SoftwareUpdate::info()
{
    QString info;

    #ifdef HAVE_SOFTWARE_UPDATE
        #ifdef _WIN32
            info = QString("%1 %2").arg("WinSparkle").arg(WIN_SPARKLE_VERSION_STRING);
        #elif defined(__APPLE__)
            info = "Sparkle";
        #endif
    #endif /* HAVE_SOFTWARE_UPDATE */

    return info;
}

bool SoftwareUpdate::plattformSupported()
{
    #if defined(HAVE_SOFTWARE_UPDATE) and (defined(_WIN32) || defined(__APPLE__))
        return true;
    #else
        return false;
    #endif /* if */
}

QUrl SoftwareUpdate::updateUrl() const
{
    QUrl updateUrl;

    #ifdef HAVE_SOFTWARE_UPDATE
        const auto _prefix = "update";
        const auto _version = 0;
        const auto _locale = "en-US";

    #if defined(__x86_64__) || defined(_M_X64)
        const auto _arch = "x86-64";
    #elif defined(__arm64__) || defined(_M_ARM64)
        const auto _arch = "arm64";
    #endif

        const auto _baseurl = "https://www.wireshark.org/";

        QString _urlPath = QString(_prefix) + "/" +
            QString::number(_version) + "/" +
            QString(application_flavor_name_proper()) + "/" +
            QString(application_version()) + "/" +
            QString(SU_OSNAME) + "/" +
            QString(_arch) + "/"+ QString(_locale) + "/" +
            ((prefs.gui_update_channel == UPDATE_CHANNEL_DEVELOPMENT) ? "development" : "stable") + ".xml";

        updateUrl = _baseurl + _urlPath;
    #endif /* HAVE_SOFTWARE_UPDATE */

    #ifdef UPDATE_TEST
        updateUrl = QUrl(APPCAST_URL);
        qDebug() << "Using appcast override URL:" << updateUrl.toString();
        return updateUrl;
    #endif /* if */

    return updateUrl;
}

void SoftwareUpdate::performUIUpdate()
{
    #ifdef HAVE_SOFTWARE_UPDATE
        /* Skip update check for PortableApps installations */
        if (WorkspaceState::isPortableApplication()) {
            return;
        }

        #ifdef _WIN32
            win_sparkle_check_update_with_ui();
        #elif defined(__APPLE__)
            SparkleBridge::updateCheck();
        #endif /* if */
    #endif /* HAVE_SOFTWARE_UPDATE */
}

void SoftwareUpdate::cleanup()
{
    stopAutoCheck();
    #if defined(HAVE_SOFTWARE_UPDATE) && defined(_WIN32)
        win_sparkle_cleanup();
    #endif /* if */
}

void SoftwareUpdate::startAutoCheck(int intervalSeconds)
{
#ifdef HAVE_SOFTWARE_UPDATE
    /* Skip update check for PortableApps installations */
    if (WorkspaceState::isPortableApplication()) {
        return;
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
#else
    Q_UNUSED(intervalSeconds);
#endif /* HAVE_SOFTWARE_UPDATE */
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

#if defined(_WIN32)
/** Check to see if Wireshark can shut down safely (e.g. offer to save the
 *  current capture). These callbacks are used by the software update system
 *  to determine if it can shut down the app to install updates.
 *
 *  Note on Windows:
 *  At this point the update is ready to install, but WinSparkle has
 *  not yet run the installer. We need to close our "Wireshark is
 *  running" mutexes since the IsWiresharkRunning NSIS macro checks
 *  for them.
 *  We must not exit the Qt main event loop here, which means we must
 *  not close the main window.
 */
int SoftwareUpdate::softwareUpdateCanShutdownCallback() {
    if (instance_) {
        emit instance_->updateEngaged();

        ShutdownEvent shutdownEvent;
        emit instance_->appShutdownRequested(&shutdownEvent);

        if (shutdownEvent.isAccepted()) {
            return true;
        }
    }
    return false;
}

/**
 * Note on Windows:
 * At this point the installer has been launched. Neither Wireshark nor
 * its children should have any "Wireshark is running" mutexes open.
 * The main window should still be open as noted above in and it's safe
 * to exit the Qt main event loop.
 */
void __cdecl SoftwareUpdate::shutdownRequestCallback() {
     if (instance_) {
             mainApp->quit();
     }
}

void SoftwareUpdate::softwareUpdateEngaged() {
    if (instance_) {

        /* Restarting auto check after update */
        /* This can be called from a different thread; QTimer can only be
         * stopped and started from the owning thread. */
        QMetaObject::invokeMethod(instance_, [=]() {
            instance_->startAutoCheck();
            }, Qt::QueuedConnection);

        emit instance_->updateEngaged();
    }
}
#elif defined(__APPLE__)
/** Check to see if Wireshark can shut down safely (e.g. offer to save the
 *  current capture). These callbacks are used by the software update system
 *  to determine if it can shut down the app to install updates.
 */
void SoftwareUpdate::onPostponeRelaunch(void (*proceed)(void *ctx), void *ctx) {
    if (instance_) {
        emit instance_->updateEngaged();

        ShutdownEvent shutdownEvent;
        emit instance_->appShutdownRequested(&shutdownEvent);

        if (shutdownEvent.isAccepted()) {
            return proceed(ctx);
        }
    }
}
#endif

void SoftwareUpdate::checkForUpdates()
{
    updateMutex_.lock();
    QNetworkRequest request(updateUrl());
    QString userAgent = QString("%1 Update Check/%2").arg(application_flavor_name_proper()).arg(application_version());
    request.setHeader(QNetworkRequest::UserAgentHeader, userAgent);

    // Bypass caches to always get the latest appcast
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);

    networkAccessManager_->get(request);

#if defined(UPDATE_TEST)
    qDebug() << "Checking for updates at:" << updateUrl().toString();
#endif /* if */
    updateMutex_.unlock();
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

    #if defined(WIN32)
        const auto target_os = "windows";
    #elif defined(__APPLE__)
        const auto target_os = "macos";
    #else
        /** needs to be set to something, as an empty string means any platform for sparkle */
        const auto target_os = "xxxx";
    #endif

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
