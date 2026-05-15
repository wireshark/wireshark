/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SOFTWARE_UPDATE_H
#define SOFTWARE_UPDATE_H

#include <QObject>
#include <QUrl>
#include <QMutex>
#include <QTimer>
#include <QVersionNumber>

class QNetworkAccessManager;
class QNetworkReply;

/**
 * @brief An event object passed to shutdown listeners to allow vetoing.
 */
class ShutdownEvent {
public:
    /**
     * @brief Signal that this listener consents to the shutdown.
     */
    void accept();

    /**
     * @brief Veto the shutdown with an optional explanatory message.
     * @param reason A human-readable string explaining why the shutdown
     *               is being blocked, shown to the user. May be empty.
     */
    void reject(const QString &reason = {});

    /**
     * @brief Return whether the shutdown has been accepted.
     * @return true if accept() was called and reject() was not.
     */
    bool isAccepted() const;

    /**
     * @brief Return the reason provided to the most recent reject() call.
     * @return The rejection reason string, or an empty string if the
     *         shutdown was not rejected.
     */
    QString reason() const;

private:
    bool accepted_ = false; /**< Set by accept(). */
    bool rejected_ = false; /**< Set by reject(); takes precedence over accepted_. */
    QString reason_;        /**< Reason string supplied to reject(). */
};

/**
 * @brief A single entry from a Sparkle-compatible appcast feed.
 */
struct AppcastItem {
    QString title;             /**< Human-readable release title (e.g. "Wireshark 4.4.2"). */
    QVersionNumber version;    /**< Full version number used for comparison. */
    QVersionNumber shortVersion; /**< Abbreviated display version (e.g. "4.4.2"). */
    QUrl downloadUrl;          /**< Direct download URL for the release artifact. */
    QUrl releaseNotesUrl;      /**< URL of the HTML release notes page. */
    /** Target OS constraint: @c "windows", @c "macos", or empty to indicate
     *  the item applies to all platforms. */
    QString os;
    qint64 length = 0;         /**< Expected size of the download artifact in bytes. */
    QString edSignature;       /**< Ed25519 signature for verifying the download artifact. */
};

/**
 * @brief The SoftwareUpdate class provides an interface for checking for software
 * updates and engaging the update process.
 *
 * This class is implemented as a singleton and can be accessed through the static
 * instance() method. It provides methods for initializing and cleaning up the update
 * framework, as well as for starting and stopping automatic update checks. The class
 * also emits signals when updates are available, when update checks fail, when the
 * update process is engaged, and when the application requests a shutdown for
 * performing an update.
 */
class SoftwareUpdate : public QObject
{
        Q_OBJECT
public:
    /** @brief Deleted copy constructor — SoftwareUpdate is a singleton. */
    SoftwareUpdate(const SoftwareUpdate &) = delete;

    /** @brief Deleted copy-assignment operator — SoftwareUpdate is a singleton. */
    SoftwareUpdate &operator=(const SoftwareUpdate &) = delete;

    /**
     * @brief Return the singleton SoftwareUpdate instance.
     * @return Pointer to the global SoftwareUpdate instance.
     */
    static SoftwareUpdate *instance();

    /**
     * This method will be called by the main application after it has initialized
     * far enough that the update frameworks can be initialized. Together with that
     * the automatic update check will also be started, if the user has enabled it
     * in the preferences. The interval used will be the one set in the preferences as well.
     *
     * @param runWithoutSilentCheck If true, the update check will be performed as it had
     * been before the silent check was implemented, by using the API versions of the silent
     * checks.
     */
    void init(bool runWithoutSilentCheck = false);

    /**
     * Cleans up the update framework and stops the automatic update check.
     */
    void cleanup();

    /**
     * This will initiate the UI update process. It is assumed, that if the periodic
     * update check is enabled, this will be called by the user by interacting with the
     * update notification. It will also be called when clicking on the "Check for updates"
     * action in the "Help" menu.
     *
     * The "normal" flow is, that we periodically check for updates in the background and
     * notify the user if an update is available. It is then up to the user to decide if
     * they want to update or not.
     */
    static void performUIUpdate();

    /**
     * Returns a string with the information about which software update framework is being used.
     */
    static QString info();

    /**
     * A runtime "wrapper" for HAVE_SOFTWARE_UPDATE and including platform checks. This can be
     * used by the UI to check if an update is currently supported and possible or not.
     *
     * @return true The platform is supported
     * @return false The platform is not supported
     */
    static bool plattformSupported();

/**** Utility functions for manipulating the automatic update check through the UI ****/

/**
 * @brief Start the periodic automatic update check.
 *
 * @param intervalSeconds The check interval in seconds, or 0 to use the
 *                        preference-configured interval.
 */
void startAutoCheck(int intervalSeconds = 0);

/**
 * @brief Stop the periodic automatic update check.
 */
void stopAutoCheck();

/**
 * @brief Return whether the periodic automatic update check is enabled.
 * @return true if the auto-check timer is currently active.
 */
bool isAutoCheckEnabled() const;

signals:
    /**
     * @brief Emitted when a new software update is available.
     * @param newVersion   The version string of the available update.
     * @param releaseNotes The release notes HTML or plain text for the update.
     */
    void updateAvailable(QString newVersion, QString releaseNotes);

    /**
     * @brief Emitted when the update check fails.
     * @param errorString A human-readable description of the failure.
     */
    void updateCheckFailed(const QString &errorString);

    /**
     * @brief Emitted when the update process is engaged.
     *
     * Emitted in any of the following cases:
     * -# The user accepted an update after being notified of an available update.
     * -# The user accepted an update after manually checking through the UI.
     * -# The user was shown the update dialog but dismissed it.
     * -# The user was shown the update dialog but cancelled it.
     * -# The update process failed.
     */
    void updateEngaged();

    /**
     * @brief Emitted when the application requests a shutdown to perform an update.
     * @param shutdownEvent The event object that listeners may accept or reject.
     */
    void appShutdownRequested(ShutdownEvent *shutdownEvent);

private:
    static SoftwareUpdate *instance_; /**< The singleton instance. */
    static QMutex mutex_;             /**< Guards instance creation. */
    static QMutex updateMutex_;       /**< Guards concurrent update-check operations. */

    QTimer *updateCheckTimer_;                  /**< Timer driving periodic auto-checks. */
    QNetworkAccessManager *networkAccessManager_; /**< Network manager for appcast requests. */

    /**
     * @brief Return the URL of the appcast feed for the current platform.
     * @return The appcast feed URL.
     */
    QUrl updateUrl() const;

    /**
     * @brief Parse a Sparkle-compatible appcast XML payload.
     * @param data The raw XML bytes received from the appcast feed.
     * @return An ordered list of AppcastItem entries parsed from @p data.
     */
    QList<AppcastItem> parseAppcast(const QByteArray &data) const;


#if defined(_WIN32)
    /**
     * @brief WinSparkle callback queried before the updater may shut down the app.
     * @return Non-zero if the application is ready to shut down; zero to delay.
     */
    static int __cdecl softwareUpdateCanShutdownCallback();

    /**
     * @brief WinSparkle callback invoked when the updater requests application shutdown.
     */
    static void __cdecl shutdownRequestCallback();

    /**
     * @brief WinSparkle callback invoked when the update process is engaged.
     */
    static void __cdecl softwareUpdateEngaged();

#elif defined(__APPLE__)
    /**
     * @brief Sparkle callback invoked when the updater requests a postponed relaunch.
     *
     * @param proceed Function pointer the application must call to allow relaunch.
     * @param ctx     Opaque context pointer passed back to @p proceed.
     */
    static void onPostponeRelaunch(void (*proceed)(void *ctx), void *ctx);
#endif /* if */

private slots:
    /**
     * @brief Handle the completion of an appcast network request.
     * @param reply The finished network reply containing the appcast data or an error.
     */
    void onNetworkReplyFinished(QNetworkReply *reply);

    /**
     * @brief Initiate an update check by fetching the appcast feed.
     *
     * Called by the auto-check timer and by manual check requests from the UI.
     */
    void checkForUpdates();


protected:
    /**
     * @brief Construct the SoftwareUpdate singleton.
     * @param parent The parent QObject.
     */
    explicit SoftwareUpdate(QObject *parent = nullptr);

    /** @brief Destroy the SoftwareUpdate singleton and release all resources. */
    ~SoftwareUpdate();
};

#endif /* SOFTWARE_UPDATE_H */
