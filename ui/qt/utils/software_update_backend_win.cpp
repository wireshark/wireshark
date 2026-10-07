/* software_update_backend_win.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/software_update_backend.h"

#include "app/application_flavor.h"
#include "epan/prefs.h"

#include "ui/language.h"
#include "ui/qt/main_application.h"
#include "ui/qt/utils/software_update.h"

#include <winsparkle.h>

#if !defined(_M_X64) && !defined(_M_ARM64)
    #error Software updates are only be defined for x86-64 or arm64.
#endif /* if */

class WinSparkleUpdateBackend : public SoftwareUpdateBackend
{
public:
    QString info() const override
    {
        return QString("%1 %2").arg("WinSparkle").arg(WIN_SPARKLE_VERSION_STRING);
    }

    bool supportsAppcast() const override { return true; }

    QString osName() const override { return QStringLiteral("Windows"); }

    void init(const QUrl &appcastUrl, bool runWithoutSilentCheck) override
    {
        silentCheck_ = !runWithoutSilentCheck;

        /*
         * According to the WinSparkle 0.5 documentation these must be called
         * once, before win_sparkle_init. We can't update them dynamically when
         * our preferences change.
         */
        QString regKey = QString("Software\\%1\\WinSparkle Settings").arg(application_flavor_name_proper());

        win_sparkle_set_registry_path(regKey.toUtf8().constData());
        win_sparkle_set_appcast_url(appcastUrl.toString().toUtf8().constData());
        if (prefs.gui_update_enabled && runWithoutSilentCheck) {
            win_sparkle_set_automatic_check_for_updates(1);
            win_sparkle_set_update_check_interval(prefs.gui_update_interval);
        } else {
            win_sparkle_set_automatic_check_for_updates(0);
        }
        win_sparkle_set_update_cancelled_callback(&softwareUpdateEngaged);
        win_sparkle_set_update_postponed_callback(&softwareUpdateEngaged);
        win_sparkle_set_update_skipped_callback(&softwareUpdateEngaged);
        win_sparkle_set_update_dismissed_callback(&softwareUpdateEngaged);
        win_sparkle_set_can_shutdown_callback(&softwareUpdateCanShutdownCallback);
        win_sparkle_set_shutdown_request_callback(&shutdownRequestCallback);
        const char* ws_language = get_language_used();
        if ((ws_language != NULL) && (strcmp(ws_language, USE_SYSTEM_LANGUAGE) != 0)) {
            win_sparkle_set_lang(ws_language);
        }
        win_sparkle_init();
    }

    void performUIUpdate() override
    {
        win_sparkle_check_update_with_ui();
    }

    void cleanup() override
    {
        win_sparkle_cleanup();
    }

private:
    /** Our own timer drives the checks, not WinSparkle. Static for the C callbacks. */
    static inline bool silentCheck_ = false;

    /** Check to see if Wireshark can shut down safely (e.g. offer to save the
     *  current capture). These callbacks are used by the software update system
     *  to determine if it can shut down the app to install updates.
     *
     *  At this point the update is ready to install, but WinSparkle has
     *  not yet run the installer. We need to close our "Wireshark is
     *  running" mutexes since the IsWiresharkRunning NSIS macro checks
     *  for them.
     *  We must not exit the Qt main event loop here, which means we must
     *  not close the main window.
     */
    static int __cdecl softwareUpdateCanShutdownCallback()
    {
        SoftwareUpdate *su = SoftwareUpdate::instance();
        emit su->updateEngaged();

        ShutdownEvent shutdownEvent;
        emit su->appShutdownRequested(&shutdownEvent);

        return shutdownEvent.isAccepted();
    }

    /**
     * At this point the installer has been launched. Neither Wireshark nor
     * its children should have any "Wireshark is running" mutexes open.
     * The main window should still be open as noted above in and it's safe
     * to exit the Qt main event loop.
     */
    static void __cdecl shutdownRequestCallback()
    {
        mainApp->quit();
    }

    static void __cdecl softwareUpdateEngaged()
    {
        SoftwareUpdate *su = SoftwareUpdate::instance();

        /* Restarting auto check after update, unless WinSparkle checks by itself */
        if (silentCheck_ && prefs.gui_update_enabled) {
            /* This can be called from a different thread; QTimer can only be
             * stopped and started from the owning thread. */
            QMetaObject::invokeMethod(su, [su]() {
                su->startAutoCheck(prefs.gui_update_interval);
                }, Qt::QueuedConnection);
        }

        emit su->updateEngaged();
    }
};

SoftwareUpdateBackend *SoftwareUpdateBackend::create()
{
    return new WinSparkleUpdateBackend();
}
