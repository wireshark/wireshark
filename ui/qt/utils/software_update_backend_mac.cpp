/* software_update_backend_mac.cpp
 *
 * Glue between SoftwareUpdate and the Sparkle bridge in ui/macosx.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/software_update_backend.h"

#include "epan/prefs.h"

#include "ui/qt/utils/software_update.h"

#include <ui/macosx/sparkle_bridge.h>

#include <QDebug>

#if !defined(__x86_64__) && !defined(__arm64__)
    #error Software updates are only be defined for x86-64 or arm64.
#endif /* if */

class SparkleUpdateBackend : public SoftwareUpdateBackend
{
public:
    QString info() const override { return QStringLiteral("Sparkle"); }

    bool supportsAppcast() const override { return true; }

    QString osName() const override { return QStringLiteral("macOS"); }

    void init(const QUrl &appcastUrl, bool runWithoutSilentCheck) override
    {
        if (runWithoutSilentCheck && prefs.gui_update_enabled) {
            SparkleBridge::updateInit(appcastUrl.toString().toUtf8().constData(), prefs.gui_update_enabled, prefs.gui_update_interval);
        } else {
            SparkleBridge::updateInit(appcastUrl.toString().toUtf8().constData(), false, 0);
        }

        SparkleBridge::setUpdateCallbacks(
            // engage callback
            []() {
                emit SoftwareUpdate::instance()->updateEngaged();
            },
            // postpone callback — save documents, then proceed
            [](void (*proceed)(void *ctx), void *ctx) {
                SoftwareUpdate *su = SoftwareUpdate::instance();
                emit su->updateEngaged();

                ShutdownEvent shutdownEvent;
                emit su->appShutdownRequested(&shutdownEvent);

                if (shutdownEvent.isAccepted()) {
                    proceed(ctx);
                }
            },
            // will-relaunch callback — final cleanup
            []() {
                qInfo() << "Sparkle is about to relaunch the application.";
            }
        );
    }

    void performUIUpdate() override
    {
        SparkleBridge::updateCheck();
    }
};

SoftwareUpdateBackend *SoftwareUpdateBackend::create()
{
    return new SparkleUpdateBackend();
}
