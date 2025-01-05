/* stratoshark_application.cpp
 *
 * Stratoshark - System call and event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "stratoshark_application.h"

StratosharkApplication *ssApp;

StratosharkApplication::StratosharkApplication(int &argc, char **argv) :
    MainApplication(argc, argv)
{
    ssApp = this;
#if defined(Q_OS_MAC)
    Q_INIT_RESOURCE(ssicon_mac);
#else
    Q_INIT_RESOURCE(ssicon);
#endif
    setApplicationName("Stratoshark");
    setDesktopFileName(QStringLiteral("org.wireshark.Stratoshark"));
}

StratosharkApplication::~StratosharkApplication()
{
    ssApp = NULL;
}

void StratosharkApplication::initializeIcons()
{
    // Do this as late as possible in order to allow time for
    // MimeDatabaseInitThread to do its work.
#if defined(Q_OS_MAC)
    normal_icon_ = QIcon(windowIcon());
    QList<int> icon_sizes = QList<int>() << 16 << 32 << 128 << 256 << 512;
    QList<const char *> retina_vals = QList<const char *>() << "" << "@2x";
    foreach (int icon_size, icon_sizes) {
        foreach (const char *retina_val, retina_vals) {
            QString icon_path = QStringLiteral(":/ssicon_mac/ssicon%1%2.png").arg(icon_size).arg(retina_val);
            normal_icon_.addFile(icon_path);
            icon_path = QStringLiteral(":/ssicon_mac/ssiconcap%1%2.png").arg(icon_size).arg(retina_val);
            capture_icon_.addFile(icon_path);
        }
    }
#else
    QList<int> icon_sizes = QList<int>() << 16 << 24 << 32 << 48 << 256;
    foreach (int icon_size, icon_sizes) {
        QString icon_path = QStringLiteral(":/ssicon/ssicon%1.png").arg(icon_size);
        normal_icon_.addFile(icon_path);
        icon_path = QStringLiteral(":/ssicon/ssiconcap%1.png").arg(icon_size);
        capture_icon_.addFile(icon_path);
    }
#endif
}
