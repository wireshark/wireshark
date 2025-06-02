/* wireshark_application.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wireshark_application.h"

WiresharkApplication *wsApp;

WiresharkApplication::WiresharkApplication(int &argc,  char **argv) :
    MainApplication(argc, argv)
{
    wsApp = this;
#if defined(Q_OS_MAC)
    Q_INIT_RESOURCE(wsicon_mac);
#else
    Q_INIT_RESOURCE(wsicon);
#endif
    setApplicationName("Wireshark");
    setDesktopFileName(QStringLiteral("org.wireshark.Wireshark"));
}

WiresharkApplication::~WiresharkApplication()
{
    wsApp = NULL;
}

void WiresharkApplication::initializeIcons()
{
    // Do this as late as possible in order to allow time for
    // MimeDatabaseInitThread to do its work.
#ifdef Q_OS_MAC
    QList<int> icon_sizes = QList<int>() << 1024 << 512 << 256 << 128 << 64 << 32 << 16;
#else
    QList<int> icon_sizes = QList<int>() << 256 << 128 << 64 << 48 << 32 << 24 << 16;
#endif
    if (normal_icon_.isNull()) {
        // We shouldn't be here on Windows or macOS
        foreach (int icon_size, icon_sizes) {
            QString icon_path = QStringLiteral(":/wsicon/wsicon%1.png").arg(icon_size);
            normal_icon_.addFile(icon_path);
        }
    }
    foreach (int icon_size, icon_sizes) {
        QString icon_path = QStringLiteral(":/wsicon/wsiconcap%1.png").arg(icon_size);
        capture_icon_.addFile(icon_path);
    }
}
