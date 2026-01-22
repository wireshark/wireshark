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
#ifndef Q_OS_MAC
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
#ifndef Q_OS_MAC
    QList<int> icon_sizes = QList<int>() << 256 << 64 << 48 << 32 << 24 << 16;
    foreach (int icon_size, icon_sizes) {
        QString icon_path = QStringLiteral(":/wsicon/wsicon%1.png").arg(icon_size);
        normal_icon_.addFile(icon_path);
        icon_path = QStringLiteral(":/wsicon/wsiconcap%1.png").arg(icon_size);
        capture_icon_.addFile(icon_path);
    }
#endif
}
