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
    Q_INIT_RESOURCE(wsicon);
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
    QList<int> icon_sizes = QList<int>() << 16 << 24 << 32 << 48 << 64 << 128 << 256 << 512 << 1024;
    foreach (int icon_size, icon_sizes) {
        QString icon_path = QString(":/wsicon/wsicon%1.png").arg(icon_size);
        normal_icon_.addFile(icon_path);
        icon_path = QString(":/wsicon/wsiconcap%1.png").arg(icon_size);
        capture_icon_.addFile(icon_path);
    }
}
