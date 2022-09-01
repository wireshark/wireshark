/* wireshark_application.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wireshark_application.h"

WiresharkApplication *wsApp = NULL;

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
