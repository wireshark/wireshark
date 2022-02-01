/* logshark_application.cpp
 *
 * Logshark - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "logshark_application.h"

LogsharkApplication *lsApp = NULL;

LogsharkApplication::LogsharkApplication(int &argc,  char **argv) :
    MainApplication(argc, argv)
{
    lsApp = this;
    setApplicationName("Logshark");
    setDesktopFileName(QStringLiteral("org.wireshark.Logshark"));
}

LogsharkApplication::~LogsharkApplication()
{
    lsApp = NULL;
}
