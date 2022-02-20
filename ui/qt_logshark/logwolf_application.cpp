/* logwolf_application.cpp
 *
 * Logwolf - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "logwolf_application.h"

LogwolfApplication *lwApp = NULL;

LogwolfApplication::LogwolfApplication(int &argc, char **argv) :
    MainApplication(argc, argv)
{
    lwApp = this;
    setApplicationName("Logwolf");
    setDesktopFileName(QStringLiteral("org.wireshark.Logwolf"));
}

LogwolfApplication::~LogwolfApplication()
{
    lwApp = NULL;
}
