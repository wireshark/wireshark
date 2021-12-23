/** @file
 *
 * Logshark - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LOGSHARK_APPLICATION_H
#define LOGSHARK_APPLICATION_H

#include <wireshark_application.h>

class LogsharkApplication : public WiresharkApplication
{
public:
    explicit LogsharkApplication(int &argc,  char **argv);
    ~LogsharkApplication();
};

extern LogsharkApplication *lsApp;

#endif // LOGSHARK_APPLICATION_H
