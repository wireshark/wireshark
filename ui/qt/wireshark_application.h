/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WIRESHARK_APPLICATION_H
#define WIRESHARK_APPLICATION_H

#include <main_application.h>

class WiresharkApplication : public MainApplication
{
public:
    explicit WiresharkApplication(int &argc,  char **argv);
    ~WiresharkApplication();
};

extern WiresharkApplication *wsApp;

#endif // WIRESHARK_APPLICATION_H
