/** @file
 *
 * Logwolf - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LOGWOLF_APPLICATION_H
#define LOGWOLF_APPLICATION_H

#include <main_application.h>

// To do:
// - Remove SequenceDiagram dependency on RTPStreamDialog
// - Remove PacketListModel dependency on WirelessTimeline

class LogwolfApplication : public MainApplication
{
public:
    explicit LogwolfApplication(int &argc, char **argv);
    ~LogwolfApplication();
};

extern LogwolfApplication *lwApp;

#endif // LOGWOLF_APPLICATION_H
