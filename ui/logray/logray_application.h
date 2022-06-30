/** @file
 *
 * Logray - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LOGRAY_APPLICATION_H
#define LOGRAY_APPLICATION_H

#include <main_application.h>

// To do:
// - Remove SequenceDiagram dependency on RTPStreamDialog
// - Remove PacketListModel dependency on WirelessTimeline

class LograyApplication : public MainApplication
{
public:
    explicit LograyApplication(int &argc, char **argv);
    ~LograyApplication();

    void refreshLocalInterfaces() override;
};

extern LograyApplication *lwApp;

#endif // LOGRAY_APPLICATION_H
