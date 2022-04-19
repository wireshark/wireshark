/* logwolf_application.cpp
 *
 * Logwolf - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "logwolf_application.h"

#include "extcap.h"
#include "ui/iface_lists.h"
#include "ui/ws_ui_util.h"

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

void LogwolfApplication::refreshLocalInterfaces()
{
    extcap_clear_interfaces();

#ifdef HAVE_LIBPCAP
    GList * filter_list = NULL;
    filter_list = g_list_append(filter_list, GUINT_TO_POINTER((guint) IF_EXTCAP));

    scan_local_interfaces_filtered(filter_list, main_window_update);

    g_list_free(filter_list);

    emit localInterfaceListChanged();
#endif
}
