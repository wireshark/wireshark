/* logray_application.cpp
 *
 * Logray - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "logray_application.h"

#include "extcap.h"
#include "ui/iface_lists.h"
#include "ui/ws_ui_util.h"

LograyApplication *lwApp = NULL;

LograyApplication::LograyApplication(int &argc, char **argv) :
    MainApplication(argc, argv)
{
    lwApp = this;
    Q_INIT_RESOURCE(lricon);
    setApplicationName("Logray");
    setDesktopFileName(QStringLiteral("org.wireshark.Logray"));
}

LograyApplication::~LograyApplication()
{
    lwApp = NULL;
}

void LograyApplication::refreshLocalInterfaces()
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
