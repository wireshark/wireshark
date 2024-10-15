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

LograyApplication *lwApp;

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
    free_interface_list(cached_if_list_);
    cached_if_list_ = NULL;

    GList * filter_list = NULL;
    filter_list = g_list_append(filter_list, GUINT_TO_POINTER((unsigned) IF_EXTCAP));

    // We don't need to (re)start the stats (which calls dumpcap) because
    // Logray only uses extcaps now. If that changes, do the below instead.
#if 0
    emit scanLocalInterfaces(filter_list);
#endif

    scan_local_interfaces_filtered(filter_list, main_window_update);

    g_list_free(filter_list);

    emit localInterfaceListChanged();
#endif
}

void LograyApplication::initializeIcons()
{
    // Do this as late as possible in order to allow time for
    // MimeDatabaseInitThread to do its work.
    QList<int> icon_sizes = QList<int>() << 16 << 24 << 32 << 48 << 64 << 128 << 256 << 512 << 1024;
    foreach (int icon_size, icon_sizes) {
        QString icon_path = QString(":/lricon/lricon%1.png").arg(icon_size);
        normal_icon_.addFile(icon_path);
        icon_path = QString(":/lricon/lriconcap%1.png").arg(icon_size);
        capture_icon_.addFile(icon_path);
    }
}
