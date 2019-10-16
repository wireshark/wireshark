/* wireshark_file_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wireshark_file_dialog.h"

#ifdef Q_OS_WIN
#include <windows.h>
#include "ui/packet_range.h"
#include "ui/win32/file_dlg_win32.h"
#endif // Q_OS_WIN

QString WiresharkFileDialog::getExistingDirectory(QWidget *parent, const QString &caption, const QString &dir, Options options)
{
#ifdef Q_OS_WIN
    HANDLE da_ctx = set_thread_per_monitor_v2_awareness();
#endif
    QString ed = QFileDialog::getExistingDirectory(parent, caption, dir, options);
#ifdef Q_OS_WIN
    revert_thread_per_monitor_v2_awareness(da_ctx);
#endif
    return ed;
}

QString WiresharkFileDialog::getOpenFileName(QWidget *parent, const QString &caption, const QString &dir, const QString &filter, QString *selectedFilter, Options options)
{
#ifdef Q_OS_WIN
    HANDLE da_ctx = set_thread_per_monitor_v2_awareness();
#endif
    QString ofn = QFileDialog::getOpenFileName(parent, caption, dir, filter, selectedFilter, options);
#ifdef Q_OS_WIN
    revert_thread_per_monitor_v2_awareness(da_ctx);
#endif
    return ofn;
}

QString WiresharkFileDialog::getSaveFileName(QWidget *parent, const QString &caption, const QString &dir, const QString &filter, QString *selectedFilter, Options options)
{
#ifdef Q_OS_WIN
    HANDLE da_ctx = set_thread_per_monitor_v2_awareness();
#endif
    QString sfn = QFileDialog::getSaveFileName(parent, caption, dir, filter, selectedFilter, options);
#ifdef Q_OS_WIN
    revert_thread_per_monitor_v2_awareness(da_ctx);
#endif
    return sfn;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
