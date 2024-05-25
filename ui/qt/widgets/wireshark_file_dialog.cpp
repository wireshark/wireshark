/* wireshark_file_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wireshark_file_dialog.h"

#ifdef Q_OS_WIN
#include <windows.h>
#include "ui/packet_range.h"
#include "ui/win32/file_dlg_win32.h"
#endif // Q_OS_WIN


WiresharkFileDialog::WiresharkFileDialog(QWidget *parent, const QString &caption, const QString &directory, const QString &filter) :
    QFileDialog(parent, caption, directory, filter)
{
#ifdef Q_OS_MAC
    // Add /Volumes to the sidebar. We might want to call
    // setFilter(QDir::Hidden | QDir::AllEntries) in addition to or instead
    // of this as recommended in QTBUG-6805 and QTBUG-6875, but you can
    // access hidden files in the Qt file dialog by right-clicking on the
    // file list or simply typing in the path in the "File name:" entry.

    QList<QUrl> sb_urls = sidebarUrls();
    bool have_volumes = false;
    QString volumes = "/Volumes";
    foreach (QUrl sbu, sb_urls) {
        if (sbu.toLocalFile() == volumes) {
            have_volumes = true;
        }
    }
    if (! have_volumes) {
        sb_urls << QUrl::fromLocalFile(volumes);
        setSidebarUrls(sb_urls);
    }
#endif
}

QString WiresharkFileDialog::selectedNativePath() const
{
    if (selectedFiles().isEmpty()) {
        // The API implies this can't happen
        return QString();
    }
    return QDir::toNativeSeparators(selectedFiles().at(0));
}

QString WiresharkFileDialog::getExistingDirectory(QWidget *parent, const QString &caption, const QString &dir, Options options)
{
#ifdef Q_OS_WIN
    HANDLE da_ctx = set_thread_per_monitor_v2_awareness();
#endif
    QString ed = QFileDialog::getExistingDirectory(parent, caption, dir, options);
#ifdef Q_OS_WIN
    revert_thread_per_monitor_v2_awareness(da_ctx);
#endif
    return QDir::toNativeSeparators(ed);
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
    return QDir::toNativeSeparators(ofn);
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
    return QDir::toNativeSeparators(sfn);
}
