/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WIRESHARK_FILE_DIALOG_H
#define WIRESHARK_FILE_DIALOG_H

#include <QFileDialog>

/**
 * @brief The WiresharkFileDialog class
 *
 * Qt uses '/' as a universal path separator and converts to native path
 * separators, i.e., '\' on Windows, only immediately before displaying a
 * path to a user. This class can return the path with native path
 * separators.
 *
 * Qt <= 5.9 supports setting old (Windows 8.1) per-monitor DPI awareness
 * via Qt:AA_EnableHighDpiScaling. We do this in main.cpp. In order for
 * native dialogs to be rendered correctly we need to set per-monitor
 * *v2* awareness prior to creating the dialog.
 * Qt doesn't render correctly when per-monitor v2 awareness is enabled, so
 * we need to revert our thread context when we're done.
 * The class functions below are simple wrappers around their QFileDialog
 * equivalents that set PMv2 awareness before showing native dialogs on
 * Windows and resets it afterward. They also return the result with native
 * directory separators on Windows.
 */

class WiresharkFileDialog : public QFileDialog
{
public:
    WiresharkFileDialog(QWidget *parent = nullptr, const QString &caption = QString(), const QString &directory = QString(), const QString &filter = QString());
    QString selectedNativePath() const;
    static QString getExistingDirectory(QWidget *parent = Q_NULLPTR, const QString &caption = QString(), const QString &dir = QString(), Options options = ShowDirsOnly);
    static QString getOpenFileName(QWidget *parent = Q_NULLPTR, const QString &caption = QString(), const QString &dir = QString(), const QString &filter = QString(), QString *selectedFilter = Q_NULLPTR, Options options = Options());
    static QString getSaveFileName(QWidget *parent = Q_NULLPTR, const QString &caption = QString(), const QString &dir = QString(), const QString &filter = QString(), QString *selectedFilter = Q_NULLPTR, Options options = Options());
};

#endif // WIRESHARK_FILE_DIALOG_H
