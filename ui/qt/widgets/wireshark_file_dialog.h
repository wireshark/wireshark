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
    /**
     * @brief Constructs a Wireshark file dialog.
     * @param parent    The parent widget.
     * @param caption   The dialog window title.
     * @param directory The initial directory shown in the dialog.
     * @param filter    The file type filter string (e.g. "Captures (*.pcap *.pcapng)").
     */
    WiresharkFileDialog(QWidget *parent = nullptr, const QString &caption = QString(), const QString &directory = QString(), const QString &filter = QString());

    /**
     * @brief Returns the selected file path in native OS format.
     * @return The selected path with native directory separators.
     */
    QString selectedNativePath() const;

    /**
     * @brief Presents a directory chooser dialog and returns the selected path.
     * @param parent  The parent widget.
     * @param caption The dialog window title.
     * @param dir     The initial directory to display.
     * @param options Dialog behavior options (default: ShowDirsOnly).
     * @return The chosen directory path in native format, or an empty string if cancelled.
     */
    static QString getExistingDirectory(QWidget *parent = Q_NULLPTR, const QString &caption = QString(), const QString &dir = QString(), Options options = ShowDirsOnly);

    /**
     * @brief Presents an open-file dialog and returns the selected file path.
     * @param parent         The parent widget.
     * @param caption        The dialog window title.
     * @param dir            The initial directory to display.
     * @param filter         The file type filter string.
     * @param selectedFilter If non-null, receives the filter the user selected.
     * @param options        Dialog behavior options.
     * @return The chosen file path in native format, or an empty string if cancelled.
     */
    static QString getOpenFileName(QWidget *parent = Q_NULLPTR, const QString &caption = QString(), const QString &dir = QString(), const QString &filter = QString(), QString *selectedFilter = Q_NULLPTR, Options options = Options());

    /**
     * @brief Presents a save-file dialog and returns the chosen file path.
     * @param parent         The parent widget.
     * @param caption        The dialog window title.
     * @param dir            The initial directory to display.
     * @param filter         The file type filter string.
     * @param selectedFilter If non-null, receives the filter the user selected.
     * @param options        Dialog behavior options.
     * @return The chosen file path in native format, or an empty string if cancelled.
     */
    static QString getSaveFileName(QWidget *parent = Q_NULLPTR, const QString &caption = QString(), const QString &dir = QString(), const QString &filter = QString(), QString *selectedFilter = Q_NULLPTR, Options options = Options());
};

#endif // WIRESHARK_FILE_DIALOG_H
