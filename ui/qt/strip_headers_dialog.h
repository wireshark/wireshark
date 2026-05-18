/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRIP_HEADERS_DIALOG_H
#define STRIP_HEADERS_DIALOG_H

#include <QDialog>
#include <QDebug>

namespace Ui {
class StripHeadersDialog;
}

/**
 * @brief Dialog that allows the user to strip encapsulation headers from
 *        packets in the current capture file, producing a new file with
 *        a different link-layer encapsulation type.
 */
class StripHeadersDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Strip Headers dialog.
     * @param parent Optional parent widget.
     */
    explicit StripHeadersDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the dialog and releases the associated UI resources.
     */
    ~StripHeadersDialog();

private:
    Ui::StripHeadersDialog *ui; /**< Qt Designer-generated UI object for this dialog. */

private slots:
    /**
     * @brief Validates the selected encapsulation options and initiates the
     *        header-stripping operation when the user confirms the dialog.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Opens the context-sensitive help page for the Strip Headers dialog.
     */
    void on_buttonBox_helpRequested();
};

#endif // STRIP_HEADERS_DIALOG_H
