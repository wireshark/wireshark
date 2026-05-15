/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORT_PDU_DIALOG_H
#define EXPORT_PDU_DIALOG_H

#include <QDialog>
#include <QDebug>

namespace Ui {
class ExportPDUDialog;
}

/**
 * @brief A dialog for exporting Protocol Data Units (PDUs) to a file.
 */
class ExportPDUDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ExportPDUDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit ExportPDUDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the ExportPDUDialog.
     */
    ~ExportPDUDialog();

private:
    /** Pointer to the generated UI elements. */
    Ui::ExportPDUDialog *ui;

private slots:
    /**
     * @brief Slot triggered when the dialog is accepted.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();
};

#endif // EXPORT_PDU_DIALOG_H
