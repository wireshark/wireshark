/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_ALL_ASSOCS_DIALOG_H
#define SCTP_ALL_ASSOCS_DIALOG_H

#include <config.h>

#include <file.h>

#include <epan/dissectors/packet-sctp.h>

#include "ui/tap-sctp-analysis.h"

#include <QDialog>
#include <QObject>

namespace Ui {
class SCTPAllAssocsDialog;
}

/**
 * @brief Dialog displaying a list of all detected SCTP associations.
 */
class SCTPAllAssocsDialog : public QDialog
{
     Q_OBJECT

public:
    /**
     * @brief Constructs a new SCTPAllAssocsDialog object.
     * @param parent The parent widget.
     * @param cf Pointer to the capture file.
     */
    explicit SCTPAllAssocsDialog(QWidget *parent = 0, capture_file *cf = NULL);

    /**
     * @brief Destroys the SCTPAllAssocsDialog object.
     */
    ~SCTPAllAssocsDialog();

    /**
     * @brief Fills the dialog's table with SCTP association data.
     */
    void fillTable();

public slots:
    /**
     * @brief Sets the active capture file for the dialog.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    /**
     * @brief Handles the event when the "Analyse" button is clicked.
     */
    void on_analyseButton_clicked();

    /**
     * @brief Handles the event when the "Set Filter" button is clicked.
     */
    void on_setFilterButton_clicked();

    /**
     * @brief Retrieves the currently selected item in the association table.
     */
    void getSelectedItem();

private:
    /** @brief Pointer to the user interface object for this dialog. */
    Ui::SCTPAllAssocsDialog *ui;

    /** @brief Pointer to the capture file context. */
    capture_file *cap_file_;

    /** @brief The ID of the currently selected SCTP association. */
    uint16_t selected_assoc_id;

signals:
    /**
     * @brief Signal emitted to request filtering packets based on the selected association.
     * @param new_filter The filter string to apply.
     * @param force True to force the application of the filter.
     */
    void filterPackets(QString new_filter, bool force);
};

#endif // SCTP_ALL_ASSOCS_DIALOG_H
