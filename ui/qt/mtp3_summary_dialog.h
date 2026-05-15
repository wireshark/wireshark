/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MTP3_SUMMARY_DIALOG_H
#define MTP3_SUMMARY_DIALOG_H

#include "wireshark_dialog.h"

namespace Ui {
class Mtp3SummaryDialog;
}

/**
 * @brief Dialog for displaying MTP3 summary statistics.
 */
class Mtp3SummaryDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new Mtp3SummaryDialog.
     * @param parent The parent widget.
     * @param capture_file The associated capture file.
     */
    explicit Mtp3SummaryDialog(QWidget &parent, CaptureFile& capture_file);

    /**
     * @brief Destroys the Mtp3SummaryDialog.
     */
    ~Mtp3SummaryDialog();

private:
    /** Pointer to the UI elements. */
    Ui::Mtp3SummaryDialog *ui;

    /**
     * @brief Converts the MTP3 summary data to an HTML formatted string.
     * @return The HTML formatted summary string.
     */
    QString summaryToHtml();

private slots:
    /**
     * @brief Updates the UI widgets with the latest data.
     */
    void updateWidgets();
};

#endif // MTP3_SUMMARY_DIALOG_H
