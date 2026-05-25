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

#ifndef GSM_MAP_SUMMARY_DIALOG_H
#define GSM_MAP_SUMMARY_DIALOG_H

#include "wireshark_dialog.h"

namespace Ui {
class GsmMapSummaryDialog;
}

/**
 * @brief A dialog for displaying GSM MAP (Mobile Application Part) summary statistics.
 */
class GsmMapSummaryDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new GsmMapSummaryDialog.
     * @param parent The parent widget.
     * @param capture_file The capture file containing the data to summarize.
     */
    explicit GsmMapSummaryDialog(QWidget &parent, CaptureFile& capture_file);

    /**
     * @brief Destroys the GsmMapSummaryDialog.
     */
    ~GsmMapSummaryDialog();

private:
    /** Pointer to the generated UI elements. */
    Ui::GsmMapSummaryDialog *ui;

    /**
     * @brief Converts the GSM MAP summary data to an HTML formatted string.
     * @return The HTML formatted summary string.
     */
    QString summaryToHtml();

private slots:
    /**
     * @brief Slot triggered to update the dialog widgets based on the current data state.
     */
    void updateWidgets() override;

};

#endif // GSM_MAP_SUMMARY_DIALOG_H
