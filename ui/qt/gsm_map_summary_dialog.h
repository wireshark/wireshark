/* gsm_map_summary_dialog.h
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

class GsmMapSummaryDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit GsmMapSummaryDialog(QWidget &parent, CaptureFile& capture_file);
    ~GsmMapSummaryDialog();

private:
    Ui::GsmMapSummaryDialog *ui;

    QString summaryToHtml();

private slots:
    void updateWidgets();

};

#endif // GSM_MAP_SUMMARY_DIALOG_H

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
