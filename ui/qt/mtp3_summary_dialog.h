/* mtp3_summary_dialog.h
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

class Mtp3SummaryDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit Mtp3SummaryDialog(QWidget &parent, CaptureFile& capture_file);
    ~Mtp3SummaryDialog();

private:
    Ui::Mtp3SummaryDialog *ui;

    QString summaryToHtml();

private slots:
    void updateWidgets();
};

#endif // MTP3_SUMMARY_DIALOG_H

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
