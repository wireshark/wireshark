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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
