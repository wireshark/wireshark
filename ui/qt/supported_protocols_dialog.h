/* supported_protocols_dialog.h
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

#ifndef SUPPORTED_PROTOCOLS_DIALOG_H
#define SUPPORTED_PROTOCOLS_DIALOG_H

#include "geometry_state_dialog.h"

namespace Ui {
class SupportedProtocolsDialog;
}

class SupportedProtocolsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit SupportedProtocolsDialog(QWidget *parent = 0);
    ~SupportedProtocolsDialog();

private:
    Ui::SupportedProtocolsDialog *ui;

    int field_count_;
    void updateStatistics();

private slots:
    void fillTree();

    void on_searchLineEdit_textChanged(const QString &search_re);
};

#endif // SUPPORTED_PROTOCOLS_DIALOG_H

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
