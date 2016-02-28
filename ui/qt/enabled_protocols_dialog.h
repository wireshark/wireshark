/* enabled_protocols_dialog.h
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

#ifndef ENABLED_PROTOCOLS_DIALOG_H
#define ENABLED_PROTOCOLS_DIALOG_H

#include "geometry_state_dialog.h"
#include "wireshark_dialog.h"

namespace Ui {
class EnabledProtocolsDialog;
}

struct _protocol;

class QAbstractButton;

class EnabledProtocolsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit EnabledProtocolsDialog(QWidget *parent);
    ~EnabledProtocolsDialog();
    void selectProtocol(struct _protocol *protocol);

private slots:
    void on_invert_button__clicked();
    void on_enable_all_button__clicked();
    void on_disable_all_button__clicked();
    void on_search_line_edit__textChanged(const QString &search_re);
    void on_buttonBox_accepted();
#if 0
    void on_buttonBox_clicked(QAbstractButton *button);
#endif
    void on_buttonBox_helpRequested();

private:
    Ui::EnabledProtocolsDialog *ui;

    static void addHeuristicItem(gpointer data, gpointer user_data);
    bool applyChanges();
    void writeChanges();

};

#endif // ENABLED_PROTOCOLS_DIALOG_H

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
