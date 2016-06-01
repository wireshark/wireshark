/* firewall_rules_dialog.h
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

#ifndef FIREWALL_RULES_DIALOG_H
#define FIREWALL_RULES_DIALOG_H

#include "epan/address.h"

#include <wireshark_dialog.h>

namespace Ui {
class FirewallRulesDialog;
}

class QAbstractButton;

typedef void (*syntax_func)(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);

class FirewallRulesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit FirewallRulesDialog(QWidget &parent, CaptureFile &cf);
    ~FirewallRulesDialog();

private slots:
    void on_productComboBox_currentIndexChanged(int new_idx);
    void on_inboundCheckBox_toggled(bool);
    void on_denyCheckBox_toggled(bool);
    void on_buttonBox_helpRequested();

    void on_buttonBox_clicked(QAbstractButton *button);

private:
    Ui::FirewallRulesDialog *ui;

    QString file_name_;
    int packet_num_;

    size_t prod_;
    address dl_src_;
    address dl_dst_;
    address net_src_;
    address net_dst_;
    port_type ptype_;
    guint32 src_port_;
    guint32 dst_port_;

    void updateWidgets();
    void addRule(QString description, syntax_func rule_func, address *addr, guint32 port);
};

#endif // FIREWALL_RULES_DIALOG_H

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
