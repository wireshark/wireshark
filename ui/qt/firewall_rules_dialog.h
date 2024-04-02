/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FIREWALL_RULES_DIALOG_H
#define FIREWALL_RULES_DIALOG_H

#include "epan/address.h"

#include <wireshark_dialog.h>

namespace Ui {
class FirewallRulesDialog;
}

class QAbstractButton;

typedef void (*syntax_func)(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);

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
    uint32_t src_port_;
    uint32_t dst_port_;

    void updateWidgets();
    void addRule(QString description, syntax_func rule_func, address *addr, uint32_t port);
};

#endif // FIREWALL_RULES_DIALOG_H
