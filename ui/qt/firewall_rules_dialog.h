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

/**
 * @brief Pointer to a function used to generate firewall rule syntax.
 * @param rtxt The string buffer to append the generated rule text to.
 * @param addr The IP or MAC address string.
 * @param port The port number.
 * @param ptype The type of the port (e.g., TCP or UDP).
 * @param inbound True if the rule is for inbound traffic, false for outbound.
 * @param deny True if the rule is to deny traffic, false to allow.
 */
typedef void (*syntax_func)(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);

/**
 * @brief A dialog for generating and displaying firewall rules based on packet data.
 */
class FirewallRulesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FirewallRulesDialog.
     * @param parent The parent widget.
     * @param cf The capture file from which to extract packet data for rules.
     */
    explicit FirewallRulesDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Destroys the FirewallRulesDialog.
     */
    ~FirewallRulesDialog();

private slots:
    /**
     * @brief Slot triggered when the selected firewall product type changes.
     * @param new_idx The index of the newly selected product.
     */
    void on_productComboBox_currentIndexChanged(int new_idx);

    /**
     * @brief Slot triggered when the inbound/outbound checkbox is toggled.
     */
    void on_inboundCheckBox_toggled(bool);

    /**
     * @brief Slot triggered when the deny/allow checkbox is toggled.
     */
    void on_denyCheckBox_toggled(bool);

    /**
     * @brief Slot triggered when help is requested from the dialog's button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Slot triggered when a button in the button box is clicked.
     * @param button The button that was clicked.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

private:
    /** Pointer to the generated UI elements. */
    Ui::FirewallRulesDialog *ui;

    /** The name of the file associated with the rules. */
    QString file_name_;

    /** The specific packet number used as the basis for generating rules. */
    int packet_num_;

    /** The index of the currently selected firewall product format. */
    size_t prod_;

    /** The source data link (MAC) address. */
    address dl_src_;

    /** The destination data link (MAC) address. */
    address dl_dst_;

    /** The source network (IP) address. */
    address net_src_;

    /** The destination network (IP) address. */
    address net_dst_;

    /** The port type (e.g., TCP, UDP) of the selected packet. */
    port_type ptype_;

    /** The source port number. */
    uint32_t src_port_;

    /** The destination port number. */
    uint32_t dst_port_;

    /**
     * @brief Updates the dialog's widgets based on current rule selections.
     */
    void updateWidgets();

    /**
     * @brief Generates and adds a new rule to the dialog display.
     * @param description A text description of the rule's purpose.
     * @param rule_func The formatting function specific to the firewall product.
     * @param addr Pointer to the address to apply the rule to.
     * @param port The port number to apply the rule to.
     */
    void addRule(QString description, syntax_func rule_func, address *addr, uint32_t port);
};

#endif // FIREWALL_RULES_DIALOG_H
