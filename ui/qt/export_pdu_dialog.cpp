/* export_pdu_dialog.cpp
 * Dialog for exporting PDUs to file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "export_pdu_dialog.h"
#include <ui_export_pdu_dialog.h>

#include <wiretap/pcap-encap.h>

#include <epan/tap.h>
#include <epan/exported_pdu.h>

#include "ui/tap_export_pdu.h"
#include "ui/export_pdu_ui_utils.h"

ExportPDUDialog::ExportPDUDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExportPDUDialog)
{
    GSList *tap_name_list;

    ui->setupUi(this);

    for (tap_name_list = get_export_pdu_tap_list(); tap_name_list; tap_name_list = g_slist_next(tap_name_list)) {
        ui->comboBox->addItem((const char*)(tap_name_list->data));
    }
}
void ExportPDUDialog::on_buttonBox_accepted()
{
    exp_pdu_t  exp_pdu_data;

    exp_pdu_data.pkt_encap = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_WIRESHARK_UPPER_PDU);

    const QByteArray& filter = ui->displayFilterLineEdit->text().toUtf8();
    const QByteArray& tap_name = ui->comboBox->currentText().toUtf8();

    do_export_pdu(filter.constData(), tap_name.constData(), &exp_pdu_data);
}
ExportPDUDialog::~ExportPDUDialog()
{
    delete ui;
}

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
