/* export_pdu_dialog.cpp
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

#include "config.h"

#include "export_pdu_dialog.h"
#include "ui_export_pdu_dialog.h"

#include "globals.h"
#include "pcap-encap.h"

#include <epan/tap.h>
#include <epan/exported_pdu.h>

#include "ui/tap_export_pdu.h"

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
    const char *filter;
    QString    tap_name;
    exp_pdu_t  exp_pdu_data;

    exp_pdu_data.pkt_encap = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_WIRESHARK_UPPER_PDU);

    filter = ui->displayFilterLineEdit->text().toUtf8().constData();
    tap_name = ui->comboBox->currentText();

    do_export_pdu(filter, (gchar *)tap_name.toUtf8().constData(), &exp_pdu_data);
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
