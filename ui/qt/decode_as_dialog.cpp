/* stats_tree_dialog.h
 *
 * $Id$
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

#include "decode_as_dialog.h"
#include "ui_decode_as_dialog.h"

#include "epan/decode_as.h"
#include "epan/dissectors/packet-dcerpc.h"

#include "wireshark_application.h"

#include <QTreeWidgetItem>

#include <QDebug>

const int field_col_    = 0;
const int value_col_    = 1;
const int default_col_  = 2;
const int current_col_  = 3;

DecodeAsDialog::DecodeAsDialog(QWidget *parent, capture_file *cf) :
    QDialog(parent),
    ui(new Ui::DecodeAsDialog),
    cap_file_(cf)
{
    ui->setupUi(this);

    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(fillTable()));
    fillTable();
}

DecodeAsDialog::~DecodeAsDialog()
{
    delete ui;
}

void DecodeAsDialog::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    fillTable();
}

void DecodeAsDialog::fillTable()
{
    ui->decodeAsTreeWidget->clear();
    dissector_all_tables_foreach_changed(buildChangedList, this);
    decode_dcerpc_add_show_list(buildDceRpcChangedList, this);
}

void DecodeAsDialog::buildChangedList(const gchar *table_name, ftenum_t selector_type, gpointer key, gpointer value, gpointer user_data)
{
    DecodeAsDialog *da_dlg = (DecodeAsDialog *)user_data;
    if (!da_dlg) return;

    dissector_handle_t default_dh, current_dh;
    QString value_str;
    QString default_proto_name = "(none)", current_proto_name = "(none)";
    QTreeWidgetItem *ti = new QTreeWidgetItem();

    current_dh = dtbl_entry_get_handle((dtbl_entry_t *)value);
    if (current_dh) {
        current_proto_name = dissector_handle_get_short_name(current_dh);
    }
    default_dh = dtbl_entry_get_initial_handle((dtbl_entry_t *)value);
    if (default_dh) {
        default_proto_name = dissector_handle_get_short_name(default_dh);
    }

    switch (selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        switch (get_dissector_table_base(table_name)) {

        case BASE_DEC:
            value_str = QString::number(GPOINTER_TO_UINT(key));
            break;

        case BASE_HEX:
            switch (get_dissector_table_selector_type(table_name)) {

            case FT_UINT8:
                value_str = QString("%1").arg(GPOINTER_TO_UINT(key), 2, 16, QChar('0'));
                break;

            case FT_UINT16:
                value_str = QString("%1").arg(GPOINTER_TO_UINT(key), 4, 16, QChar('0'));
                break;

            case FT_UINT24:
                value_str = QString("%1").arg(GPOINTER_TO_UINT(key), 6, 16, QChar('0'));
                break;

            case FT_UINT32:
                value_str = QString("%1").arg(GPOINTER_TO_UINT(key), 8, 16, QChar('0'));
                break;

            default:
                g_assert_not_reached();
                break;
            }
            break;

        case BASE_OCT:
            value_str = QString::number(GPOINTER_TO_UINT(key), 8);
            break;
        }
        break;

    case FT_STRING:
    case FT_STRINGZ:
        value_str = (char *)key;
        break;

    default:
        g_assert_not_reached();
        break;
    }

    ti->setText(field_col_, get_dissector_table_ui_name(table_name));
    ti->setText(value_col_, value_str);
    ti->setText(default_col_, default_proto_name);
    ti->setText(current_col_, current_proto_name);

    da_dlg->ui->decodeAsTreeWidget->addTopLevelItem(ti);
}

void DecodeAsDialog::buildDceRpcChangedList(gpointer data, gpointer user_data)
{
    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t *)data;
    qDebug() << "=bdcecl" << binding->ifname;
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
