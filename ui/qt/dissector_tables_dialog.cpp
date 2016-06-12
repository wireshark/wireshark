/* dissector_tables_dialog.cpp
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

#include "dissector_tables_dialog.h"
#include <ui_dissector_tables_dialog.h>

#include "config.h"

#include <epan/packet.h>

#include <QTreeWidgetItem>

#include "wireshark_application.h"
enum {
    col_table_name_,
    col_short_name_
};

enum {
    top_level_type_ = 1000,
    table_type_,
    string_type_,
    integer_type_,
    custom_type_,
    heuristic_type_
};

class DissectorTableTreeWidgetItem : public QTreeWidgetItem
{
public:
    DissectorTableTreeWidgetItem(QString table_name, QString short_name) : QTreeWidgetItem (table_type_) {
        setText(col_table_name_, table_name);
        setText(col_short_name_, short_name);
    }
};

class IntegerTableTreeWidgetItem : public QTreeWidgetItem
{
public:
    IntegerTableTreeWidgetItem(unsigned port, QString proto_name) :
        QTreeWidgetItem (integer_type_),
        port_(port)
    {
        setText(col_table_name_, QString::number(port_));
        setText(col_short_name_, proto_name);
    }
    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != integer_type_) return QTreeWidgetItem::operator< (other);
        const IntegerTableTreeWidgetItem *other_row = static_cast<const IntegerTableTreeWidgetItem *>(&other);

        if (treeWidget()->sortColumn() == col_table_name_) {
            return port_ < other_row->port_;
        }
        return QTreeWidgetItem::operator< (other);
    }

private:
    unsigned port_;
};

DissectorTablesDialog::DissectorTablesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::DissectorTablesDialog)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 3 / 4, parent->height() * 3 / 4);

    setWindowTitle(wsApp->windowTitleString(tr("Dissector Tables")));

    on_tableTreeWidget_itemSelectionChanged();

    QTreeWidgetItem *string_ti = new QTreeWidgetItem(ui->tableTreeWidget, top_level_type_);
    string_ti->setText(col_table_name_, tr("String Tables"));
    string_ti->setFirstColumnSpanned(true);
    string_ti->setExpanded(true);

    QTreeWidgetItem *integer_ti = new QTreeWidgetItem(ui->tableTreeWidget, top_level_type_);
    integer_ti->setText(col_table_name_, tr("Integer Tables"));
    integer_ti->setFirstColumnSpanned(true);
    integer_ti->setExpanded(true);

    QTreeWidgetItem *custom_ti = new QTreeWidgetItem(ui->tableTreeWidget, top_level_type_);
    custom_ti->setText(col_table_name_, tr("Custom Tables"));
    custom_ti->setFirstColumnSpanned(true);
    custom_ti->setExpanded(true);

    dissector_all_tables_foreach_table(gatherTableNames, this, NULL);

    string_ti->addChildren(string_dissectors_);
    integer_ti->addChildren(integer_dissectors_);
    integer_ti->addChildren(custom_dissectors_);

    QTreeWidgetItem *heuristic_ti = new QTreeWidgetItem(ui->tableTreeWidget, top_level_type_);
    heuristic_ti->setText(col_table_name_, tr("Heuristic Tables"));
    heuristic_ti->setFirstColumnSpanned(true);
    heuristic_ti->setExpanded(true);

    dissector_all_heur_tables_foreach_table(gatherHeurTableNames, this, NULL);

    heuristic_ti->addChildren(heuristic_dissectors_);

    ui->tableTreeWidget->sortByColumn(col_table_name_, Qt::AscendingOrder);
    ui->tableTreeWidget->resizeColumnToContents(col_table_name_);
}

DissectorTablesDialog::~DissectorTablesDialog()
{
    delete ui;
}

void DissectorTablesDialog::gatherTableNames(const char *short_name, const char *table_name, gpointer dlg_ptr)
{
    DissectorTablesDialog *dt_dlg = qobject_cast<DissectorTablesDialog *>((DissectorTablesDialog *)dlg_ptr);
    if (!dt_dlg) return;

    ftenum_t selector_type = get_dissector_table_selector_type(short_name);
    DissectorTableTreeWidgetItem *dt_ti = new DissectorTableTreeWidgetItem(table_name, short_name);

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        dt_dlg->integer_dissectors_ << dt_ti;
        break;
    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        dt_dlg->string_dissectors_ << dt_ti;
        break;
    case FT_BYTES:
        dt_dlg->custom_dissectors_ << dt_ti;
        break;
    default:
        // Assert?
        delete dt_ti;
        return;
    }

    QList<QTreeWidgetItem *> proto_decode_list;
    dissector_table_foreach(short_name, gatherProtocolDecodes, &proto_decode_list);

    dt_ti->addChildren(proto_decode_list);
}

void DissectorTablesDialog::gatherProtocolDecodes(const char *, ftenum_t selector_type, gpointer key, gpointer value, gpointer list_ptr)
{
    QList<QTreeWidgetItem *> *pdl_ptr = dynamic_cast<QList<QTreeWidgetItem *> *>((QList<QTreeWidgetItem *> *)list_ptr);
    if (!pdl_ptr) return;

    dtbl_entry_t       *dtbl_entry;
    dissector_handle_t  handle;

    dtbl_entry = (dtbl_entry_t*)value;
    handle = dtbl_entry_get_handle(dtbl_entry);
    const QString proto_name = dissector_handle_get_short_name(handle);
    QTreeWidgetItem *ti = NULL;

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    {
        ti = new IntegerTableTreeWidgetItem(GPOINTER_TO_UINT(key), proto_name);
        break;
    }

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    {
        ti = new QTreeWidgetItem(string_type_);
        ti->setText(col_table_name_, (const char *)key);
        ti->setText(col_short_name_, proto_name);
        break;
    }

    case FT_BYTES:
    {
        const QString dissector_name = dissector_handle_get_dissector_name(handle);
        ti = new QTreeWidgetItem(string_type_);
        ti->setText(col_table_name_, dissector_name);
        ti->setText(col_short_name_, proto_name);
        break;
    }

    default:
        g_assert_not_reached();
    }

    if (ti) *pdl_ptr << ti;
}

void DissectorTablesDialog::gatherHeurTableNames(const char *table_name, heur_dissector_list *list, gpointer dlg_ptr)
{
    DissectorTablesDialog *dt_dlg = qobject_cast<DissectorTablesDialog *>((DissectorTablesDialog *)dlg_ptr);
    if (!dt_dlg) return;

    QTreeWidgetItem *ti = new QTreeWidgetItem(heuristic_type_);
    ti->setText(col_table_name_, table_name);
    ti->setFirstColumnSpanned(true);

    dt_dlg->heuristic_dissectors_ << ti;

    if (list) {
        QList<QTreeWidgetItem *> heur_decode_list;
        heur_dissector_table_foreach(table_name, gatherHeurProtocolDecodes, &heur_decode_list);
        ti->addChildren(heur_decode_list);
    }
}

void DissectorTablesDialog::gatherHeurProtocolDecodes(const char *, struct heur_dtbl_entry *dtbl_entry, gpointer list_ptr)
{
    QList<QTreeWidgetItem *> *hdl_ptr = dynamic_cast<QList<QTreeWidgetItem *> *>((QList<QTreeWidgetItem *> *)list_ptr);
    if (!hdl_ptr) return;

    if (dtbl_entry->protocol) {
        QTreeWidgetItem *ti = new QTreeWidgetItem(heuristic_type_);
        ti->setText(col_table_name_, proto_get_protocol_long_name(dtbl_entry->protocol));
        ti->setText(col_short_name_, proto_get_protocol_short_name(dtbl_entry->protocol));
        *hdl_ptr << ti;
    }
}

void DissectorTablesDialog::on_tableTreeWidget_itemSelectionChanged()
{
    int type = top_level_type_;
    QStringList header_labels;

    if (ui->tableTreeWidget->currentItem()) {
        type = ui->tableTreeWidget->currentItem()->type();
    }

    switch (type) {
    case table_type_:
        header_labels << tr("Table Name") << tr("Selector Name");
        break;
    case string_type_:
            header_labels << tr("String") << tr("Dissector");
            break;
    case integer_type_:
            header_labels << tr("Port") << tr("Dissector");
            break;
    case custom_type_:
            header_labels << tr("String") << tr("Dissector");
            break;
    case heuristic_type_:
            header_labels << tr("Protocol") << tr("Short Name");
            break;
    case top_level_type_:
            header_labels << tr("Table Type") << QString();
            break;
    }

    ui->tableTreeWidget->setHeaderLabels(header_labels);
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
