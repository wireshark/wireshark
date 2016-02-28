/* decode_as_dialog.cpp
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
#include <ui_decode_as_dialog.h>

#include "epan/decode_as.h"
#include "epan/dissectors/packet-dcerpc.h"
#include "epan/epan_dissect.h"

#include "ui/decode_as_utils.h"
#include "ui/simple_dialog.h"
#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QComboBox>
#include <QFont>
#include <QFontMetrics>
#include <QLineEdit>

// To do:
// - Ranges
// - Add DCERPC support (or make DCERPC use a regular dissector table?)
// - Fix string (BER) selectors
// - Use a StyledItemDelegate to edit entries instead of managing widgets
//   by hand. See the coloring rules dialog for an example.

const int table_col_    = 0;
const int selector_col_ = 1;
const int type_col_     = 2;
const int default_col_  = 3; // aka "initial"
const int proto_col_    = 4; // aka "current"

const char *default_table_ = "TCP port";
const char *default_proto_ = DECODE_AS_NONE;
const char *default_int_selector_ = "0"; // Arbitrary
const char *default_str_selector_ = "foo"; // Arbitrary

typedef struct _dissector_info_t {
    QString             proto_name;
    dissector_handle_t  dissector_handle;
} dissector_info_t;

Q_DECLARE_METATYPE(dissector_info_t *)

typedef struct _table_item_t {
    const gchar* proto_name;
    guint8       curr_layer_num;
} table_item_t;

Q_DECLARE_METATYPE(table_item_t)

DecodeAsDialog::DecodeAsDialog(QWidget *parent, capture_file *cf, bool create_new) :
    GeometryStateDialog(parent),
    ui(new Ui::DecodeAsDialog),
    cap_file_(cf),
    table_names_combo_box_(NULL),
    selector_combo_box_(NULL),
    cur_proto_combo_box_(NULL)
{
    ui->setupUi(this);
    loadGeometry();

    setWindowTitle(wsApp->windowTitleString(tr("Decode As" UTF8_HORIZONTAL_ELLIPSIS)));
    ui->deleteToolButton->setEnabled(false);

    GList *cur;
    for (cur = decode_as_list; cur; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *) cur->data;
        QString table_ui_name = get_dissector_table_ui_name(entry->table_name);
        if (!table_ui_name.isEmpty()) {
            ui_name_to_name_[table_ui_name] = entry->table_name;
        }
    }

    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(fillTable()));
    fillTable();

    if (create_new) on_newToolButton_clicked();
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

QString DecodeAsDialog::entryString(const gchar *table_name, gpointer value)
{
    QString entry_str;
    ftenum_t selector_type = get_dissector_table_selector_type(table_name);

    switch (selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    {
        uint num_val = GPOINTER_TO_UINT(value);
        switch (get_dissector_table_param(table_name)) {

        case BASE_DEC:
            entry_str = QString::number(num_val);
            break;

        case BASE_HEX:
            int width;
            switch (selector_type) {
            case FT_UINT8:
                width = 2;
                break;
            case FT_UINT16:
                width = 4;
                break;
            case FT_UINT24:
                width = 6;
                break;
            case FT_UINT32:
                width = 8;
                break;

            default:
                g_assert_not_reached();
                break;
            }
            entry_str = QString("%1").arg(int_to_qstring(num_val, width, 16));
            break;

        case BASE_OCT:
            entry_str = "0" + QString::number(num_val, 8);
            break;
        }
        break;
    }

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        entry_str = (char *)value;
        break;

    case FT_GUID:
        //TODO: DCE/RPC dissector table
        break;

    default:
        g_assert_not_reached();
        break;
    }
    return entry_str;
}

void DecodeAsDialog::fillTable()
{
    ui->decodeAsTreeWidget->clear();
    dissector_all_tables_foreach_changed(buildChangedList, this);
    decode_dcerpc_add_show_list(buildDceRpcChangedList, this);

    if (ui->decodeAsTreeWidget->topLevelItemCount() > 0) {
        for (int i = 0; i < ui->decodeAsTreeWidget->columnCount(); i++) {
            ui->decodeAsTreeWidget->resizeColumnToContents(i);
        }
    }
}

void DecodeAsDialog::activateLastItem()
{
    int last_idx = ui->decodeAsTreeWidget->topLevelItemCount() - 1;
    if (last_idx < 0) return;

    QTreeWidgetItem *last_item = ui->decodeAsTreeWidget->invisibleRootItem()->child(last_idx);
    if (!last_item) return;

    ui->decodeAsTreeWidget->setCurrentItem(last_item);
    on_decodeAsTreeWidget_itemActivated(last_item);
}

void DecodeAsDialog::on_decodeAsTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    if (current == previous) return;

    for (int col = 0; col < ui->decodeAsTreeWidget->columnCount(); col++) {
        if (previous && ui->decodeAsTreeWidget->itemWidget(previous, col)) {
            ui->decodeAsTreeWidget->removeItemWidget(previous, col);
        }
    }
}

void DecodeAsDialog::on_decodeAsTreeWidget_itemActivated(QTreeWidgetItem *item, int)
{
    GList *cur;

    table_names_combo_box_ = new QComboBox();
    QString current_text = item->text(table_col_);
    QSet<QString> da_set;

    // If a packet is selected group its tables at the top in order
    // from last-dissected to first.

    for (cur = decode_as_list; cur; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *) cur->data;
        const char *table_name = get_dissector_table_ui_name(entry->table_name);
        if (table_name) {
            da_set.insert(get_dissector_table_ui_name(entry->table_name));
        }
    }

    if (cap_file_ && cap_file_->edt) {
        bool copying = !current_text.isEmpty();
        wmem_list_frame_t * protos = wmem_list_head(cap_file_->edt->pi.layers);
        guint8 curr_layer_num = 1;
        while (protos != NULL) {
            int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
            const gchar * proto_name = proto_get_protocol_filter_name(proto_id);
            for (cur = decode_as_list; cur; cur = cur->next) {
                decode_as_t *entry = (decode_as_t *) cur->data;
                if (g_strcmp0(proto_name, entry->name) == 0) {
                    QString table_ui_name = get_dissector_table_ui_name(entry->table_name);
                    table_item_t table_item;
                    table_item.proto_name = proto_name;
                    table_item.curr_layer_num = curr_layer_num;
                    table_names_combo_box_->insertItem(0, table_ui_name, QVariant::fromValue<table_item_t>(table_item));
                    da_set.remove(table_ui_name);
                    if (!copying) {
                        current_text = table_ui_name;
                    }
                }
            }
            protos = wmem_list_frame_next(protos);
            curr_layer_num++;
        }
    }

    if (table_names_combo_box_->count() > 0) {
        table_names_combo_box_->insertSeparator(table_names_combo_box_->count());
    }

    QList<QString> da_list = da_set.toList();
    qSort(da_list.begin(), da_list.end());

    foreach (QString table_ui_name, da_list) {
        table_names_combo_box_->addItem(table_ui_name, ui_name_to_name_[table_ui_name]);
    }

    if (current_text.isEmpty()) current_text = default_table_;
    ui->decodeAsTreeWidget->setItemWidget(item, table_col_, table_names_combo_box_);

    selector_combo_box_ = new QComboBox();
    selector_combo_box_->setEditable(true);
    selector_combo_box_->lineEdit()->setText(item->text(selector_col_));

    connect(selector_combo_box_, SIGNAL(editTextChanged(QString)), this, SLOT(selectorEditTextChanged(QString)));

    ui->decodeAsTreeWidget->setItemWidget(item, selector_col_, selector_combo_box_);

    cur_proto_combo_box_ = new QComboBox();

    ui->decodeAsTreeWidget->setItemWidget(item, proto_col_, cur_proto_combo_box_);
    connect(cur_proto_combo_box_, SIGNAL(currentIndexChanged(const QString &)),
            this, SLOT(curProtoCurrentIndexChanged(const QString &)));

    table_names_combo_box_->setCurrentIndex(table_names_combo_box_->findText(current_text));
    tableNamesCurrentIndexChanged(current_text);

    connect(table_names_combo_box_, SIGNAL(currentIndexChanged(const QString &)),
            this, SLOT(tableNamesCurrentIndexChanged(const QString &)));
    table_names_combo_box_->setFocus();
}

void DecodeAsDialog::on_decodeAsTreeWidget_itemSelectionChanged()
{
    if (ui->decodeAsTreeWidget->selectedItems().length() > 0) {
        ui->deleteToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
    } else {
        ui->deleteToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
    }
}

void DecodeAsDialog::buildChangedList(const gchar *table_name, ftenum_t, gpointer key, gpointer value, gpointer user_data)
{
    DecodeAsDialog *da_dlg = (DecodeAsDialog *)user_data;
    if (!da_dlg) return;

    dissector_handle_t default_dh, current_dh;
    QString default_proto_name = DECODE_AS_NONE, current_proto_name = DECODE_AS_NONE;
    QTreeWidgetItem *item = new QTreeWidgetItem();

    item->setText(table_col_, get_dissector_table_ui_name(table_name));
    item->setText(selector_col_, da_dlg->entryString(table_name, key));
    da_dlg->fillTypeColumn(item);

    default_dh = dtbl_entry_get_initial_handle((dtbl_entry_t *)value);
    if (default_dh) {
        default_proto_name = dissector_handle_get_short_name(default_dh);
    }
    item->setText(default_col_, default_proto_name);

    current_dh = dtbl_entry_get_handle((dtbl_entry_t *)value);
    if (current_dh) {
        current_proto_name = dissector_handle_get_short_name(current_dh);
    }
    item->setText(proto_col_, current_proto_name);

    dissector_info_t  *dissector_info = new dissector_info_t();
    dissector_info->proto_name = current_proto_name;
    dissector_info->dissector_handle = current_dh;
    item->setData(proto_col_, Qt::UserRole, QVariant::fromValue<dissector_info_t *>(dissector_info));

    da_dlg->ui->decodeAsTreeWidget->addTopLevelItem(item);
}

void DecodeAsDialog::buildDceRpcChangedList(gpointer, gpointer)
{
    //    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t *)data;
}

void DecodeAsDialog::addRecord(bool copy_from_current)
{
    QTreeWidgetItem *cur_ti = NULL;

    if (copy_from_current) {
        cur_ti = ui->decodeAsTreeWidget->currentItem();
        if (!cur_ti) return;
    }

    QTreeWidgetItem *ti = new QTreeWidgetItem();
    ui->decodeAsTreeWidget->addTopLevelItem(ti);

    if (cur_ti) {
        ti->setText(table_col_, cur_ti->text(table_col_));
        ti->setText(selector_col_, cur_ti->text(selector_col_));
        ti->setText(default_col_, cur_ti->text(default_col_));
        ti->setText(proto_col_, cur_ti->text(proto_col_));
        ti->setData(proto_col_, Qt::UserRole, cur_ti->data(proto_col_, Qt::UserRole));
    }

    activateLastItem();

    if (ui->decodeAsTreeWidget->topLevelItemCount() > 0) {
        for (int i = 0; i < ui->decodeAsTreeWidget->columnCount(); i++) {
            ui->decodeAsTreeWidget->resizeColumnToContents(i);
        }
    }
}

void DecodeAsDialog::fillTypeColumn(QTreeWidgetItem *item)
{
    if (!item) return;
    const char *table_name = ui_name_to_name_[item->text(table_col_)];

    ftenum_t selector_type = get_dissector_table_selector_type(table_name);

    if (IS_FT_STRING(selector_type)) {
        item->setText(type_col_, tr("String"));
    } else {
        QString type_desc = tr("Integer, base ");
        switch (get_dissector_table_param(table_name)) {
        case BASE_OCT:
            type_desc.append("8");
            break;
        case BASE_DEC:
            type_desc.append("10");
            break;
        case BASE_HEX:
            type_desc.append("16");
            break;
        default:
            type_desc.append(tr("unknown"));
        }
        item->setText(type_col_, type_desc);
    }
}

void DecodeAsDialog::on_newToolButton_clicked()
{
    addRecord();
}

void DecodeAsDialog::on_deleteToolButton_clicked()
{
    QTreeWidgetItem *item = ui->decodeAsTreeWidget->currentItem();
    if (!item) return;
    delete item;
}

void DecodeAsDialog::on_copyToolButton_clicked()
{
    addRecord(true);
}

void DecodeAsDialog::decodeAddProtocol(const gchar *, const gchar *proto_name, gpointer value, gpointer user_data)
{
    QSet<dissector_info_t *> *dissector_info_set = (QSet<dissector_info_t *> *)user_data;
    if (!dissector_info_set) return;

    dissector_info_t  *dissector_info = new dissector_info_t();
    dissector_info->proto_name = proto_name;
    dissector_info->dissector_handle = (dissector_handle_t) value;

    dissector_info_set->insert(dissector_info);
}

void DecodeAsDialog::tableNamesCurrentIndexChanged(const QString &text)
{
    QTreeWidgetItem *item = ui->decodeAsTreeWidget->currentItem();
    if (!item || text.isEmpty() || !selector_combo_box_ || !cur_proto_combo_box_) return;

    QString current_text = item->text(proto_col_);
    if (current_text.isEmpty()) current_text = default_proto_;

    item->setText(table_col_, text);
    fillTypeColumn(item);

    selector_combo_box_->clear();

    bool edt_present = cap_file_ && cap_file_->edt;
    QVariant variant = table_names_combo_box_->itemData(table_names_combo_box_->currentIndex());
    gint8 curr_layer_num_saved = edt_present ? cap_file_->edt->pi.curr_layer_num : 0;
    const gchar *proto_name = NULL;
    if (variant.canConvert<table_item_t>()) {
        table_item_t table_item = variant.value<table_item_t>();
        if (edt_present) {
            cap_file_->edt->pi.curr_layer_num = table_item.curr_layer_num;
        }
        proto_name = table_item.proto_name;
    }

    QSet<dissector_info_t *> dissector_info_set;
    GList *cur;
    for (cur = decode_as_list; cur; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *) cur->data;
        if (((proto_name == NULL) || (g_strcmp0(proto_name, entry->name) == 0)) &&
            (g_strcmp0(ui_name_to_name_[text], entry->table_name) == 0)) {
            if (edt_present) {
                for (uint ni = 0; ni < entry->num_items; ni++) {
                    if (entry->values[ni].num_values == 1) { // Skip over multi-value ("both") entries
                        selector_combo_box_->addItem(entryString(entry->table_name,
                                                                entry->values[ni].build_values[0](&cap_file_->edt->pi)));
                    }
                }
                selector_combo_box_->setCurrentIndex(entry->default_index_value);
            }
            entry->populate_list(entry->table_name, decodeAddProtocol, &dissector_info_set);
        }
    }
    if (edt_present) {
        cap_file_->edt->pi.curr_layer_num = curr_layer_num_saved;
    }
    if (selector_combo_box_->count() > 0) {
        selector_combo_box_->setCurrentIndex(0);
    } else {
        ftenum_t selector_type = get_dissector_table_selector_type(ui_name_to_name_[text]);
        if (IS_FT_STRING(selector_type)) {
            selector_combo_box_->setEditText(default_str_selector_);
        } else {
            selector_combo_box_->setEditText(default_int_selector_);
        }
    }

    cur_proto_combo_box_->clear();
    cur_proto_combo_box_->addItem(DECODE_AS_NONE);
    cur_proto_combo_box_->insertSeparator(cur_proto_combo_box_->count());

    QSetIterator<dissector_info_t *> i(dissector_info_set);
    while (i.hasNext()) {
        dissector_info_t  *dissector_info = i.next();

        cur_proto_combo_box_->addItem(dissector_info->proto_name, QVariant::fromValue<dissector_info_t *>(dissector_info));
    }

    cur_proto_combo_box_->model()->sort(0);
    cur_proto_combo_box_->setCurrentIndex(cur_proto_combo_box_->findText(current_text));
}

void DecodeAsDialog::selectorEditTextChanged(const QString &text)
{
    QTreeWidgetItem *item = ui->decodeAsTreeWidget->currentItem();
    if (!item || !table_names_combo_box_ || !selector_combo_box_) return;

    const char *table_name = ui_name_to_name_[table_names_combo_box_->currentText()];
    if (!table_name) return;

    item->setText(selector_col_, text);
    ftenum_t selector_type = get_dissector_table_selector_type(table_name);
    dissector_handle_t dissector;

    if (IS_FT_STRING(selector_type)) {
        dissector = dissector_get_default_string_handle(table_name, text.toUtf8().constData());
    } else {
        dissector = dissector_get_default_uint_handle(table_name, text.toInt(NULL, 0));
    }

    if (dissector) {
        item->setText(default_col_, dissector_handle_get_short_name(dissector));
    } else {
        item->setText(default_col_, DECODE_AS_NONE);
    }
}

void DecodeAsDialog::curProtoCurrentIndexChanged(const QString &text)
{
    QTreeWidgetItem *item = ui->decodeAsTreeWidget->currentItem();
    if (!item) return;
    item->setText(proto_col_, text);
    item->setData(proto_col_, Qt::UserRole, cur_proto_combo_box_->itemData(cur_proto_combo_box_->findText(text)));
}

typedef QPair<const char *, guint32> UintPair;
typedef QPair<const char *, const char *> CharPtrPair;

void DecodeAsDialog::gatherChangedEntries(const gchar *table_name,
        ftenum_t selector_type, gpointer key, gpointer, gpointer user_data)
{
    DecodeAsDialog *da_dlg = qobject_cast<DecodeAsDialog*>((DecodeAsDialog *)user_data);
    if (!da_dlg) return;

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        da_dlg->changed_uint_entries_ << UintPair(table_name, GPOINTER_TO_UINT(key));
        break;
    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        da_dlg->changed_string_entries_ << CharPtrPair(table_name, (const char *) key);
        break;
    default:
        break;
    }
}

void DecodeAsDialog::applyChanges()
{
    // Reset all dissector tables, then apply all rules from GUI.

    // We can't call g_hash_table_removed from g_hash_table_foreach, which
    // means we can't call dissector_reset_{string,uint} from
    // dissector_all_tables_foreach_changed. Collect changed entries in
    // lists and remove them separately.
    //
    // If dissector_all_tables_remove_changed existed we could call it
    // instead.
    dissector_all_tables_foreach_changed(gatherChangedEntries, this);
    foreach (UintPair uint_entry, changed_uint_entries_) {
        dissector_reset_uint(uint_entry.first, uint_entry.second);
    }
    changed_uint_entries_.clear();
    foreach (CharPtrPair char_ptr_entry, changed_string_entries_) {
        dissector_reset_string(char_ptr_entry.first, char_ptr_entry.second);
    }
    changed_string_entries_.clear();

    for (int i = 0; i < ui->decodeAsTreeWidget->topLevelItemCount(); i++) {
        QTreeWidgetItem   *item = ui->decodeAsTreeWidget->topLevelItem(i);
        ftenum_t           selector_type = get_dissector_table_selector_type(ui_name_to_name_[item->text(table_col_)]);
        dissector_info_t  *dissector_info;
        QVariant           variant = item->data(proto_col_, Qt::UserRole);
        decode_as_t       *decode_as_entry;

        if (variant == QVariant::Invalid) {
            continue;
        }

        dissector_info = variant.value<dissector_info_t *>();

        for (GList *cur = decode_as_list; cur; cur = cur->next) {
            decode_as_entry = (decode_as_t *) cur->data;

            if (!g_strcmp0(decode_as_entry->table_name, ui_name_to_name_[item->text(table_col_)])) {
                gpointer  selector_value;
                QByteArray byteArray;

                switch (selector_type) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                    selector_value = GUINT_TO_POINTER(item->text(selector_col_).toUInt(0, 0));
                    break;
                case FT_STRING:
                case FT_STRINGZ:
                case FT_UINT_STRING:
                case FT_STRINGZPAD:
                    byteArray = item->text(selector_col_).toUtf8();
                    selector_value = (gpointer) byteArray.constData();
                    break;
                default:
                    continue;
                }

                if (item->text(proto_col_) == DECODE_AS_NONE || !dissector_info->dissector_handle) {
                    decode_as_entry->reset_value(decode_as_entry->table_name, selector_value);
                    break;
                } else {
                    decode_as_entry->change_value(decode_as_entry->table_name, selector_value, &dissector_info->dissector_handle, (char *) item->text(proto_col_).toUtf8().constData());
                    break;
                }
            }
        }

        delete(dissector_info);
    }

    wsApp->queueAppSignal(WiresharkApplication::PacketDissectionChanged);
}

void DecodeAsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    switch (ui->buttonBox->standardButton(button)) {
    case QDialogButtonBox::Ok:
        applyChanges();
        break;
    case QDialogButtonBox::Save:
        {
        gchar* err = NULL;

        applyChanges();
        if (save_decode_as_entries(&err) < 0) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
            g_free(err);
        }
        }
        break;
    case QDialogButtonBox::Help:
        wsApp->helpTopicAction(HELP_DECODE_AS_SHOW_DIALOG);
        break;
    default:
        break;
    }
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
