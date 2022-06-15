/* decode_as_delegate.cpp
 * Delegates for editing various field types in a Decode As record.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "decode_as_delegate.h"

#include "epan/decode_as.h"
#include "epan/epan_dissect.h"

#include <ui/qt/utils/variant_pointer.h>

#include <QComboBox>
#include <QEvent>
#include <QLineEdit>
#include <QTreeView>

typedef struct _dissector_info_t {
    QString             proto_name;
    dissector_handle_t  dissector_handle;
} dissector_info_t;

Q_DECLARE_METATYPE(dissector_info_t *)

DecodeAsDelegate::DecodeAsDelegate(QObject *parent, capture_file *cf)
 : QStyledItemDelegate(parent),
    cap_file_(cf)
{
    cachePacketProtocols();
}

DecodeAsItem* DecodeAsDelegate::indexToField(const QModelIndex &index) const
{
    const QVariant v = index.model()->data(index, Qt::UserRole);
    return static_cast<DecodeAsItem*>(v.value<void *>());
}

void DecodeAsDelegate::cachePacketProtocols()
{
    //cache the list of potential decode as protocols in the current packet
    if (cap_file_ && cap_file_->edt) {

        wmem_list_frame_t * protos = wmem_list_head(cap_file_->edt->pi.layers);
        guint8 curr_layer_num = 1;

        while (protos != NULL) {
            int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
            const gchar * proto_name = proto_get_protocol_filter_name(proto_id);
            for (GList *cur = decode_as_list; cur; cur = cur->next) {
                decode_as_t *entry = (decode_as_t *) cur->data;
                if (g_strcmp0(proto_name, entry->name) == 0) {
                    packet_proto_data_t proto_data;

                    proto_data.table_ui_name = get_dissector_table_ui_name(entry->table_name);
                    proto_data.proto_name = proto_name;
                    proto_data.curr_layer_num = curr_layer_num;

                    packet_proto_list_.append(proto_data);
                }
            }
            protos = wmem_list_frame_next(protos);
            curr_layer_num++;
        }
    }
}

void DecodeAsDelegate::collectDAProtocols(QSet<QString>& all_protocols, QList<QString>& current_list) const
{
    // If a packet is selected group its tables at the top in order
    // from last-dissected to first.

    //gather the initial list
    for (GList *cur = decode_as_list; cur; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *) cur->data;
        const char *table_name = get_dissector_table_ui_name(entry->table_name);
        if (table_name) {
            all_protocols.insert(get_dissector_table_ui_name(entry->table_name));
        }
    }

    //filter out those in selected packet
    foreach(packet_proto_data_t proto, packet_proto_list_)
    {
        current_list.append(proto.table_ui_name);
        all_protocols.remove(proto.table_ui_name);
    }
}

//Determine if there are multiple values in the selector field that would
//correspond to using a combo box
bool DecodeAsDelegate::isSelectorCombo(DecodeAsItem* item) const
{
    const gchar *proto_name = NULL;

    foreach(packet_proto_data_t proto, packet_proto_list_)
    {
        if (g_strcmp0(proto.table_ui_name, item->tableUIName_) == 0) {
            proto_name = proto.proto_name;
            break;
        }
    }

    for (GList *cur = decode_as_list; cur; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *) cur->data;
        if ((g_strcmp0(proto_name, entry->name) == 0) &&
            (g_strcmp0(item->tableName_, entry->table_name) == 0) &&
            (cap_file_ && cap_file_->edt)) {
                return true;
        }
    }

    return false;
}

void DecodeAsDelegate::decodeAddProtocol(const gchar *, const gchar *proto_name, gpointer value, gpointer user_data)
{
    QMap<QString, dissector_info_t*>* proto_list = (QMap<QString, dissector_info_t*>*)user_data;

    if (!proto_list)
        return;

    dissector_info_t  *dissector_info = new dissector_info_t();
    dissector_info->proto_name = proto_name;
    dissector_info->dissector_handle = (dissector_handle_t) value;

    proto_list->insert(proto_name, dissector_info);
}

QWidget* DecodeAsDelegate::createEditor(QWidget *parentWidget, const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
{
    DecodeAsItem* item = indexToField(index);
    QWidget *editor = nullptr;

    switch(index.column())
    {
    case DecodeAsModel::colTable:
        {
        QComboBox *cb_editor = new QComboBox(parentWidget);
        QSet<QString> da_set;
        QList<QString> packet_list;
        QString table_ui_name;

        collectDAProtocols(da_set, packet_list);

        cb_editor->setSizeAdjustPolicy(QComboBox::AdjustToContents);

        //put the protocols from the packet first in the combo box
        foreach (table_ui_name, packet_list) {
            cb_editor->addItem(table_ui_name, table_ui_name);
        }
        if (packet_list.count() > 0) {
            cb_editor->insertSeparator(static_cast<int>(packet_list.count()));
        }

        //put the rest of the protocols in the combo box
        QList<QString> da_list = da_set.values();
        std::sort(da_list.begin(), da_list.end());

        foreach (table_ui_name, da_list) {
            cb_editor->addItem(table_ui_name, table_ui_name);
        }

        //Make sure the combo box is at least as wide as the column
        QTreeView* parentTree = (QTreeView*)parent();
        int protoColWidth = parentTree->columnWidth(index.column());
        if (protoColWidth > cb_editor->size().width())
            cb_editor->setFixedWidth(protoColWidth);

        editor = cb_editor;
        break;
        }
    case DecodeAsModel::colSelector:
        {
        QComboBox *cb_editor = NULL;
        const gchar *proto_name = NULL;
        bool edt_present = cap_file_ && cap_file_->edt;
        gint8 curr_layer_num_saved = edt_present ? cap_file_->edt->pi.curr_layer_num : 0;

        foreach(packet_proto_data_t proto, packet_proto_list_)
        {
            if (g_strcmp0(proto.table_ui_name, item->tableUIName_) == 0) {
                if (edt_present) {
                    cap_file_->edt->pi.curr_layer_num = proto.curr_layer_num;
                }
                proto_name = proto.proto_name;
                //XXX - break?  Or do we always want the last layer of tunnelled protocols?
                //XXX - Or do we want to add *all* the values from all the layers where the protocol appears to the combobox?
            }
        }

        for (GList *cur = decode_as_list; cur; cur = cur->next) {
            decode_as_t *entry = (decode_as_t *) cur->data;
            if ((g_strcmp0(proto_name, entry->name) == 0) &&
                (g_strcmp0(item->tableName_, entry->table_name) == 0)) {
                if (edt_present) {
                    //create a combobox to add the entries from the packet
                    cb_editor = new QComboBox(parentWidget);

                    //Don't limit user to just what's in combo box
                    cb_editor->setEditable(true);

                    cb_editor->setSizeAdjustPolicy(QComboBox::AdjustToContents);

                    //add the current value of the column
                    const QString& current_value = index.model()->data(index, Qt::EditRole).toString();
                    if (!current_value.isEmpty())
                        cb_editor->addItem(current_value);

                    //get the value(s) from the packet
                    for (uint ni = 0; ni < entry->num_items; ni++) {
                        if (entry->values[ni].num_values == 1) { // Skip over multi-value ("both") entries
                            QString entryStr = DecodeAsModel::entryString(entry->table_name,
                                                                    entry->values[ni].build_values[0](&cap_file_->edt->pi));
                            //don't duplicate entries
                            if (cb_editor->findText(entryStr) < 0)
                                cb_editor->addItem(entryStr);
                        }
                    }
                    cb_editor->setCurrentIndex(entry->default_index_value);

                    //Make sure the combo box is at least as wide as the column
                    QTreeView* parentTree = (QTreeView*)parent();
                    int protoColWidth = parentTree->columnWidth(index.column());
                    if (protoColWidth > cb_editor->size().width())
                        cb_editor->setFixedWidth(protoColWidth);
                }
                break;
            }
        }

        if (edt_present) {
            cap_file_->edt->pi.curr_layer_num = curr_layer_num_saved;
        }

        //if there isn't a need for a combobox, just let user have a text box for direct edit
        if (cb_editor) {
            editor = cb_editor;
        } else {
            editor = QStyledItemDelegate::createEditor(parentWidget, option, index);
        }
        break;
        }

    case DecodeAsModel::colProtocol:
        {
        QComboBox *cb_editor = new QComboBox(parentWidget);
        QMap<QString, dissector_info_t*> protocols;

        cb_editor->setSizeAdjustPolicy(QComboBox::AdjustToContents);

        for (GList *cur = decode_as_list; cur; cur = cur->next) {
            decode_as_t *entry = (decode_as_t *) cur->data;
            if (g_strcmp0(item->tableName_, entry->table_name) == 0) {
                entry->populate_list(entry->table_name, decodeAddProtocol, &protocols);
                break;
            }
        }

        cb_editor->addItem(DECODE_AS_NONE);
        cb_editor->insertSeparator(cb_editor->count());

        //QMap already sorts the keys (protocols) alphabetically
        QMap<QString, dissector_info_t*>::iterator protocol;
        for (protocol = protocols.begin(); protocol != protocols.end(); ++protocol)
        {
            cb_editor->addItem(protocol.key(), VariantPointer<dissector_info_t>::asQVariant(protocol.value()));
        }

        //Make sure the combo box is at least as wide as the column
        QTreeView* parentTree = (QTreeView*)parent();
        int protoColWidth = parentTree->columnWidth(index.column());
        if (protoColWidth > cb_editor->size().width())
            cb_editor->setFixedWidth(protoColWidth);

        editor = cb_editor;
        break;
        }
    }

    if (editor) {
        editor->setAutoFillBackground(true);
    }
    return editor;
}

void DecodeAsDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    DecodeAsItem* item = indexToField(index);

    switch(index.column())
    {
    case DecodeAsModel::colTable:
    case DecodeAsModel::colProtocol:
        {
        QComboBox *combobox = static_cast<QComboBox *>(editor);
        const QString &data = index.model()->data(index, Qt::EditRole).toString();
        combobox->setCurrentText(data);
        }
        break;
    case DecodeAsModel::colSelector:
        if (isSelectorCombo(item)) {
            QComboBox *combobox = static_cast<QComboBox *>(editor);
            const QString &data = index.model()->data(index, Qt::EditRole).toString();
            combobox->setCurrentText(data);
        }
        else {
            QStyledItemDelegate::setEditorData(editor, index);
        }
        break;
    default:
        QStyledItemDelegate::setEditorData(editor, index);
        break;
    }
}

void DecodeAsDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                              const QModelIndex &index) const
{
    DecodeAsItem* item = indexToField(index);

    switch(index.column())
    {
    case DecodeAsModel::colTable:
        {
        QComboBox *combobox = static_cast<QComboBox *>(editor);
        const QString &data = combobox->currentText();
        model->setData(index, data, Qt::EditRole);
        break;
        }
    case DecodeAsModel::colSelector:
        if (isSelectorCombo(item)) {
            QComboBox *combobox = static_cast<QComboBox *>(editor);
            const QString &data = combobox->currentText();
            model->setData(index, data, Qt::EditRole);
        } else {
            QStyledItemDelegate::setModelData(editor, model, index);
        }
        break;
    case DecodeAsModel::colProtocol:
        {
        QComboBox *combobox = static_cast<QComboBox *>(editor);
        const QString &data = combobox->currentText();
        model->setData(index, data, Qt::EditRole);

        //set the dissector handle
        QVariant var = combobox->itemData(combobox->currentIndex());
        dissector_info_t* dissector_info = VariantPointer<dissector_info_t>::asPtr(var);
        if (dissector_info != NULL) {
            ((DecodeAsModel*)model)->setDissectorHandle(index, dissector_info->dissector_handle);
        } else {
            ((DecodeAsModel*)model)->setDissectorHandle(index, NULL);
        }
        break;
        }
    default:
        QStyledItemDelegate::setModelData(editor, model, index);
        break;
    }
}

#if 0
// Qt docs suggest overriding updateEditorGeometry, but the defaults seem sane.
void UatDelegate::updateEditorGeometry(QWidget *editor,
        const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyledItemDelegate::updateEditorGeometry(editor, option, index);
}
#endif
