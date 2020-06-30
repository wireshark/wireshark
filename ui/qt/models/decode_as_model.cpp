/* decode_as_model.cpp
 * Data model for Decode As records.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>

#include "decode_as_model.h"
#include <epan/to_str.h>
#include <epan/decode_as.h>
#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/dissectors/packet-dcerpc.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <wsutil/file_util.h>

#include <QVector>

static const char *DEFAULT_TABLE = "tcp.port";    // Arbitrary
static const char *DEFAULT_UI_TABLE = "TCP port";    // Arbitrary

DecodeAsItem::DecodeAsItem()
 : tableName_(DEFAULT_TABLE),
 tableUIName_(DEFAULT_UI_TABLE),
 selectorUint_(0),
 selectorString_(""),
 selectorDCERPC_(NULL),
 default_proto_(DECODE_AS_NONE),
 current_proto_(DECODE_AS_NONE),
 dissector_handle_(NULL)
{
}

DecodeAsItem::~DecodeAsItem()
{
}


DecodeAsModel::DecodeAsModel(QObject *parent, capture_file *cf) :
    QAbstractTableModel(parent),
    cap_file_(cf)
{
}

Qt::ItemFlags DecodeAsModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::ItemFlags();

    DecodeAsItem* item = decode_as_items_[index.row()];

    Qt::ItemFlags flags = QAbstractTableModel::flags(index);
    switch(index.column())
    {
    case DecodeAsModel::colTable:
    case DecodeAsModel::colProtocol:
        flags |= Qt::ItemIsEditable;
        break;
    case DecodeAsModel::colSelector:
        {
        ftenum_t selector_type = get_dissector_table_selector_type(item->tableName_);
        if ((selector_type != FT_NONE) &&
            (item->selectorDCERPC_ == NULL))
            flags |= Qt::ItemIsEditable;
        break;
        }
    }

    return flags;
}

QVariant DecodeAsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return QVariant();
    }

    DecodeAsItem* item;

    switch (role)
    {
    case Qt::ToolTipRole:
        switch (index.column())
        {
        case colTable:
            return tr("Match using this field");
        case colSelector:
            return tr("Current\"Decode As\" behavior");
        case colType:
            return QVariant();
        case colDefault:
            return tr("Default \"Decode As\" behavior");
        case colProtocol:
            return tr("Change behavior when the protocol field matches this value");
        }
        return QVariant();
    case Qt::DisplayRole:
    case Qt::EditRole:
        item = decode_as_items_[index.row()];
        if (item == NULL)
            return QVariant();

        switch (index.column())
        {
        case colTable:
            return item->tableUIName_;
        case colSelector:
        {
            ftenum_t selector_type = get_dissector_table_selector_type(item->tableName_);
            if (IS_FT_UINT(selector_type)) {
                return entryString(item->tableName_, GUINT_TO_POINTER(item->selectorUint_));
            } else if (IS_FT_STRING(selector_type)) {
                return entryString(item->tableName_, (gconstpointer)item->selectorString_.toUtf8().constData());
            } else if (selector_type == FT_GUID) {
                if (item->selectorDCERPC_ != NULL) {
                    return item->selectorDCERPC_->ctx_id;
                }
            }

            return DECODE_AS_NONE;
        }
        case colType:
        {
            ftenum_t selector_type = get_dissector_table_selector_type(item->tableName_);

            if (IS_FT_STRING(selector_type)) {
                return tr("String");
            } else if (IS_FT_UINT(selector_type)) {
                QString type_desc = tr("Integer, base ");
                switch (get_dissector_table_param(item->tableName_)) {
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
                return type_desc;
            } else if (selector_type == FT_NONE) {
                return tr("<none>");
            } else if (selector_type == FT_GUID) {
                if (item->selectorDCERPC_ != NULL) {
                    return QString("ctx_id");
                } else {
                    return tr("GUID");
                }
            }
            break;
        }
        case colDefault:
            return item->default_proto_;
        case colProtocol:
            return item->current_proto_;
        }
        return QVariant();

    case Qt::UserRole:
        item = decode_as_items_[index.row()];
        return QVariant::fromValue(static_cast<void *>(item));
    }

    return QVariant();
}

QVariant DecodeAsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return QVariant();

    switch (section) {
    case colTable:
        return tr("Field");
    case colSelector:
        return tr("Value");
    case colType:
        return tr("Type");
    case colDefault:
        return tr("Default");
    case colProtocol:
        return tr("Current");
    default:
        g_assert_not_reached();
    }

    return QVariant();
}

int DecodeAsModel::rowCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return decode_as_items_.count();
}

int DecodeAsModel::columnCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return colDecodeAsMax;
}

bool DecodeAsModel::setData(const QModelIndex &cur_index, const QVariant &value, int role)
{
    if (!cur_index.isValid())
        return false;

    if (role != Qt::EditRole)
        return false;

    if (data(cur_index, role) == value) {
        // Data appears unchanged, do not do additional checks.
        return true;
    }

    DecodeAsItem* item = decode_as_items_[cur_index.row()];

    switch(cur_index.column())
    {
    case DecodeAsModel::colTable:
        {
        QString valueStr = value.toString();
        //grab the table values from the Decode As list because they are persistent
        for (GList *cur = decode_as_list; cur; cur = cur->next) {
            decode_as_t *entry = (decode_as_t *) cur->data;
            if (valueStr.compare(get_dissector_table_ui_name(entry->table_name)) == 0) {
                item->tableName_ = entry->table_name;
                item->tableUIName_ = get_dissector_table_ui_name(entry->table_name);

                //all other columns affected
                emit dataChanged(index(cur_index.row(), colSelector),
                                 index(cur_index.row(), colProtocol));

            }
        }
        }
        break;
    case DecodeAsModel::colProtocol:
        item->current_proto_ = value.toString();
        break;
    case DecodeAsModel::colSelector:
        {
        ftenum_t selector_type = get_dissector_table_selector_type(item->tableName_);

        if (IS_FT_STRING(selector_type)) {
            item->selectorString_ = value.toString();
        } else if (IS_FT_UINT(selector_type)) {
            item->selectorUint_ = value.toString().toUInt(Q_NULLPTR, 0);
        }
        }
        break;
    }

    return true;
}

bool DecodeAsModel::insertRows(int row, int count, const QModelIndex &/*parent*/)
{
    // support insertion of just one item for now.
    if (count != 1 || row < 0 || row > rowCount())
        return false;

    beginInsertRows(QModelIndex(), row, row);

    DecodeAsItem* item = new DecodeAsItem();
    DecodeAsItem* alternativeItem = NULL;
    bool lastItemIsOk = false;

    if (cap_file_ && cap_file_->edt) {
        //populate the new Decode As item with the last protocol layer
        //that can support Decode As
        wmem_list_frame_t * protos = wmem_list_head(cap_file_->edt->pi.layers);
        gint8 curr_layer_num_saved = cap_file_->edt->pi.curr_layer_num;
        guint8 curr_layer_num = 1;

        while (protos != NULL) {
            int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
            const gchar * proto_name = proto_get_protocol_filter_name(proto_id);
            for (GList *cur = decode_as_list; cur; cur = cur->next) {
                decode_as_t *entry = (decode_as_t *) cur->data;
                if (g_strcmp0(proto_name, entry->name) == 0) {
                    dissector_handle_t dissector = NULL;
                    ftenum_t selector_type = get_dissector_table_selector_type(entry->table_name);
                    bool itemOk = false;

                    //reset the default and current protocols in case previous layer
                    //populated it and this layer doesn't have a handle for it
                    item->default_proto_ =  item->current_proto_ = DECODE_AS_NONE;

                    item->tableName_ = entry->table_name;
                    item->tableUIName_ = get_dissector_table_ui_name(entry->table_name);

                    //see if there is a default dissector that matches value
                    if (IS_FT_STRING(selector_type)) {

                        //pick the first value in the packet as the default
                        cap_file_->edt->pi.curr_layer_num = curr_layer_num;
                        gpointer selector = entry->values[0].build_values[0](&cap_file_->edt->pi);
                        if (selector != NULL) {
                            item->selectorString_ = entryString(item->tableName_, selector);
                            dissector = dissector_get_default_string_handle(entry->table_name, (const gchar*)selector);
                        } else {
                            item->selectorString_ = "";
                        }
                        itemOk = !item->selectorString_.isEmpty();

                    } else if (IS_FT_UINT(selector_type)) {

                        //pick the first value in the packet as the default
                        cap_file_->edt->pi.curr_layer_num = curr_layer_num;
                        item->selectorUint_ = GPOINTER_TO_UINT(entry->values[0].build_values[0](&cap_file_->edt->pi));
                        itemOk = item->selectorUint_ != 0;

                        dissector = dissector_get_default_uint_handle(entry->table_name, item->selectorUint_);
                    } else if (selector_type == FT_NONE) {
                        // There is no default for an FT_NONE dissector table
                        dissector = NULL;
                        itemOk = true;
                    } else if (selector_type == FT_GUID) {
                        /* Special handling for DCE/RPC dissectors */
                        if (strcmp(entry->name, "dcerpc") == 0) {
                            item->selectorDCERPC_ = (decode_dcerpc_bind_values_t*)entry->values[0].build_values[0](&cap_file_->edt->pi);
                            itemOk = true;
                        }
                    }

                    if (itemOk) {
                        if (!alternativeItem) {
                            alternativeItem = new DecodeAsItem();
                        }
                        *alternativeItem = *item;
                    }
                    lastItemIsOk = itemOk;

                    if (dissector != NULL) {
                        item->default_proto_ = dissector_handle_get_short_name(dissector);
                        //When adding a new record, "default" should equal "current", so the user can
                        //explicitly change it
                        item->current_proto_ = item->default_proto_;
                    }
                }
            }
            protos = wmem_list_frame_next(protos);
            curr_layer_num++;
        }

        cap_file_->edt->pi.curr_layer_num = curr_layer_num_saved;
    }

    // If the last item has an empty selector (e.g. an empty port number),
    // prefer an entry that has a valid selector.
    if (alternativeItem) {
        if (lastItemIsOk) {
            delete alternativeItem;
        } else {
            delete item;
            item = alternativeItem;
        }
    }
    decode_as_items_ << item;

    endInsertRows();

    return true;
}

bool DecodeAsModel::removeRows(int row, int count, const QModelIndex &/*parent*/)
{
    if (count != 1 || row < 0 || row >= rowCount())
        return false;

    beginRemoveRows(QModelIndex(), row, row);
    decode_as_items_.removeAt(row);
    endRemoveRows();

    return true;
}

void DecodeAsModel::clearAll()
{
    if (rowCount() < 1)
        return;

    beginResetModel();
    decode_as_items_.clear();
    endResetModel();
}

bool DecodeAsModel::copyRow(int dst_row, int src_row)
{
    if (src_row < 0 || src_row >= rowCount() || dst_row < 0 || dst_row >= rowCount()) {
        return false;
    }

    DecodeAsItem* src = decode_as_items_[src_row];
    DecodeAsItem* dst = decode_as_items_[dst_row];

    dst->tableName_ = src->tableName_;
    dst->tableUIName_ = src->tableUIName_;
    dst->selectorUint_ = src->selectorUint_;
    dst->selectorString_ = src->selectorString_;
    dst->selectorDCERPC_ = src->selectorDCERPC_;
    dst->default_proto_ = src->default_proto_;
    dst->current_proto_ = src->current_proto_;
    dst->dissector_handle_ = src->dissector_handle_;

    QVector<int> roles;
    roles << Qt::EditRole << Qt::BackgroundRole;
    emit dataChanged(index(dst_row, 0), index(dst_row, columnCount()), roles);

    return true;
}

prefs_set_pref_e DecodeAsModel::readDecodeAsEntry(gchar *key, const gchar *value, void *private_data, gboolean)
{
    DecodeAsModel *model = (DecodeAsModel*)private_data;
    if (model == NULL)
        return PREFS_SET_OK;

    if (strcmp(key, DECODE_AS_ENTRY) != 0) {
        return PREFS_SET_NO_SUCH_PREF;
    }

    /* Parse into table, selector, initial, current */
    gchar **values = g_strsplit_set(value, ",", 4);
    DecodeAsItem *item = new DecodeAsItem();

    dissector_table_t dissector_table = find_dissector_table(values[0]);

    QString tableName(values[0]);
    bool tableNameFound = false;
    // Get the table values from the Decode As list because they are persistent
    for (GList *cur = decode_as_list; cur; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *) cur->data;
        if (tableName.compare(entry->table_name) == 0) {
            item->tableName_ = entry->table_name;
            item->tableUIName_ = get_dissector_table_ui_name(entry->table_name);
            tableNameFound = true;
            break;
        }
    }

    if (!tableNameFound || !dissector_table) {
        delete item;
        g_strfreev(values);
        return PREFS_SET_SYNTAX_ERR;
    }

    QString selector(values[1]);
    ftenum_t selector_type = get_dissector_table_selector_type(item->tableName_);

    if (IS_FT_STRING(selector_type)) {
        item->selectorString_ = selector;
    } else if (IS_FT_UINT(selector_type)) {
        item->selectorUint_ = selector.toUInt(Q_NULLPTR, 0);
    }

    item->default_proto_ = values[2];
    item->dissector_handle_ = dissector_table_get_dissector_handle(dissector_table, values[3]);
    if (item->dissector_handle_) {
        item->current_proto_ = values[3];
    }

    model->decode_as_items_ << item;
    g_strfreev(values);

    return PREFS_SET_OK;
}

bool DecodeAsModel::copyFromProfile(QString filename, const gchar **err)
{
    FILE *fp = ws_fopen(filename.toUtf8().constData(), "r");

    if (fp == NULL) {
        *err = g_strerror(errno);
        return false;
    }

    beginInsertRows(QModelIndex(), rowCount(), rowCount());
    read_prefs_file(filename.toUtf8().constData(), fp, readDecodeAsEntry, this);
    endInsertRows();

    fclose(fp);

    return true;
}

QString DecodeAsModel::entryString(const gchar *table_name, gconstpointer value)
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
        entry_str = (const char *)value;
        break;

    case FT_GUID:
        //avoid the assert for now
        break;

    case FT_NONE:
        //doesn't really matter, just avoiding the assert
        return "0";

    default:
        g_assert_not_reached();
        break;
    }
    return entry_str;
}

void DecodeAsModel::fillTable()
{
    decode_as_items_.clear();
    emit beginResetModel();

    dissector_all_tables_foreach_changed(buildChangedList, this);
    decode_dcerpc_add_show_list(buildDceRpcChangedList, this);

    emit endResetModel();
}

void DecodeAsModel::setDissectorHandle(const QModelIndex &index, dissector_handle_t  dissector_handle)
{
    DecodeAsItem* item = decode_as_items_[index.row()];
    if (item != NULL)
        item->dissector_handle_ = dissector_handle;
}

void DecodeAsModel::buildChangedList(const gchar *table_name, ftenum_t, gpointer key, gpointer value, gpointer user_data)
{
    DecodeAsModel *model = (DecodeAsModel*)user_data;
    if (model == NULL)
        return;

    dissector_handle_t default_dh, current_dh;
    QString default_proto_name(DECODE_AS_NONE), current_proto_name(DECODE_AS_NONE);
    DecodeAsItem* item = new DecodeAsItem();
    ftenum_t selector_type = get_dissector_table_selector_type(table_name);

    item->tableName_ = table_name;
    item->tableUIName_ = get_dissector_table_ui_name(table_name);
    if (IS_FT_UINT(selector_type)) {
       item->selectorUint_ = GPOINTER_TO_UINT(key);
    } else if (IS_FT_STRING(selector_type)) {
       item->selectorString_ = entryString(table_name, key);
    }

    default_dh = dtbl_entry_get_initial_handle((dtbl_entry_t *)value);
    if (default_dh) {
        default_proto_name = dissector_handle_get_short_name(default_dh);
    }
    item->default_proto_ = default_proto_name;

    current_dh = dtbl_entry_get_handle((dtbl_entry_t *)value);
    if (current_dh) {
        current_proto_name = QString(dissector_handle_get_short_name(current_dh));
    }
    item->current_proto_ = current_proto_name;
    item->dissector_handle_ = current_dh;

    model->decode_as_items_ << item;
}

void DecodeAsModel::buildDceRpcChangedList(gpointer data, gpointer user_data)
{
    dissector_table_t sub_dissectors;
    guid_key guid_val;
    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t *)data;
    QString default_proto_name(DECODE_AS_NONE), current_proto_name(DECODE_AS_NONE);

    DecodeAsModel *model = (DecodeAsModel*)user_data;
    if (model == NULL)
        return;

    DecodeAsItem* item = new DecodeAsItem();

    item->tableName_ = "dcerpc.uuid";
    item->tableUIName_ = get_dissector_table_ui_name(item->tableName_);

    item->selectorDCERPC_ = binding;

    sub_dissectors = find_dissector_table(item->tableName_);

    guid_val.ver = binding->ver;
    guid_val.guid = binding->uuid;
    item->dissector_handle_ = dissector_get_guid_handle(sub_dissectors, &guid_val);
    if (item->dissector_handle_) {
        current_proto_name = QString(dissector_handle_get_short_name(item->dissector_handle_));
    }
    item->current_proto_ = current_proto_name;
    item->default_proto_ = default_proto_name;

    model->decode_as_items_ << item;
}

typedef QPair<const char *, guint32> UintPair;
typedef QPair<const char *, const char *> CharPtrPair;

void DecodeAsModel::gatherChangedEntries(const gchar *table_name,
        ftenum_t selector_type, gpointer key, gpointer, gpointer user_data)
{
    DecodeAsModel *model = qobject_cast<DecodeAsModel*>((DecodeAsModel*)user_data);
    if (model == NULL)
        return;

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        model->changed_uint_entries_ << UintPair(table_name, GPOINTER_TO_UINT(key));
        break;
    case FT_NONE:
        //need to reset dissector table, so this needs to be in a changed list,
        //might as well be the uint one.
        model->changed_uint_entries_ << UintPair(table_name, 0);
        break;

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        model->changed_string_entries_ << CharPtrPair(table_name, (const char *) key);
        break;
    default:
        break;
    }
}

void DecodeAsModel::applyChanges()
{
    dissector_table_t sub_dissectors;
    module_t *module;
    pref_t* pref_value;
    dissector_handle_t handle;
    // Reset all dissector tables, then apply all rules from model.

    // We can't call g_hash_table_removed from g_hash_table_foreach, which
    // means we can't call dissector_reset_{string,uint} from
    // dissector_all_tables_foreach_changed. Collect changed entries in
    // lists and remove them separately.
    //
    // If dissector_all_tables_remove_changed existed we could call it
    // instead.
    dissector_all_tables_foreach_changed(gatherChangedEntries, this);
    foreach (UintPair uint_entry, changed_uint_entries_) {
        /* Set "Decode As preferences" to default values */
        sub_dissectors = find_dissector_table(uint_entry.first);
        handle = dissector_get_uint_handle(sub_dissectors, uint_entry.second);
        if (handle != NULL) {
            module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(handle)));
            pref_value = prefs_find_preference(module, uint_entry.first);
            if (pref_value != NULL) {
                module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                reset_pref(pref_value);
            }
        }

        dissector_reset_uint(uint_entry.first, uint_entry.second);
    }
    changed_uint_entries_.clear();
    foreach (CharPtrPair char_ptr_entry, changed_string_entries_) {
        dissector_reset_string(char_ptr_entry.first, char_ptr_entry.second);
    }
    changed_string_entries_.clear();

    foreach(DecodeAsItem *item, decode_as_items_) {
        decode_as_t       *decode_as_entry;

        if (item->current_proto_.isEmpty()) {
            continue;
        }

        for (GList *cur = decode_as_list; cur; cur = cur->next) {
            decode_as_entry = (decode_as_t *) cur->data;

            if (!g_strcmp0(decode_as_entry->table_name, item->tableName_)) {

                ftenum_t selector_type = get_dissector_table_selector_type(item->tableName_);
                gconstpointer  selector_value;
                QByteArray byteArray;

                switch (selector_type) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                    selector_value = GUINT_TO_POINTER(item->selectorUint_);
                    break;
                case FT_STRING:
                case FT_STRINGZ:
                case FT_UINT_STRING:
                case FT_STRINGZPAD:
                    byteArray = item->selectorString_.toUtf8();
                    selector_value = (gconstpointer) byteArray.constData();
                    break;
                case FT_NONE:
                    //selector value is ignored, but dissector table needs to happen
                    selector_value = NULL;
                    break;
                case FT_GUID:
                    if (item->selectorDCERPC_ != NULL) {
                        selector_value = (gconstpointer)item->selectorDCERPC_;
                    } else {
                        //TODO: Support normal GUID dissector tables
                        selector_value = NULL;
                    }
                    break;
                default:
                    continue;
                }

                if ((item->current_proto_ == DECODE_AS_NONE) || !item->dissector_handle_) {
                    decode_as_entry->reset_value(decode_as_entry->table_name, selector_value);
                    sub_dissectors = find_dissector_table(decode_as_entry->table_name);

                    /* For now, only numeric dissector tables can use preferences */
                    if (IS_FT_UINT(dissector_table_get_type(sub_dissectors))) {
                        if (item->dissector_handle_ != NULL) {
                            module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(item->dissector_handle_)));
                            pref_value = prefs_find_preference(module, decode_as_entry->table_name);
                            if (pref_value != NULL) {
                                module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                                prefs_remove_decode_as_value(pref_value, item->selectorUint_, TRUE);
                            }
                        }
                    }
                    break;
                } else {
                    decode_as_entry->change_value(decode_as_entry->table_name, selector_value, &item->dissector_handle_, item->current_proto_.toUtf8().constData());
                    sub_dissectors = find_dissector_table(decode_as_entry->table_name);

                    /* For now, only numeric dissector tables can use preferences */
                    if (IS_FT_UINT(dissector_table_get_type(sub_dissectors))) {
                        module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(item->dissector_handle_)));
                        pref_value = prefs_find_preference(module, decode_as_entry->table_name);
                        if (pref_value != NULL) {
                            module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                            prefs_add_decode_as_value(pref_value, item->selectorUint_, FALSE);
                        }
                    }
                    break;
                }
            }
        }
    }
}

/* * Editor modelines
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
