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
#include <ui/qt/utils/variant_pointer.h>
#include <wsutil/file_util.h>
#include <wsutil/ws_assert.h>

#include <QVector>

static const char *DEFAULT_TABLE = "tcp.port";    // Arbitrary
static const char *DEFAULT_UI_TABLE = "TCP port";    // Arbitrary

DecodeAsItem::DecodeAsItem(const char* table_name, const void *selector) :
 tableName_(DEFAULT_TABLE),
 tableUIName_(DEFAULT_UI_TABLE),
 selectorUint_(0),
 selectorString_(""),
 selectorDCERPC_(NULL),
 default_dissector_(DECODE_AS_NONE),
 current_dissector_(DECODE_AS_NONE),
 dissector_handle_(NULL)
{
    if (table_name == nullptr)
        return;

    init(table_name, selector);
}

DecodeAsItem::DecodeAsItem(const decode_as_t *entry, const void *selector) :
 tableName_(DEFAULT_TABLE),
 tableUIName_(DEFAULT_UI_TABLE),
 selectorUint_(0),
 selectorString_(""),
 selectorDCERPC_(NULL),
 default_dissector_(DECODE_AS_NONE),
 current_dissector_(DECODE_AS_NONE),
 dissector_handle_(NULL)
{
    if (entry == nullptr)
        return;

    init(entry->table_name, selector);
}

DecodeAsItem::~DecodeAsItem()
{
}

void DecodeAsItem::init(const char* table_name, const void *selector)
{
    tableName_ = table_name;
    tableUIName_ = get_dissector_table_ui_name(tableName_);

    dissector_handle_t default_handle = NULL;
    ftenum_t selector_type = get_dissector_table_selector_type(tableName_);
    if (FT_IS_STRING(selector_type)) {
        if (selector != NULL) {
            default_handle = dissector_get_default_string_handle(tableName_, (const char*)selector);
            selectorString_ = QString((const char*)selector);
        }
    } else if (FT_IS_UINT(selector_type)) {
        if (selector != NULL) {
            selectorUint_ = GPOINTER_TO_UINT(selector);
            default_handle = dissector_get_default_uint_handle(tableName_, selectorUint_);
        }
    } else if (selector_type == FT_NONE) {
        // There is no default for an FT_NONE dissector table
    } else if (selector_type == FT_GUID) {
        /* Special handling for DCE/RPC dissectors */
        if (strcmp(tableName_, DCERPC_TABLE_NAME) == 0) {
            selectorDCERPC_ = (decode_dcerpc_bind_values_t*)(selector);
        }
    }

    if (default_handle != NULL) {
        default_dissector_ = dissector_handle_get_description(default_handle);
        // When adding a new record, we set the "current" values equal to
        // the default, so the user can easily reset the value.
        // The existing value read from the prefs file should already
        // be added to the table from reading the prefs file.
        // When reading existing values the current dissector should be
        // set explicitly to the actual current value.
        current_dissector_ = default_dissector_;
        dissector_handle_ = default_handle;
    }
}

void DecodeAsItem::setTable(const decode_as_t *entry)
{
    if (entry == nullptr)
        return;

    tableName_ = entry->table_name;
    tableUIName_ = get_dissector_table_ui_name(entry->table_name);

    /* XXX: Should the selector values be reset (e.g., to 0 and "")
     * What if someone tries to change the table to the DCERPC table?
     * That doesn't really work without the DCERPC special handling.
     */

    updateHandles();
}

void DecodeAsItem::setSelector(const QString &value)
{
    ftenum_t selector_type = get_dissector_table_selector_type(tableName_);

    if (FT_IS_STRING(selector_type)) {
        selectorString_ = value;
    } else if (FT_IS_UINT(selector_type)) {
        selectorUint_ = value.toUInt(Q_NULLPTR, 0);
    }

    updateHandles();
}

void DecodeAsItem::setDissectorHandle(dissector_handle_t handle)
{
    dissector_handle_ = handle;
    if (handle == nullptr) {
        current_dissector_ = DECODE_AS_NONE;
    } else {
        current_dissector_ = dissector_handle_get_description(handle);
    }
}

void DecodeAsItem::updateHandles()
{
    ftenum_t selector_type = get_dissector_table_selector_type(tableName_);
    dissector_handle_t default_handle = nullptr;

    if (FT_IS_STRING(selector_type)) {
        default_handle = dissector_get_default_string_handle(tableName_, qUtf8Printable(selectorString_));
    } else if (FT_IS_UINT(selector_type)) {
        default_handle = dissector_get_default_uint_handle(tableName_, selectorUint_);
    }
    if (default_handle != nullptr) {
        default_dissector_ = dissector_handle_get_description(default_handle);
    } else {
        default_dissector_ = DECODE_AS_NONE;
    }
}

DecodeAsModel::DecodeAsModel(QObject *parent, capture_file *cf) :
    QAbstractTableModel(parent),
    cap_file_(cf)
{
}

DecodeAsModel::~DecodeAsModel()
{
    foreach(DecodeAsItem* item, decode_as_items_)
        delete item;
    decode_as_items_.clear();
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
        ftenum_t selector_type = get_dissector_table_selector_type(item->tableName());
        if ((selector_type != FT_NONE) &&
            (item->selectorDCERPC() == NULL))
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
            return tr("Change behavior when the field matches this value");
        case colType:
            return tr("Field value type (and base, if Integer)");
        case colDefault:
            return tr("Default \"Decode As\" behavior");
        case colProtocol:
            return tr("Current\"Decode As\" behavior");
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
            return item->tableUIName();
        case colSelector:
        {
            ftenum_t selector_type = get_dissector_table_selector_type(item->tableName());
            if (FT_IS_UINT(selector_type)) {
                return entryString(item->tableName(), GUINT_TO_POINTER(item->selectorUint()));
            } else if (FT_IS_STRING(selector_type)) {
                return entryString(item->tableName(), (const void *)item->selectorString().toUtf8().constData());
            } else if (selector_type == FT_GUID) {
                if (item->selectorDCERPC() != NULL) {
                    return item->selectorDCERPC()->ctx_id;
                }
            }

            return DECODE_AS_NONE;
        }
        case colType:
        {
            ftenum_t selector_type = get_dissector_table_selector_type(item->tableName());

            if (FT_IS_STRING(selector_type)) {
                return tr("String");
            } else if (FT_IS_UINT(selector_type)) {
                QString type_desc = tr("Integer, base ");
                switch (get_dissector_table_param(item->tableName())) {
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
                if (item->selectorDCERPC() != NULL) {
                    return QString("ctx_id");
                } else {
                    return tr("GUID");
                }
            }
            break;
        }
        case colDefault:
            return item->defaultDissector();
        case colProtocol:
            return item->currentDissector();
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
        ws_assert_not_reached();
    }

    return QVariant();
}

int DecodeAsModel::rowCount(const QModelIndex &parent) const
{
    // there are no children
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(decode_as_items_.count());
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
                item->setTable(entry);
                //all other columns affected
                emit dataChanged(index(cur_index.row(), colSelector),
                                 index(cur_index.row(), colProtocol));
                break;
            }
        }
        }
        break;
    case DecodeAsModel::colProtocol:
    {
        dissector_handle_t handle = VariantPointer<dissector_handle>::asPtr(value);
        item->setDissectorHandle(handle);
        break;
    }
    case DecodeAsModel::colSelector:
        item->setSelector(value.toString());
        emit dataChanged(index(cur_index.row(), colDefault),
                         index(cur_index.row(), colProtocol));
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

    DecodeAsItem* item = nullptr;
    const decode_as_t *firstEntry = nullptr;

    if (cap_file_ && cap_file_->edt) {
        // Populate the new Decode As item with the last protocol layer
        // that can support Decode As and has a selector field for that
        // present in the frame.
        //
        // XXX: This treats 0 (for UInts) and empty strings the same as
        // the fields for the tables not being present at all.

        wmem_list_frame_t * protos = wmem_list_tail(cap_file_->edt->pi.layers);
        int8_t curr_layer_num_saved = cap_file_->edt->pi.curr_layer_num;
        uint8_t curr_layer_num = wmem_list_count(cap_file_->edt->pi.layers);

        while (protos != NULL && item == nullptr) {
            int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
            const char * proto_name = proto_get_protocol_filter_name(proto_id);
            for (GList *cur = decode_as_list; cur; cur = cur->next) {
                decode_as_t *entry = (decode_as_t *) cur->data;
                if (g_strcmp0(proto_name, entry->name) == 0) {
                    if (firstEntry == nullptr) {
                        firstEntry = entry;
                    }
                    ftenum_t selector_type = get_dissector_table_selector_type(entry->table_name);
                    // Pick the first value in the packet for the current
                    // layer for the table
                    // XXX: What if the Decode As table supports multiple
                    // values, but the first possible one is 0/NULL?
                    cap_file_->edt->pi.curr_layer_num = curr_layer_num;
                    void *selector = entry->values[0].build_values[0](&cap_file_->edt->pi);
                    // FT_NONE tables don't need a value
                    if (selector != NULL || selector_type == FT_NONE) {
                        item = new DecodeAsItem(entry, selector);
                        break;
                    }

                }
            }
            protos = wmem_list_frame_prev(protos);
            curr_layer_num--;
        }

        cap_file_->edt->pi.curr_layer_num = curr_layer_num_saved;
    }

    // If we didn't find an entry with a valid selector, create an entry
    // from the last table with an empty selector, or an empty entry.
    if (item == nullptr) {
        item = new DecodeAsItem(firstEntry);
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
    DecodeAsItem* item = decode_as_items_.takeAt(row);
    delete item;
    endRemoveRows();

    return true;
}

void DecodeAsModel::clearAll()
{
    if (rowCount() < 1)
        return;

    beginResetModel();
    foreach(DecodeAsItem* item, decode_as_items_)
        delete item;
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

    *dst = *src;

    QVector<int> roles;
    roles << Qt::EditRole << Qt::BackgroundRole;
    emit dataChanged(index(dst_row, 0), index(dst_row, columnCount()), roles);

    return true;
}

prefs_set_pref_e DecodeAsModel::readDecodeAsEntry(char *key, const char *value, void *private_data, bool)
{
    DecodeAsModel *model = (DecodeAsModel*)private_data;
    if (model == NULL)
        return PREFS_SET_OK;

    if (strcmp(key, DECODE_AS_ENTRY) != 0) {
        return PREFS_SET_NO_SUCH_PREF;
    }

    /* Parse into table, selector, initial, current */
    char **values = g_strsplit_set(value, ",", 4);
    DecodeAsItem *item = nullptr;

    dissector_table_t dissector_table = find_dissector_table(values[0]);

    QString tableName(values[0]);
    // Get the table values from the Decode As list because they are persistent
    for (GList *cur = decode_as_list; cur; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *) cur->data;
        if (tableName.compare(entry->table_name) == 0) {
            item = new DecodeAsItem(entry);
            break;
        }
    }

    if (item == nullptr) {
        g_strfreev(values);
        return PREFS_SET_SYNTAX_ERR;
    }

    QString selector(values[1]);
    item->setSelector(selector);

    /* The value for the default dissector in the decode_as_entries file
     * has no effect other than perhaps making the config file more
     * informative when edited manually.
     * We will actually display and reset to the programmatic default value.
     */
    item->setDissectorHandle(dissector_table_get_dissector_handle(dissector_table, values[3]));

    model->decode_as_items_ << item;
    g_strfreev(values);

    return PREFS_SET_OK;
}

bool DecodeAsModel::copyFromProfile(QString filename, const char **err)
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

QString DecodeAsModel::entryString(const char *table_name, const void *value)
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
                ws_assert_not_reached();
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
    case FT_STRINGZTRUNC:
        entry_str = (const char *)value;
        break;

    case FT_GUID:
        //avoid the assert for now
        break;

    case FT_NONE:
        //doesn't really matter, just avoiding the assert
        return "0";

    default:
        ws_assert_not_reached();
        break;
    }
    return entry_str;
}

void DecodeAsModel::fillTable()
{
    decode_as_items_.clear();
    beginResetModel();

    dissector_all_tables_foreach_changed(buildChangedList, this);
    decode_dcerpc_add_show_list(buildDceRpcChangedList, this);

    endResetModel();
}

void DecodeAsModel::setDissectorHandle(const QModelIndex &index, dissector_handle_t  dissector_handle)
{
    DecodeAsItem* item = decode_as_items_[index.row()];
    if (item != NULL)
        item->setDissectorHandle(dissector_handle);
}

void DecodeAsModel::buildChangedList(const char *table_name, ftenum_t, void *key, void *value, void *user_data)
{
    DecodeAsModel *model = (DecodeAsModel*)user_data;
    if (model == NULL)
        return;

    dissector_handle_t current_dh;
    DecodeAsItem* item = new DecodeAsItem(table_name, key);

    current_dh = dtbl_entry_get_handle((dtbl_entry_t *)value);
    item->setDissectorHandle(current_dh);

    model->decode_as_items_ << item;
}

void DecodeAsModel::buildDceRpcChangedList(void *data, void *user_data)
{
    dissector_table_t sub_dissectors;
    guid_key guid_val;
    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t *)data;

    DecodeAsModel *model = (DecodeAsModel*)user_data;
    if (model == NULL)
        return;

    DecodeAsItem* item = new DecodeAsItem(DCERPC_TABLE_NAME, binding);

    sub_dissectors = find_dissector_table(DCERPC_TABLE_NAME);

    guid_val.ver = binding->ver;
    guid_val.guid = binding->uuid;
    item->setDissectorHandle(dissector_get_guid_handle(sub_dissectors, &guid_val));

    model->decode_as_items_ << item;
}

typedef QPair<const char *, const char *> CharPtrPair;

void DecodeAsModel::gatherChangedEntries(const char *table_name,
        ftenum_t selector_type, void *key, void *value, void *user_data)
{
    DecodeAsModel *model = qobject_cast<DecodeAsModel*>((DecodeAsModel*)user_data);
    if (model == NULL)
        return;

    dissector_handle_t current = dtbl_entry_get_handle((dtbl_entry_t *)value);

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        model->changed_uint_entries_.emplaceBack(table_name, GPOINTER_TO_UINT(key), dissector_handle_get_pref_suffix(current));
#else
        model->changed_uint_entries_ << UIntEntry(table_name, GPOINTER_TO_UINT(key), dissector_handle_get_pref_suffix(current));
#endif
        break;
    case FT_NONE:
        //need to reset dissector table, so this needs to be in a changed list,
        //might as well be the uint one.
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        model->changed_uint_entries_.emplaceBack(table_name, 0, "");
#else
        model->changed_uint_entries_ << UIntEntry(table_name, 0, "");
#endif
        break;

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
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
    foreach (const auto &uint_entry, changed_uint_entries_) {
        /* Set "Decode As preferences" to default values */
        sub_dissectors = find_dissector_table(uint_entry.table);
        handle = dissector_get_uint_handle(sub_dissectors, uint_entry.key);
        if (handle != NULL) {
            module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(handle)));
            pref_value = prefs_find_preference(module, uint_entry.pref_name);
            if (pref_value != NULL) {
                module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                reset_pref(pref_value);
            }
        }

        dissector_reset_uint(uint_entry.table, uint_entry.key);
    }
    changed_uint_entries_.clear();
    foreach (CharPtrPair char_ptr_entry, changed_string_entries_) {
        dissector_reset_string(char_ptr_entry.first, char_ptr_entry.second);
    }
    changed_string_entries_.clear();

    foreach(DecodeAsItem *item, decode_as_items_) {
        decode_as_t       *decode_as_entry;

        if (item->currentDissector().isEmpty()) {
            continue;
        }

        for (GList *cur = decode_as_list; cur; cur = cur->next) {
            decode_as_entry = (decode_as_t *) cur->data;

            if (!g_strcmp0(decode_as_entry->table_name, item->tableName())) {

                ftenum_t selector_type = get_dissector_table_selector_type(item->tableName());
                const void *   selector_value;
                QByteArray byteArray;

                switch (selector_type) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                    selector_value = GUINT_TO_POINTER(item->selectorUint());
                    break;
                case FT_STRING:
                case FT_STRINGZ:
                case FT_UINT_STRING:
                case FT_STRINGZPAD:
                case FT_STRINGZTRUNC:
                    byteArray = item->selectorString().toUtf8();
                    selector_value = (const void *) byteArray.constData();
                    break;
                case FT_NONE:
                    //selector value is ignored, but dissector table needs to happen
                    selector_value = NULL;
                    break;
                case FT_GUID:
                    if (item->selectorDCERPC() != NULL) {
                        selector_value = (const void *)item->selectorDCERPC();
                    } else {
                        //TODO: Support normal GUID dissector tables
                        selector_value = NULL;
                    }
                    break;
                default:
                    continue;
                }

                if ((item->currentDissector() == item->defaultDissector())) {
                    decode_as_entry->reset_value(decode_as_entry->table_name, selector_value);
                    sub_dissectors = find_dissector_table(decode_as_entry->table_name);

                    /* For now, only numeric dissector tables can use preferences */
                    if (FT_IS_UINT(dissector_table_get_type(sub_dissectors))) {
                        if (item->dissectorHandle() != NULL) {
                            module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(item->dissectorHandle())));
                            pref_value = prefs_find_preference(module, decode_as_entry->table_name);
                            if (pref_value != NULL) {
                                module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                                prefs_remove_decode_as_value(pref_value, item->selectorUint(), true);
                            }
                        }
                    }
                    break;
                } else {
                    decode_as_entry->change_value(decode_as_entry->table_name, selector_value, item->dissectorHandle(), item->currentDissector().toUtf8().constData());
                    sub_dissectors = find_dissector_table(decode_as_entry->table_name);

                    /* For now, only numeric dissector tables can use preferences */
                    if (item->dissectorHandle() != NULL) {
                        if (FT_IS_UINT(dissector_table_get_type(sub_dissectors))) {
                            module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(item->dissectorHandle())));
                            pref_value = prefs_find_preference(module, QByteArray(decode_as_entry->table_name).append(dissector_handle_get_pref_suffix(item->dissectorHandle())));
                            if (pref_value != NULL) {
                                module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                                prefs_add_decode_as_value(pref_value, item->selectorUint(), false);
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
    prefs_apply_all();
}
