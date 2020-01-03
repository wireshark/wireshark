/* dissector_tables_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/dissector_tables_model.h>
#include <epan/ftypes/ftypes.h>
#include <epan/packet.h>

#include <ui/qt/utils/variant_pointer.h>
#include "wireshark_application.h"

static const char* CUSTOM_TABLE_NAME = "Custom Tables";
static const char* INTEGER_TABLE_NAME = "Integer Tables";
static const char* STRING_TABLE_NAME = "String Tables";
static const char* HEURISTIC_TABLE_NAME = "Heuristic Tables";

class IntegerTablesItem : public DissectorTablesItem
{
public:
    IntegerTablesItem(unsigned int value, QString shortName, DissectorTablesItem* parent);
    virtual ~IntegerTablesItem();

    virtual bool lessThan(DissectorTablesItem &right) const;

protected:
    unsigned int value_;
};


DissectorTablesItem::DissectorTablesItem(QString tableName, QString shortName, DissectorTablesItem* parent) :
    ModelHelperTreeItem<DissectorTablesItem>(parent),
    tableName_(tableName),
    shortName_(shortName)
{
}

DissectorTablesItem::~DissectorTablesItem()
{
}

bool DissectorTablesItem::lessThan(DissectorTablesItem &right) const
{
    if (tableName().compare(right.tableName(), Qt::CaseInsensitive) < 0)
        return true;

    return false;
}


IntegerTablesItem::IntegerTablesItem(unsigned int value, QString shortName, DissectorTablesItem* parent)
    : DissectorTablesItem(QString("%1").arg(value), shortName, parent)
    , value_(value)
{
}

IntegerTablesItem::~IntegerTablesItem()
{
}

bool IntegerTablesItem::lessThan(DissectorTablesItem &right) const
{
    if (value_ == ((IntegerTablesItem&)right).value_) {
        return DissectorTablesItem::lessThan(right);
    }

    if (value_ < ((IntegerTablesItem&)right).value_) {
        return true;
    }

    return false;
}








DissectorTablesModel::DissectorTablesModel(QObject *parent) :
    QAbstractItemModel(parent),
    root_(new DissectorTablesItem(QString("ROOT"), QString("ROOT"), NULL))
{
    populate();
}

DissectorTablesModel::~DissectorTablesModel()
{
    delete root_;
}

int DissectorTablesModel::rowCount(const QModelIndex &parent) const
{
    DissectorTablesItem *parent_item;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<DissectorTablesItem*>(parent.internalPointer());

    if (parent_item == NULL)
        return 0;

    return parent_item->childCount();
}

int DissectorTablesModel::columnCount(const QModelIndex&) const
{
    return colLast;
}

QModelIndex DissectorTablesModel::parent(const QModelIndex& index) const
{
    if (!index.isValid())
        return QModelIndex();

    DissectorTablesItem* item = static_cast<DissectorTablesItem*>(index.internalPointer());
    if (item != NULL) {
        DissectorTablesItem* parent_item = item->parentItem();
        if (parent_item != NULL) {
            if (parent_item == root_)
                return QModelIndex();

            return createIndex(parent_item->row(), 0, parent_item);
        }
    }

    return QModelIndex();
}

QModelIndex DissectorTablesModel::index(int row, int column, const QModelIndex& parent) const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    DissectorTablesItem *parent_item, *child_item;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<DissectorTablesItem*>(parent.internalPointer());

    Q_ASSERT(parent_item);

    child_item = parent_item->child(row);
    if (child_item) {
        return createIndex(row, column, child_item);
    }

    return QModelIndex();
}

QVariant DissectorTablesModel::data(const QModelIndex &index, int role) const
{
    if ((!index.isValid()) || (role != Qt::DisplayRole))
        return QVariant();

    DissectorTablesItem* item = static_cast<DissectorTablesItem*>(index.internalPointer());
    if (item == NULL)
        return QVariant();

    switch ((enum DissectorTablesColumn)index.column())
    {
    case colTableName:
        return item->tableName();
    case colShortName:
        return item->shortName();
    default:
        break;
    }

    return QVariant();
}

static void gatherProtocolDecodes(const char *, ftenum_t selector_type, gpointer key, gpointer value, gpointer item_ptr)
{
    DissectorTablesItem* pdl_ptr = (DissectorTablesItem*)item_ptr;
    if (pdl_ptr == NULL)
        return;

    dtbl_entry_t       *dtbl_entry = (dtbl_entry_t*)value;
    dissector_handle_t  handle = dtbl_entry_get_handle(dtbl_entry);
    const QString proto_name = dissector_handle_get_short_name(handle);
    DissectorTablesItem *ti = NULL;

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        ti = new IntegerTablesItem(GPOINTER_TO_UINT(key), proto_name, pdl_ptr);
        pdl_ptr->prependChild(ti);
        break;

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        ti = new DissectorTablesItem((const char *)key, proto_name, pdl_ptr);
        pdl_ptr->prependChild(ti);
        break;

    case FT_BYTES:
        ti = new DissectorTablesItem(dissector_handle_get_dissector_name(handle), proto_name, pdl_ptr);
        pdl_ptr->prependChild(ti);
        break;

    default:
        break;
    }
}

struct tables_root
{
    DissectorTablesItem* custom_table;
    DissectorTablesItem* integer_table;
    DissectorTablesItem* string_table;
};

static void gatherTableNames(const char *short_name, const char *table_name, gpointer model_ptr)
{
    struct tables_root* tables = (struct tables_root*)model_ptr;
    if (model_ptr == NULL)
        return;

    ftenum_t selector_type = get_dissector_table_selector_type(short_name);
    DissectorTablesItem *dt_ti = NULL;

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        dt_ti = new DissectorTablesItem(table_name, short_name, tables->integer_table);
        tables->integer_table->prependChild(dt_ti);
        break;
    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        dt_ti = new DissectorTablesItem(table_name, short_name, tables->string_table);
        tables->string_table->prependChild(dt_ti);
        break;
    case FT_BYTES:
        dt_ti = new DissectorTablesItem(table_name, short_name, tables->custom_table);
        tables->custom_table->prependChild(dt_ti);
        break;
    default:
        // Assert?
        return;
    }

    dissector_table_foreach(short_name, gatherProtocolDecodes, dt_ti);
}

static void gatherHeurProtocolDecodes(const char *, struct heur_dtbl_entry *dtbl_entry, gpointer list_ptr)
{
    DissectorTablesItem* hdl_ptr = (DissectorTablesItem*)list_ptr;
    if (hdl_ptr == NULL)
        return;

    if (dtbl_entry->protocol) {
        DissectorTablesItem *heur = new DissectorTablesItem(proto_get_protocol_long_name(dtbl_entry->protocol), proto_get_protocol_short_name(dtbl_entry->protocol), hdl_ptr);
        hdl_ptr->prependChild(heur);
    }
}

static void gatherHeurTableNames(const char *table_name, heur_dissector_list *list, gpointer heur_tables)
{
    DissectorTablesItem* table = (DissectorTablesItem*)heur_tables;
    if (table == NULL)
        return;

    DissectorTablesItem *heur = new DissectorTablesItem(table_name, QString(""), table);
    table->prependChild(heur);

    if (list) {
        heur_dissector_table_foreach(table_name, gatherHeurProtocolDecodes, heur);
    }
}

void DissectorTablesModel::populate()
{
    emit beginResetModel();

    struct tables_root tables;

    tables.custom_table = new DissectorTablesItem(tr(CUSTOM_TABLE_NAME), QString(""), root_);
    root_->prependChild(tables.custom_table);
    tables.integer_table = new DissectorTablesItem(tr(INTEGER_TABLE_NAME), QString(""), root_);
    root_->prependChild(tables.integer_table);
    tables.string_table = new DissectorTablesItem(tr(STRING_TABLE_NAME), QString(""), root_);
    root_->prependChild(tables.string_table);

    dissector_all_tables_foreach_table(gatherTableNames, &tables, NULL);

    DissectorTablesItem* heuristic_table = new DissectorTablesItem(tr(HEURISTIC_TABLE_NAME), QString(""), root_);
    root_->prependChild(heuristic_table);

    dissector_all_heur_tables_foreach_table(gatherHeurTableNames, heuristic_table, NULL);

    emit endResetModel();
}





DissectorTablesProxyModel::DissectorTablesProxyModel(QObject * parent)
: QSortFilterProxyModel(parent),
tableName_(tr("Table Type")),
shortName_(),
filter_()
{
}

QVariant DissectorTablesProxyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {

        switch ((enum DissectorTablesModel::DissectorTablesColumn)section) {
        case DissectorTablesModel::colTableName:
            return tableName_;
        case DissectorTablesModel::colShortName:
            return shortName_;
        default:
            break;
        }
    }
    return QVariant();
}

bool DissectorTablesProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    //Use DissectorTablesItem directly for better performance
    DissectorTablesItem* left_item = static_cast<DissectorTablesItem*>(left.internalPointer());
    DissectorTablesItem* right_item = static_cast<DissectorTablesItem*>(right.internalPointer());

    if ((left_item != NULL) && (right_item != NULL)) {
        return left_item->lessThan(*right_item);
    }

    return false;
}

bool DissectorTablesProxyModel::filterAcceptItem(DissectorTablesItem& item) const
{
    if (filter_.isEmpty())
        return true;

    if (item.tableName().contains(filter_, Qt::CaseInsensitive) || item.shortName().contains(filter_, Qt::CaseInsensitive))
        return true;

    DissectorTablesItem *child_item;
    for (int child_row = 0; child_row < item.childCount(); child_row++)
    {
        child_item = item.child(child_row);
        if ((child_item != NULL) && (filterAcceptItem(*child_item)))
            return true;
    }

    return false;
}

bool DissectorTablesProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex nameIdx = sourceModel()->index(sourceRow, DissectorTablesModel::colTableName, sourceParent);
    DissectorTablesItem* item = static_cast<DissectorTablesItem*>(nameIdx.internalPointer());
    if (item == NULL)
        return false;

    if (filterAcceptItem(*item))
        return true;

    return false;
}

void DissectorTablesProxyModel::setFilter(const QString& filter)
{
    filter_ = filter;
    invalidateFilter();
}

void DissectorTablesProxyModel::adjustHeader(const QModelIndex &currentIndex)
{
    tableName_ = tr("Table Type");
    shortName_ = QString();
    if (currentIndex.isValid() && currentIndex.parent().isValid()) {
        QString table;

        if (currentIndex.parent().parent().isValid()) {
            table = data(index(currentIndex.parent().parent().row(), DissectorTablesModel::colTableName), Qt::DisplayRole).toString();
            if ((table.compare(CUSTOM_TABLE_NAME) == 0) ||
                (table.compare(STRING_TABLE_NAME) == 0)) {
                tableName_ = tr("String");
                shortName_ = tr("Dissector");
            } else if (table.compare(INTEGER_TABLE_NAME) == 0) {
                tableName_ = tr("Integer");
                shortName_ = tr("Dissector");
            } else if (table.compare(HEURISTIC_TABLE_NAME) == 0) {
                tableName_ = tr("Protocol");
                shortName_ = tr("Short Name");
            }
        } else {
            table = data(index(currentIndex.parent().row(), DissectorTablesModel::colTableName), Qt::DisplayRole).toString();
            if ((table.compare(CUSTOM_TABLE_NAME) == 0) ||
                (table.compare(INTEGER_TABLE_NAME) == 0) ||
                (table.compare(STRING_TABLE_NAME) == 0)) {
                tableName_ = tr("Table Name");
                shortName_ = tr("Selector Name");
            } else if (table.compare(HEURISTIC_TABLE_NAME) == 0) {
                tableName_ = tr("Protocol");
                shortName_ = tr("Short Name");
            }
        }
    }


    emit headerDataChanged(Qt::Vertical, 0, 1);
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
