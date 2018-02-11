/* supported_protocols_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QSortFilterProxyModel>
#include <QStringList>
#include <QPalette>
#include <QApplication>
#include <QBrush>

#include <ui/qt/models/supported_protocols_model.h>

SupportedProtocolsItem::SupportedProtocolsItem(protocol_t* proto, const char *name, const char* filter, ftenum_t ftype, const char* descr, SupportedProtocolsItem* parent)
    : ModelHelperTreeItem<SupportedProtocolsItem>(parent),
    proto_(proto),
    name_(name),
    filter_(filter),
    ftype_(ftype),
    descr_(descr)
{
}

SupportedProtocolsItem::~SupportedProtocolsItem()
{
}


SupportedProtocolsModel::SupportedProtocolsModel(QObject *parent) :
    QAbstractItemModel(parent),
    root_(new SupportedProtocolsItem(NULL, NULL, NULL, FT_NONE, NULL, NULL)),
    field_count_(0)
{
}

SupportedProtocolsModel::~SupportedProtocolsModel()
{
    delete root_;
}

int SupportedProtocolsModel::rowCount(const QModelIndex &parent) const
{
   SupportedProtocolsItem *parent_item;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<SupportedProtocolsItem*>(parent.internalPointer());

    if (parent_item == NULL)
        return 0;

    return parent_item->childCount();
}

int SupportedProtocolsModel::columnCount(const QModelIndex&) const
{
    return colLast;
}

QVariant SupportedProtocolsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {

        switch ((enum SupportedProtocolsColumn)section) {
        case colName:
            return tr("Name");
        case colFilter:
            return tr("Filter");
        case colType:
            return tr("Type");
        case colDescription:
            return tr("Description");
        default:
            break;
        }
    }
    return QVariant();
}

QModelIndex SupportedProtocolsModel::parent(const QModelIndex& index) const
{
    if (!index.isValid())
        return QModelIndex();

    SupportedProtocolsItem* item = static_cast<SupportedProtocolsItem*>(index.internalPointer());
    if (item != NULL) {
        SupportedProtocolsItem* parent_item = item->parentItem();
        if (parent_item != NULL) {
            if (parent_item == root_)
                return QModelIndex();

            return createIndex(parent_item->row(), 0, parent_item);
        }
    }

    return QModelIndex();
}

QModelIndex SupportedProtocolsModel::index(int row, int column, const QModelIndex& parent) const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    SupportedProtocolsItem *parent_item, *child_item;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<SupportedProtocolsItem*>(parent.internalPointer());

    Q_ASSERT(parent_item);

    child_item = parent_item->child(row);
    if (child_item) {
        return createIndex(row, column, child_item);
    }

    return QModelIndex();
}

QVariant SupportedProtocolsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || role != Qt::DisplayRole)
        return QVariant();

    SupportedProtocolsItem* item = static_cast<SupportedProtocolsItem*>(index.internalPointer());
    if (item == NULL)
        return QVariant();

    switch ((enum SupportedProtocolsColumn)index.column()) {
    case colName:
        return item->name();
    case colFilter:
        return item->filter();
    case colType:
        if (index.parent().isValid())
            return QString(ftype_pretty_name(item->type()));

        return QVariant();
    case colDescription:
        return item->description();
    default:
        break;
    }

    return QVariant();
}

void SupportedProtocolsModel::populate()
{
    void *proto_cookie;
    void *field_cookie;

    emit beginResetModel();

    SupportedProtocolsItem *protoItem, *fieldItem;
    protocol_t *protocol;

    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
        proto_id = proto_get_next_protocol(&proto_cookie)) {

        protocol = find_protocol_by_id(proto_id);
        protoItem = new SupportedProtocolsItem(protocol, proto_get_protocol_short_name(protocol), proto_get_protocol_filter_name(proto_id), FT_PROTOCOL, proto_get_protocol_long_name(protocol), root_);
        root_->prependChild(protoItem);

        for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL;
             hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
            if (hfinfo->same_name_prev_id != -1)
                continue;

            fieldItem = new SupportedProtocolsItem(protocol, hfinfo->name, hfinfo->abbrev, hfinfo->type, hfinfo->blurb, protoItem);
            protoItem->prependChild(fieldItem);
            field_count_++;
        }
    }

    emit endResetModel();
}



SupportedProtocolsProxyModel::SupportedProtocolsProxyModel(QObject * parent)
: QSortFilterProxyModel(parent),
filter_()
{
}

bool SupportedProtocolsProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    //Use SupportedProtocolsItem directly for better performance
    SupportedProtocolsItem* left_item = static_cast<SupportedProtocolsItem*>(left.internalPointer());
    SupportedProtocolsItem* right_item = static_cast<SupportedProtocolsItem*>(right.internalPointer());

    if ((left_item != NULL) && (right_item != NULL)) {
        int compare_ret = left_item->name().compare(right_item->name());
        if (compare_ret < 0)
            return true;
    }

    return false;
}

bool SupportedProtocolsProxyModel::filterAcceptItem(SupportedProtocolsItem& item) const
{
    QRegExp regex(filter_, Qt::CaseInsensitive);

    if (item.name().contains(regex))
        return true;

    if (item.filter().contains(regex))
        return true;

    if (item.description().contains(regex))
        return true;

    return false;
}

bool SupportedProtocolsProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex nameIdx = sourceModel()->index(sourceRow, SupportedProtocolsModel::colName, sourceParent);
    SupportedProtocolsItem* item = static_cast<SupportedProtocolsItem*>(nameIdx.internalPointer());
    if (item == NULL)
        return true;

    if (!filter_.isEmpty()) {
        if (filterAcceptItem(*item))
            return true;

        if (!nameIdx.parent().isValid())
        {
            SupportedProtocolsItem* child_item;
            for (int row = 0; row < item->childCount(); row++)
            {
                child_item = item->child(row);
                if ((child_item != NULL) && (filterAcceptItem(*child_item)))
                    return true;
            }
        }

        return false;
    }

    return true;
}

void SupportedProtocolsProxyModel::setFilter(const QString& filter)
{
    filter_ = filter;
    invalidateFilter();
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
