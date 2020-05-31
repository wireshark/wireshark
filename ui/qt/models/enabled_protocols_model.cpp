/* enabled_protocols_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QSortFilterProxyModel>

#include <ui/qt/models/enabled_protocols_model.h>
#include <epan/packet.h>
#include <epan/disabled_protos.h>

#include <ui/qt/utils/variant_pointer.h>
#include "wireshark_application.h"

class ProtocolTreeItem : public EnabledProtocolItem
{
public:
    ProtocolTreeItem(protocol_t* proto, EnabledProtocolItem* parent)
        : EnabledProtocolItem(proto_get_protocol_short_name(proto), proto_get_protocol_long_name(proto), proto_is_protocol_enabled(proto), parent),
        proto_(proto)
    {

    }

    virtual ~ProtocolTreeItem() {}

protected:
    virtual void applyValuePrivate(gboolean value)
    {
        if (! proto_can_toggle_protocol(proto_get_id(proto_)) || proto_is_pino(proto_)) {
            return;
        }
        proto_set_decoding(proto_get_id(proto_), value);
    }

private:
    protocol_t* proto_;
};

class HeuristicTreeItem : public EnabledProtocolItem
{
public:
    HeuristicTreeItem(heur_dtbl_entry_t *heuristic, EnabledProtocolItem* parent)
        : EnabledProtocolItem(heuristic->short_name, heuristic->display_name, heuristic->enabled, parent),
        heuristic_table_(heuristic)
    {
        type_ = EnabledProtocolItem::Heuristic;
    }

    virtual ~HeuristicTreeItem() {}

protected:
    virtual void applyValuePrivate(gboolean value)
    {
        heuristic_table_->enabled = value;
    }

private:
    heur_dtbl_entry_t *heuristic_table_;
};


EnabledProtocolItem::EnabledProtocolItem(QString name, QString description, bool enabled, EnabledProtocolItem* parent) :
    ModelHelperTreeItem<EnabledProtocolItem>(parent),
    name_(name),
    description_(description),
    enabled_(enabled),
    enabledInit_(enabled),
    type_(EnabledProtocolItem::Standard)
{
}

EnabledProtocolItem::~EnabledProtocolItem()
{
}

EnabledProtocolItem::EnableProtocolType EnabledProtocolItem::type() const
{
    return type_;
}

bool EnabledProtocolItem::applyValue()
{
    if (enabledInit_ != enabled_) {
        applyValuePrivate(enabled_);
        return true;
    }

    return false;
}




EnabledProtocolsModel::EnabledProtocolsModel(QObject *parent) :
    QAbstractItemModel(parent),
    root_(new ProtocolTreeItem(NULL, NULL))
{
}

EnabledProtocolsModel::~EnabledProtocolsModel()
{
    delete root_;
}

int EnabledProtocolsModel::rowCount(const QModelIndex &parent) const
{
   EnabledProtocolItem *parent_item;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<EnabledProtocolItem*>(parent.internalPointer());

    if (parent_item == NULL)
        return 0;

    return parent_item->childCount();
}

int EnabledProtocolsModel::columnCount(const QModelIndex&) const
{
    return colLast;
}

QVariant EnabledProtocolsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {

        switch ((enum EnabledProtocolsColumn)section) {
        case colProtocol:
            return tr("Protocol");
        case colDescription:
            return tr("Description");
        default:
            break;
        }
    }
    return QVariant();
}

QModelIndex EnabledProtocolsModel::parent(const QModelIndex& index) const
{
    if (!index.isValid())
        return QModelIndex();

    EnabledProtocolItem* item = static_cast<EnabledProtocolItem*>(index.internalPointer());
    if (item != NULL) {
        EnabledProtocolItem* parent_item = item->parentItem();
        if (parent_item != NULL) {
            if (parent_item == root_)
                return QModelIndex();

            return createIndex(parent_item->row(), 0, parent_item);
        }
    }

    return QModelIndex();
}

QModelIndex EnabledProtocolsModel::index(int row, int column, const QModelIndex& parent) const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    EnabledProtocolItem *parent_item, *child_item;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<EnabledProtocolItem*>(parent.internalPointer());

    Q_ASSERT(parent_item);

    child_item = parent_item->child(row);
    if (child_item) {
        return createIndex(row, column, child_item);
    }

    return QModelIndex();
}

Qt::ItemFlags EnabledProtocolsModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::ItemFlags();

    Qt::ItemFlags flags = QAbstractItemModel::flags(index);
    switch(index.column())
    {
    case colProtocol:
        flags |= Qt::ItemIsUserCheckable;
        break;
    default:
        break;
    }

    return flags;
}

QVariant EnabledProtocolsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    EnabledProtocolItem* item = static_cast<EnabledProtocolItem*>(index.internalPointer());
    if (item == NULL)
        return QVariant();

    switch (role)
    {
    case Qt::DisplayRole:
        switch ((enum EnabledProtocolsColumn)index.column())
        {
        case colProtocol:
            return item->name();
        case colDescription:
            return item->description();
        default:
            break;
        }
        break;
    case Qt::CheckStateRole:
        switch ((enum EnabledProtocolsColumn)index.column())
        {
        case colProtocol:
            return item->enabled() ? Qt::Checked : Qt::Unchecked;
        default:
            break;
        }
        break;
    case DATA_PROTOCOL_TYPE:
        return QVariant::fromValue(item->type());
        break;
    default:
    break;
    }

    return QVariant();
}

bool EnabledProtocolsModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (!index.isValid())
        return false;

    if ((role != Qt::EditRole) &&
        ((index.column() == colProtocol) && (role != Qt::CheckStateRole)))
        return false;

    if (data(index, role) == value) {
        // Data appears unchanged, do not do additional checks.
        return true;
    }

    EnabledProtocolItem* item = static_cast<EnabledProtocolItem*>(index.internalPointer());
    if (item == NULL)
        return false;

    item->setEnabled(value == Qt::Checked ? true : false);

    QVector<int> roles;
    roles << role;

    emit dataChanged(index, index, roles);

    return true;
}

static void addHeuristicItem(gpointer data, gpointer user_data)
{
    heur_dtbl_entry_t* heur = (heur_dtbl_entry_t*)data;
    ProtocolTreeItem* protocol_item = (ProtocolTreeItem*)user_data;

    HeuristicTreeItem* heuristic_row = new HeuristicTreeItem(heur, protocol_item);
    protocol_item->prependChild(heuristic_row);
}

void EnabledProtocolsModel::populate()
{
    void *cookie;
    protocol_t *protocol;

    emit beginResetModel();

    // Iterate over all the protocols
    for (int i = proto_get_first_protocol(&cookie); i != -1; i = proto_get_next_protocol(&cookie))
    {
        if (proto_can_toggle_protocol(i))
        {
            protocol = find_protocol_by_id(i);
            ProtocolTreeItem* protocol_row = new ProtocolTreeItem(protocol, root_);
            root_->prependChild(protocol_row);

            proto_heuristic_dissector_foreach(protocol, addHeuristicItem, protocol_row);
        }
    }

    emit endResetModel();
}

void EnabledProtocolsModel::applyChanges(bool writeChanges)
{
    bool redissect = false;

    for (int proto_index = 0; proto_index < root_->childCount(); proto_index++) {
        EnabledProtocolItem* proto = root_->child(proto_index);
        redissect |= proto->applyValue();
        for (int heur_index = 0; heur_index < proto->childCount(); heur_index++) {
            EnabledProtocolItem* heur = proto->child(heur_index);
            redissect |= heur->applyValue();
        }
    }

    if (redissect) {
        saveChanges(writeChanges);
    }
}

void EnabledProtocolsModel::disableProtocol(struct _protocol *protocol)
{
    ProtocolTreeItem disabled_proto(protocol, NULL);
    disabled_proto.setEnabled(false);
    if (disabled_proto.applyValue()) {
        saveChanges();
    }
}

void EnabledProtocolsModel::saveChanges(bool writeChanges)
{
    if (writeChanges) {
        save_enabled_and_disabled_lists();
    }
    wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
}


EnabledProtocolsProxyModel::EnabledProtocolsProxyModel(QObject * parent)
: QSortFilterProxyModel(parent),
type_(EnabledProtocolsProxyModel::EveryWhere),
protocolType_(EnabledProtocolItem::Any),
filter_()
{}

bool EnabledProtocolsProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    //Use EnabledProtocolItem directly for better performance
    EnabledProtocolItem* left_item = static_cast<EnabledProtocolItem*>(left.internalPointer());
    EnabledProtocolItem* right_item = static_cast<EnabledProtocolItem*>(right.internalPointer());

    if ((left_item != NULL) && (right_item != NULL)) {

        int compare_ret = 0;

        if (left.column() == EnabledProtocolsModel::colProtocol)
            compare_ret = left_item->name().compare(right_item->name(), Qt::CaseInsensitive);
        else if (left.column() == EnabledProtocolsModel::colDescription)
            compare_ret = left_item->description().compare(right_item->description(), Qt::CaseInsensitive);

        if (compare_ret < 0)
            return true;
    }

    return false;
}

Qt::ItemFlags EnabledProtocolsProxyModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags flags = Qt::NoItemFlags;
    if (index.isValid())
    {
        QModelIndex source = mapToSource(index);
        if (filterAcceptsSelf(source.row(), source.parent()) )
        {
            flags = Qt::ItemIsEnabled;
            flags |= Qt::ItemIsSelectable;
            flags |= Qt::ItemIsUserCheckable;
        }
    }

    return flags;
}

bool EnabledProtocolsProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    if (filterAcceptsSelf(sourceRow, sourceParent))
        return true;

#if 0
    QModelIndex parent = sourceParent;
    while (parent.isValid())
    {
        if (filterAcceptsSelf(parent.row(), parent.parent()))
            return true;
        parent = parent.parent();
    }
#endif

    if (filterAcceptsChild(sourceRow, sourceParent))
        return true;

    return false;
}

bool EnabledProtocolsProxyModel::filterAcceptsSelf(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex nameIdx = sourceModel()->index(sourceRow, EnabledProtocolsModel::colProtocol, sourceParent);
    if (! nameIdx.isValid())
        return false;
    EnabledProtocolItem* item = static_cast<EnabledProtocolItem*>(nameIdx.internalPointer());
    if (! item)
        return false;

    QRegExp regex(filter_, Qt::CaseInsensitive);

    if ((type_ != EnabledProtocolsProxyModel::EnabledItems && type_ != EnabledProtocolsProxyModel::DisabledItems) &&
        (protocolType_ == EnabledProtocolItem::Any || protocolType_ == item->type()) )
    {
        if (! filter_.isEmpty())
        {
            if (item->name().contains(regex) && type_ != OnlyDescription)
                return true;

            if (item->description().contains(regex) && type_ != OnlyProtocol)
                return true;
        }
        else
            return true;
    }
    else if (type_ == EnabledProtocolsProxyModel::EnabledItems && item->enabled())
        return true;
    else if (type_ == EnabledProtocolsProxyModel::DisabledItems && ! item->enabled())
        return true;

    return false;
}

bool EnabledProtocolsProxyModel::filterAcceptsChild(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex item = sourceModel()->index(sourceRow, EnabledProtocolsModel::colProtocol, sourceParent);
    if (! item.isValid())
        return false;

    int childCount = item.model()->rowCount(item);
    if (childCount == 0)
        return false;

    for (int i = 0; i < childCount; i++)
    {
        if (filterAcceptsSelf(i, item))
            return true;
#if 0
        /* Recursive search disabled for performance reasons */
        if (filterAcceptsChild(i, item))
            return true;
#endif
    }

    return false;
}

void EnabledProtocolsProxyModel::setFilter(const QString& filter, EnabledProtocolsProxyModel::SearchType type,
    EnabledProtocolItem::EnableProtocolType protocolType)
{
    filter_ = filter;
    type_ = type;
    protocolType_ = protocolType;
    invalidateFilter();
}

void EnabledProtocolsProxyModel::setItemsEnable(EnabledProtocolsProxyModel::EnableType enableType, QModelIndex parent)
{
    if (! sourceModel())
        return;

    if (! parent.isValid())
        emit beginResetModel();

    for (int row = 0; row < rowCount(parent); row++)
    {
        QModelIndex idx = index(row, EnabledProtocolsModel::colProtocol, parent);

        QModelIndex sIdx = mapToSource(idx);
        if (sIdx.isValid())
        {
            EnabledProtocolItem* item = static_cast<EnabledProtocolItem*>(sIdx.internalPointer());
            if (item && (protocolType_ == EnabledProtocolItem::Any || protocolType_ == item->type()) )
            {
                Qt::CheckState enable = idx.data(Qt::CheckStateRole).value<Qt::CheckState>();
                if (enableType == Enable)
                    enable = Qt::Checked;
                else if (enableType == Disable)
                    enable = Qt::Unchecked;
                else
                    enable = enable == Qt::Checked ? Qt::Unchecked : Qt::Checked;

                sourceModel()->setData(mapToSource(idx), QVariant::fromValue(enable), Qt::CheckStateRole);
            }
        }

        setItemsEnable(enableType, idx);
    }


    if (! parent.isValid())
        emit endResetModel();
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
