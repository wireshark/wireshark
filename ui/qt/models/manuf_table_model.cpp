/*
 * manuf_table_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "manuf_table_model.h"

ManufTableItem::ManufTableItem(struct ws_manuf *ptr) :
    short_name_(QString::fromUtf8(ptr->short_name)),
    long_name_(QString::fromUtf8(ptr->long_name))
{
    qsizetype size;
    switch (ptr->mask) {
        case 24:
            size = 3;
            break;
        case 28:
            size = 4;
            break;
        case 36:
            size = 5;
            break;
        default:
            ws_assert_not_reached();
    }
    // Note: since 'ptr' is not stable, a deep copy is needed.
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    block_bytes_ = QByteArray(reinterpret_cast<const char *>(ptr->block), size);
#else
    block_bytes_ = QByteArray(reinterpret_cast<const char *>(ptr->block), static_cast<int>(size));
#endif

    char buf[64];
    block_name_ = QString::fromUtf8(ws_manuf_block_str(buf, sizeof(buf), ptr));
}

ManufTableItem::~ManufTableItem()
{
}

ManufTableModel::ManufTableModel(QObject *parent) : QAbstractTableModel(parent)
{
    ws_manuf_iter_t iter;
    struct ws_manuf item;

    ws_manuf_iter_init(&iter);
    while (ws_manuf_iter_next(&iter, &item)) {
        rows_.append(new ManufTableItem(&item));
    }
}

ManufTableModel::~ManufTableModel()
{
    clear();
}

int ManufTableModel::rowCount(const QModelIndex &) const
{
    return static_cast<int>(rows_.count());
}

int ManufTableModel::columnCount(const QModelIndex &) const
{
    return NUM_COLS;
}

QVariant ManufTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    if (index.row() >= rows_.size())
        return QVariant();

    ManufTableItem *item = rows_.at(index.row());
    if (index.column() >= NUM_COLS)
        return QVariant();

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case COL_MAC_PREFIX:
                return item->block_name_;
            case COL_SHORT_NAME:
                return item->short_name_;
            case COL_VENDOR_NAME:
                return item->long_name_;
            default:
                return QVariant();
        }
    }

    if (role == Qt::UserRole) {
        switch (index.column()) {
            case COL_MAC_PREFIX:
                return item->block_bytes_;
            case COL_SHORT_NAME:
                return item->short_name_;
            case COL_VENDOR_NAME:
                return item->long_name_;
            default:
                return QVariant();
        }
    }

    return QVariant();
}

void ManufTableModel::addRecord(struct ws_manuf *ptr)
{
    emit beginInsertRows(QModelIndex(), rowCount(), rowCount());
    ManufTableItem *item = new ManufTableItem(ptr);
    rows_.append(item);
    emit endInsertRows();
}

void ManufTableModel::clear()
{
    if (!rows_.isEmpty()) {
        emit beginRemoveRows(QModelIndex(), 0, rowCount() - 1);
        qDeleteAll(rows_.begin(), rows_.end());
        rows_.clear();
        emit endRemoveRows();
    }
}

QVariant ManufTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole)
        return QVariant();

    if (orientation == Qt::Horizontal) {
        switch (section) {
            case COL_MAC_PREFIX:
                return QString(tr("Address Block"));
            case COL_SHORT_NAME:
                return QString(tr("Short Name"));
            case COL_VENDOR_NAME:
                return QString(tr("Vendor Name"));
        }
    }

    return QVariant();
}


ManufSortFilterProxyModel::ManufSortFilterProxyModel(QObject* parent) :
    QSortFilterProxyModel(parent),
    filter_type_(FilterEmpty)
{
}

void ManufSortFilterProxyModel::clearFilter()
{
    if (filter_type_ == FilterEmpty)
        return;
    filter_type_ = FilterEmpty;
    invalidateFilter();
}

void ManufSortFilterProxyModel::setFilterAddress(const QByteArray &bytes)
{
    filter_type_ = FilterByAddress;
    filter_bytes_ = bytes;
    invalidateFilter();
}

void ManufSortFilterProxyModel::setFilterName(QRegularExpression &name)
{
    filter_type_ = FilterByName;
    filter_name_ = name;
    invalidateFilter();
}

static bool match_filter(const QByteArray &bytes, const QByteArray &mac_block)
{
    if (bytes.size() < mac_block.size())
        return mac_block.startsWith(bytes);

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    QByteArray prefix = bytes.first(mac_block.size());
#else
    QByteArray prefix = bytes.left(mac_block.size());
#endif
    // Blocks are 3, 4 or 5 bytes wide
    if (mac_block.size() > 3) {
        // Mask out the last nibble of the bytes for 28 and 36 bit block lengths
        // (but not 24 bit OUIs)
        prefix[prefix.size() - 1] = prefix[prefix.size() - 1] & 0xF0;
    }
    return prefix == mac_block;
}

bool ManufSortFilterProxyModel::filterAddressAcceptsRow(int source_row, const QModelIndex& source_parent) const
{
    QModelIndex chkIdx = sourceModel()->index(source_row, ManufTableModel::COL_MAC_PREFIX, source_parent);
    QByteArray mac_block = chkIdx.data(Qt::UserRole).toByteArray();
    return match_filter(filter_bytes_, mac_block);
}

bool ManufSortFilterProxyModel::filterNameAcceptsRow(int source_row, const QModelIndex& source_parent) const
{
    QModelIndex chkIdx = sourceModel()->index(source_row, ManufTableModel::COL_VENDOR_NAME, source_parent);
    QString vendor_name = chkIdx.data(Qt::UserRole).toString();
    return filter_name_.match(vendor_name).hasMatch();
}

bool ManufSortFilterProxyModel::filterAcceptsRow(int source_row, const QModelIndex& source_parent) const
{
    switch (filter_type_) {
        case FilterEmpty:       return true;
        case FilterByAddress:   return filterAddressAcceptsRow(source_row, source_parent);
        case FilterByName:      return filterNameAcceptsRow(source_row, source_parent);
    }
    ws_error("unknown filter type %d", filter_type_);
}
