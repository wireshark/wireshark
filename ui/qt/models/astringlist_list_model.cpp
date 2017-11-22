/* astringlist_list_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <QSortFilterProxyModel>
#include <QStringList>

#include <ui/qt/models/astringlist_list_model.h>

AStringListListModel::AStringListListModel(QObject * parent):
        QAbstractItemModel(parent)
{}

AStringListListModel::~AStringListListModel() { modelData.clear(); }

void AStringListListModel::appendRow(const QStringList & data, const QModelIndex &parent)
{
    QStringList columns = headerColumns();
    if ( data.count() != columns.count() )
        return;

    emit beginInsertRows(parent, rowCount(), rowCount());
    modelData << data;
    emit endInsertRows();
}

int AStringListListModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return modelData.count();
}

int AStringListListModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return headerColumns().count();
}

QVariant AStringListListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if ( orientation == Qt::Vertical )
        return QVariant();

    QStringList columns = headerColumns();
    if ( role == Qt::DisplayRole && section < columns.count() )
        return qVariantFromValue(columns[section]);

    return QVariant();
}

QVariant AStringListListModel::data(const QModelIndex &index, int role) const
{
    if ( role != Qt::DisplayRole || ! index.isValid() || index.row() >= rowCount() )
        return QVariant();

    QStringList data = modelData.at(index.row());

    if ( index.column() < columnCount() )
        return qVariantFromValue(data.at(index.column()));

    return QVariant();
}

QModelIndex AStringListListModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);

    if ( row >= rowCount() || column >= columnCount() )
        return QModelIndex();

    return createIndex(row, column);
}

QModelIndex AStringListListModel::parent(const QModelIndex & parent) const
{
    Q_UNUSED(parent);

    return QModelIndex();
}

AStringListListSortFilterProxyModel::AStringListListSortFilterProxyModel(QObject * parent)
: QSortFilterProxyModel(parent)
{
    filter_ = QString();
    type_ = FilterByContains;
}

bool AStringListListSortFilterProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    QString leftData = sourceModel()->data(left).toStringList().join(",");
    QString rightData = sourceModel()->data(right).toStringList().join(",");

    return QString::localeAwareCompare(leftData, rightData) < 0;
}

void AStringListListSortFilterProxyModel::setFilter(const QString & filter)
{
    filter_ = filter;
    invalidateFilter();
}

bool AStringListListSortFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    bool check = false;

    if ( columnsToFilter_.count() == 0 )
        return true;

    foreach(int column, columnsToFilter_)
    {
        if ( column >= columnCount() )
            continue;

        QModelIndex chkIdx = sourceModel()->index(sourceRow, column, sourceParent);
        if ( type_ == FilterByContains && sourceModel()->data(chkIdx).toString().contains(filter_) )
            check = true;
        else if ( type_ == FilterByStart && sourceModel()->data(chkIdx).toString().startsWith(filter_) )
            check = true;

        if ( check )
            break;
    }

    return check;
}

void AStringListListSortFilterProxyModel::setFilterType(AStringListListFilterType type)
{
    if ( type != type_ )
    {
        type_ = type;
        invalidateFilter();
    }
}

void AStringListListSortFilterProxyModel::setColumnToFilter(int column)
{
    if ( column < columnCount() && ! columnsToFilter_.contains(column) )
    {
        columnsToFilter_.append(column);
        invalidateFilter();
    }
}

void AStringListListSortFilterProxyModel::clearColumnsToFilter()
{
    columnsToFilter_.clear();
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
