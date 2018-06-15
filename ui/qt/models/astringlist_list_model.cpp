/* astringlist_list_model.cpp
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

#include <ui/qt/models/astringlist_list_model.h>

AStringListListModel::AStringListListModel(QObject * parent):
QAbstractTableModel(parent)
{}

AStringListListModel::~AStringListListModel() { display_data_.clear(); }

void AStringListListModel::appendRow(const QStringList & display_strings, const QString & row_tooltip, const QModelIndex &parent)
{
    QStringList columns = headerColumns();
    if ( display_strings.count() != columns.count() )
        return;

    emit beginInsertRows(parent, rowCount(), rowCount());
    display_data_ << display_strings;
    tooltip_data_ << row_tooltip;
    emit endInsertRows();
}

int AStringListListModel::rowCount(const QModelIndex &) const
{
    return display_data_.count();
}

int AStringListListModel::columnCount(const QModelIndex &parent) const
{
    if ( rowCount(parent) == 0 )
        return 0;

    return headerColumns().count();
}

QVariant AStringListListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if ( orientation == Qt::Vertical )
        return QVariant();

    QStringList columns = headerColumns();
    if ( role == Qt::DisplayRole && section < columns.count() )
        return QVariant::fromValue(columns[section]);

    return QVariant();
}

QVariant AStringListListModel::data(const QModelIndex &index, int role) const
{
    if ( ! index.isValid() || index.row() >= rowCount() )
        return QVariant();

    if ( role == Qt::DisplayRole )
    {
        QStringList data = display_data_.at(index.row());

        if ( index.column() < columnCount() )
            return QVariant::fromValue(data.at(index.column()));
    }
    else if ( role == Qt::ToolTipRole )
    {
        QString tooltip = tooltip_data_.at(index.row());
        if (!tooltip.isEmpty()) {
            return tooltip;
        }
    }

    return QVariant();
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

    return leftData.compare(rightData, sortCaseSensitivity()) < 0;
}

void AStringListListSortFilterProxyModel::setFilter(const QString & filter)
{
    filter_ = filter;
    invalidateFilter();
}

static bool AContainsB(const QString &a, const QString &b, Qt::CaseSensitivity cs)
{
    return a.contains(b, cs);
}

static bool AStartsWithB(const QString &a, const QString &b, Qt::CaseSensitivity cs)
{
    return a.startsWith(b, cs);
}

bool AStringListListSortFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    if ( columnsToFilter_.count() == 0 )
        return true;

    foreach(int column, columnsToFilter_)
    {
        if ( column >= columnCount() )
            continue;

        QModelIndex chkIdx = sourceModel()->index(sourceRow, column, sourceParent);
        QString dataString = sourceModel()->data(chkIdx).toString();

        /* Default is filter by string a contains string b */
        bool (*compareFunc)(const QString&, const QString&, Qt::CaseSensitivity) = AContainsB;
        if ( type_ == FilterByStart )
            compareFunc = AStartsWithB;

        if ( compareFunc(dataString, filter_, filterCaseSensitivity()) )
            return true;
    }

    return false;
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

AStringListListUrlProxyModel::AStringListListUrlProxyModel(QObject * parent):
        QIdentityProxyModel(parent)
{}

void AStringListListUrlProxyModel::setUrlColumn(int column)
{
    if ( column < columnCount() && ! urls_.contains(column) )
        urls_ << column;
}

bool AStringListListUrlProxyModel::isUrlColumn(int column) const
{
    return urls_.contains(column);
}

QVariant AStringListListUrlProxyModel::data(const QModelIndex &index, int role) const
{
    QVariant result = QIdentityProxyModel::data(index, role);

    if ( urls_.contains(index.column()) )
    {
        if ( role == Qt::ForegroundRole )
        {
            if ( result.canConvert(QVariant::Brush) )
            {
                QBrush selected = result.value<QBrush>();
                selected.setColor(QApplication::palette().link().color());
                return selected;
            }
        } else if ( role == Qt::TextColorRole ) {
            return QApplication::palette().link().color();
        }
    }

    return result;
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
