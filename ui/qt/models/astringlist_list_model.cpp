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

#include <ui/qt/utils/color_utils.h>

AStringListListModel::AStringListListModel(QObject * parent):
QAbstractTableModel(parent)
{}

AStringListListModel::~AStringListListModel() { display_data_.clear(); }

void AStringListListModel::appendRow(const QStringList & display_strings, const QString & row_tooltip, const QModelIndex &parent)
{
    QStringList columns = headerColumns();
    if (display_strings.count() != columns.count())
        return;

    emit beginInsertRows(parent, rowCount(), rowCount());
    display_data_ << display_strings;
    tooltip_data_ << row_tooltip;
    emit endInsertRows();
}

int AStringListListModel::rowCount(const QModelIndex &) const
{
    return static_cast<int>(display_data_.count());
}

int AStringListListModel::columnCount(const QModelIndex &parent) const
{
    if (rowCount(parent) == 0)
        return 0;

    return static_cast<int>(headerColumns().count());
}

QVariant AStringListListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Vertical)
        return QVariant();

    QStringList columns = headerColumns();
    if (role == Qt::DisplayRole && section < columns.count())
        return QVariant::fromValue(columns[section]);

    return QVariant();
}

QVariant AStringListListModel::data(const QModelIndex &index, int role) const
{
    if (! index.isValid() || index.row() >= rowCount())
        return QVariant();

    if (role == Qt::DisplayRole)
    {
        QStringList data = display_data_.at(index.row());

        if (index.column() < columnCount())
            return QVariant::fromValue(data.at(index.column()));
    }
    else if (role == Qt::ToolTipRole)
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
    types_[-1] = FilterByContains;
}

bool AStringListListSortFilterProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    QString leftData = left.data().toString();
    QString rightData = right.data().toString();

    if (numericColumns_.contains(left.column()) || numericColumns_.contains(right.column()) )
    {
        float leftD = leftData.toFloat();
        float rightD = rightData.toFloat();

        return leftD < rightD;
    }

    return leftData.compare(rightData, sortCaseSensitivity()) < 0;
}

void AStringListListSortFilterProxyModel::setFilter(const QString & filter)
{
    filter_ = filter;
    invalidateFilter();
}

static bool AContainsB(const QVariant &a, const QVariant &b, Qt::CaseSensitivity cs)
{
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    if (! a.canConvert<QString>() || ! b.canConvert<QString>())
#else
    if (! a.canConvert(QVariant::String) || ! b.canConvert(QVariant::String))
#endif
        return false;
    return a.toString().contains(b.toString(), cs);
}

static bool AStartsWithB(const QVariant &a, const QVariant &b, Qt::CaseSensitivity cs)
{
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    if (! a.canConvert<QString>() || ! b.canConvert<QString>())
#else
    if (! a.canConvert(QVariant::String) || ! b.canConvert(QVariant::String))
#endif
        return false;
    return a.toString().startsWith(b.toString(), cs);
}

static bool AIsEquivalentToB(const QVariant &a, const QVariant &b, Qt::CaseSensitivity)
{
    return a == b;
}

bool AStringListListSortFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    if (columnsToFilter_.count() == 0)
        return true;

    foreach(int column, columnsToFilter_)
    {
        if (column >= columnCount())
            continue;

        QModelIndex chkIdx = sourceModel()->index(sourceRow, column, sourceParent);
        QString dataString = chkIdx.data().toString();

        /* Default is filter by string a contains string b */
        bool (*compareFunc)(const QVariant&, const QVariant&, Qt::CaseSensitivity) = AContainsB;
        if (types_.keys().contains(column))
        {
            switch (types_.value(column, FilterByContains))
            {
            case  FilterByStart:
                compareFunc = AStartsWithB;
                break;
            case  FilterByEquivalent:
                compareFunc = AIsEquivalentToB;
                break;
            case FilterNone:
                return true;
            default:
                compareFunc = AContainsB;
                break;
            }
        }

        if (compareFunc(dataString, filter_, filterCaseSensitivity()))
            return true;
    }

    return false;
}

void AStringListListSortFilterProxyModel::setFilterType(AStringListListFilterType type, int column)
{
    if (column >= -1 && column < columnCount())
    {
        if (! types_.keys().contains(column))
        {
            types_.insert(column, type);
            invalidateFilter();
        }
        else if (types_.keys().contains(column) && type != types_[column])
        {
            types_[column] = type;
            invalidateFilter();
        }
    }
}

void AStringListListSortFilterProxyModel::setColumnToFilter(int column)
{
    if (column < columnCount() && ! columnsToFilter_.contains(column))
    {
        columnsToFilter_.append(column);
        invalidateFilter();
    }
}

void AStringListListSortFilterProxyModel::setColumnsToFilter(QList<int> columns)
{
    bool hasBeenAdded = false;

    foreach (int column, columns) {
        if (column < columnCount() && ! columnsToFilter_.contains(column)) {
            columnsToFilter_.append(column);
            hasBeenAdded = true;
        }
    }

    if (hasBeenAdded)
        invalidateFilter();
}

void AStringListListSortFilterProxyModel::clearColumnsToFilter()
{
    columnsToFilter_.clear();
    invalidateFilter();
}

void AStringListListSortFilterProxyModel::clearHiddenColumns()
{
    hiddenColumns_.clear();
    invalidateFilter();
}

void AStringListListSortFilterProxyModel::setColumnToHide(int col)
{
    if (! hiddenColumns_.contains(col) && col > -1 && sourceModel() && sourceModel()->columnCount() > col)
    {
        hiddenColumns_ << col;
        invalidateFilter();
    }
}

bool AStringListListSortFilterProxyModel::filterAcceptsColumn(int sourceColumn, const QModelIndex &sourceParent) const
{
    QModelIndex realIndex = sourceModel()->index(0, sourceColumn, sourceParent);

    if (! realIndex.isValid())
        return false;

    if (hiddenColumns_.contains(sourceColumn))
        return false;

    return true;
}

void AStringListListSortFilterProxyModel::clearNumericColumns()
{
    numericColumns_.clear();
    invalidateFilter();
}

void AStringListListSortFilterProxyModel::setColumnAsNumeric(int col)
{
    if (! numericColumns_.contains(col) && col > -1 && sourceModel() && sourceModel()->columnCount() > col)
    {
        numericColumns_ << col;
        invalidateFilter();
    }
}

AStringListListUrlProxyModel::AStringListListUrlProxyModel(QObject * parent):
        QIdentityProxyModel(parent)
{}

void AStringListListUrlProxyModel::setUrlColumn(int column)
{
    if (column < columnCount() && ! urls_.contains(column))
        urls_ << column;
}

bool AStringListListUrlProxyModel::isUrlColumn(int column) const
{
    return urls_.contains(column);
}

QVariant AStringListListUrlProxyModel::data(const QModelIndex &index, int role) const
{
    QVariant result = QIdentityProxyModel::data(index, role);

    if (role == Qt::ForegroundRole && urls_.contains(index.column())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
            && result.canConvert<QBrush>())
#else
            && result.canConvert(QVariant::Brush))
#endif
    {
        QBrush selected = result.value<QBrush>();
        selected.setColor(ColorUtils::themeLinkBrush().color());
        return selected;
    }

    return result;
}
