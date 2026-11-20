/* capture_filter_bookmark_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/capture_filter_bookmark_model.h>
#include <ui/qt/models/filter_list_model.h>

CaptureFilterBookmarkModel::CaptureFilterBookmarkModel(QObject *parent) :
    BookmarkModel(parent),
    list_(new FilterListModel(FilterListModel::Capture, this))
{
    // Follow the filters, including the inherited filters shown once the own filters changed
    auto changed = [this]() {
        beginResetModel();
        updateRows();
        endResetModel();
    };
    connect(list_, &QAbstractItemModel::rowsInserted, this, changed);
    connect(list_, &QAbstractItemModel::rowsRemoved, this, changed);
    connect(list_, &QAbstractItemModel::dataChanged, this, changed);
    updateRows();
}

void CaptureFilterBookmarkModel::updateRows()
{
    rows_.clear();
    for (int row = 0; row < list_->rowCount(); row++) {
        if (!list_->isOverridden(row))
            rows_ << row;
    }
}

int CaptureFilterBookmarkModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return static_cast<int>(rows_.count());
}

QVariant CaptureFilterBookmarkModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= rows_.count())
        return QVariant();

    const QString name = list_->index(rows_.at(index.row()), FilterListModel::ColumnName).data().toString();
    const QString expr = list_->index(rows_.at(index.row()), FilterListModel::ColumnExpression).data().toString();

    switch (role) {
    case ExpressionRole:
    case Qt::DisplayRole:
    case Qt::EditRole:
        // Typeahead completes on the expression (the value), not the name; the
        // bookmark menu reads NameRole/ExpressionRole explicitly for its display.
        return expr;
    case NameRole:
        return name;
    default:
        return QVariant();
    }
}

bool CaptureFilterBookmarkModel::contains(const QString &expression) const
{
    return list_->findByExpression(expression).isValid();
}

bool CaptureFilterBookmarkModel::isRemovable(const QString &expression) const
{
    QModelIndex idx = list_->findByExpression(expression);
    return idx.isValid() && !list_->isInherited(idx.row());
}

void CaptureFilterBookmarkModel::addBookmark(const QString &name, const QString &expression)
{
    if (expression.isEmpty())
        return;
    list_->addFilter(name, expression);
    list_->saveList();
}

void CaptureFilterBookmarkModel::removeBookmark(const QString &expression)
{
    QModelIndex idx = list_->findByExpression(expression);
    if (!idx.isValid() || list_->isInherited(idx.row()))
        return;
    list_->removeFilter(idx);
    list_->saveList();
}

void CaptureFilterBookmarkModel::reload()
{
    beginResetModel();
    // Re-setting the type reloads the underlying store from persistence.
    list_->setFilterType(FilterListModel::Capture);
    updateRows();
    endResetModel();
}
