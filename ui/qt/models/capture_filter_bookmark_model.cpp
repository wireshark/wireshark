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
}

int CaptureFilterBookmarkModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return list_->rowCount();
}

QVariant CaptureFilterBookmarkModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= list_->rowCount())
        return QVariant();

    const QString name = list_->index(index.row(), FilterListModel::ColumnName).data().toString();
    const QString expr = list_->index(index.row(), FilterListModel::ColumnExpression).data().toString();

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

void CaptureFilterBookmarkModel::addBookmark(const QString &name, const QString &expression)
{
    if (expression.isEmpty())
        return;
    beginResetModel();
    list_->addFilter(name, expression);
    list_->saveList();
    endResetModel();
}

void CaptureFilterBookmarkModel::removeBookmark(const QString &expression)
{
    QModelIndex idx = list_->findByExpression(expression);
    if (!idx.isValid())
        return;
    beginResetModel();
    list_->removeFilter(idx);
    list_->saveList();
    endResetModel();
}

void CaptureFilterBookmarkModel::reload()
{
    beginResetModel();
    // Re-setting the type reloads the underlying store from persistence.
    list_->setFilterType(FilterListModel::Capture);
    endResetModel();
}
