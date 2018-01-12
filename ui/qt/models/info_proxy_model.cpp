/* info_proxy_model.cpp
 * Proxy model for displaying an info text at the end of any QAbstractListModel
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <config.h>

#include <ui/qt/models/info_proxy_model.h>

#include <QFont>

InfoProxyModel::InfoProxyModel(int column, QObject * parent) : QIdentityProxyModel (parent)
{
    column_ = column;
}

InfoProxyModel::~InfoProxyModel()
{
    infos_.clear();
}

void InfoProxyModel::appendInfo(QString info)
{
    if ( ! infos_.contains(info) )
        infos_ << info;
}

void InfoProxyModel::clearInfos()
{
    infos_.clear();
}

int InfoProxyModel::rowCount(const QModelIndex &parent) const
{
    return sourceModel()->rowCount(parent) + infos_.count();
}

QVariant InfoProxyModel::data (const QModelIndex &index, int role) const
{
    if ( ! index.isValid() )
        return QVariant();

    if ( index.row() < sourceModel()->rowCount() )
        return sourceModel()->data(mapToSource(index), role);

    int ifIdx = index.row() - sourceModel()->rowCount();
    if ( index.column() != column_ || ifIdx < 0 || ifIdx >= infos_.count() )
        return QVariant();

    switch ( role )
    {
    case Qt::DisplayRole:
        return infos_.at(ifIdx);
        break;
    case Qt::FontRole:
        QFont font = QIdentityProxyModel::data(index, Qt::FontRole).value<QFont>();
        font.setItalic(true);
        return font;
    }

    return QIdentityProxyModel::data(index, role);
}

Qt::ItemFlags InfoProxyModel::flags(const QModelIndex &index) const
{
    if ( index.row() < sourceModel()->rowCount() )
        return sourceModel()->flags(mapToSource(index));

    return 0;
}

QModelIndex InfoProxyModel::index(int row, int column, const QModelIndex &parent) const
{
    if ( row >= sourceModel()->rowCount() && row < rowCount() )
        return createIndex(row, column);

    return QIdentityProxyModel::index(row, column, parent);
}

QModelIndex InfoProxyModel::mapToSource(const QModelIndex &proxyIndex) const
{
    if ( ! proxyIndex.isValid() )
        return QModelIndex();

    if ( proxyIndex.row() >= sourceModel()->rowCount() )
        return QModelIndex();

    return QIdentityProxyModel::mapToSource(proxyIndex);
}

QModelIndex InfoProxyModel::mapFromSource(const QModelIndex &fromIndex) const
{
    return QIdentityProxyModel::mapFromSource(fromIndex);
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
