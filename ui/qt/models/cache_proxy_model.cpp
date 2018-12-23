/* cache_proxy_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/cache_proxy_model.h>

CacheProxyModel::CacheProxyModel(QObject *parent) : QIdentityProxyModel(parent)
{
}

QVariant CacheProxyModel::data(const QModelIndex &index, int role) const
{
    QModelIndex dataIndex = cache.index(index.row(), index.column());
    if (!dataIndex.isValid()) {
        // index is possibly outside columnCount or rowCount
        return QVariant();
    }

    if (hasModel()) {
        QVariant value = QIdentityProxyModel::data(index, role);
        cache.setData(dataIndex, value, role);
        return value;
    } else {
        return cache.data(dataIndex, role);
    }
}

Qt::ItemFlags CacheProxyModel::flags(const QModelIndex &index) const
{
    if (hasModel()) {
        return QIdentityProxyModel::flags(index);
    } else {
        // Override default to prevent editing.
        return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    }
}

QVariant CacheProxyModel::headerData(int section, Qt::Orientation orientation,
                                     int role) const
{
    if (hasModel()) {
        QVariant value = QIdentityProxyModel::headerData(section, orientation, role);
        cache.setHeaderData(section, orientation, value, role);
        return value;
    } else {
        return cache.headerData(section, orientation, role);
    }
}

int CacheProxyModel::rowCount(const QModelIndex &parent) const
{
    if (hasModel()) {
        int count = QIdentityProxyModel::rowCount(parent);
        cache.setRowCount(count);
        return count;
    } else {
        return cache.rowCount(parent);
    }
}

int CacheProxyModel::columnCount(const QModelIndex &parent) const
{
    if (hasModel()) {
        int count = QIdentityProxyModel::columnCount(parent);
        cache.setColumnCount(count);
        return count;
    } else {
        return cache.columnCount(parent);
    }
}

/**
 * Sets the source model from which data must be pulled. If newSourceModel is
 * NULL, then the cache will be used.
 */
void CacheProxyModel::setSourceModel(QAbstractItemModel *newSourceModel)
{
    if (newSourceModel) {
        cache.clear();
        QIdentityProxyModel::setSourceModel(newSourceModel);
        connect(newSourceModel, &QAbstractItemModel::modelReset,
                this, &CacheProxyModel::resetCacheModel);
    } else {
        if (sourceModel()) {
            // Prevent further updates to source model from invalidating cache.
            disconnect(sourceModel(), &QAbstractItemModel::modelReset,
                    this, &CacheProxyModel::resetCacheModel);
        }
        QIdentityProxyModel::setSourceModel(&cache);
    }
}

void CacheProxyModel::resetCacheModel() {
    cache.clear();
}
