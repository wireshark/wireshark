/* cache_proxy_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "cache_proxy_model.h"

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
        connect(newSourceModel, SIGNAL(modelReset()),
                this, SLOT(resetCacheModel()));
    } else {
        if (sourceModel()) {
            // Prevent further updates to source model from invalidating cache.
            disconnect(sourceModel(), SIGNAL(modelReset()),
                    this, SLOT(resetCacheModel()));
        }
        QIdentityProxyModel::setSourceModel(&cache);
    }
}

void CacheProxyModel::resetCacheModel() {
    cache.clear();
}
