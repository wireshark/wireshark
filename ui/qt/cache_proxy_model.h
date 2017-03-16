/* cache_proxy_model.h
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

#ifndef CACHE_PROXY_MODEL_H
#define CACHE_PROXY_MODEL_H

#include <config.h>

#include <QIdentityProxyModel>
#include <QStandardItemModel>

/**
 * Caches any data read access to the source model, returning an older copy if
 * the source model is invalidated.
 *
 * Only flat data is supported at the moment, tree models (with parents) are
 * unsupported.
 */
class CacheProxyModel : public QIdentityProxyModel
{
    Q_OBJECT

public:
    CacheProxyModel(QObject *parent = 0);
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    void setSourceModel(QAbstractItemModel *newSourceModel);

private:
    mutable QStandardItemModel cache;

    bool hasModel() const { return sourceModel() != &cache; }

private slots:
    void resetCacheModel();
};
#endif
