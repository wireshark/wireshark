/* cache_proxy_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
