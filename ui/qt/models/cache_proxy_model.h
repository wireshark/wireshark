/** @file
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
 * @brief Caches any data read access to the source model, returning an older copy if
 * the source model is invalidated.
 *
 * Only flat data is supported at the moment, tree models (with parents) are
 * unsupported.
 */
class CacheProxyModel : public QIdentityProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CacheProxyModel.
     * @param parent The parent QObject, defaults to 0.
     */
    CacheProxyModel(QObject *parent = 0);

    /**
     * @brief Retrieves data from the model for the given index and role.
     * @param index The model index to retrieve data for.
     * @param role The role for which the data is requested (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role, returning cached data if the source is invalid.
     */
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

    /**
     * @brief Retrieves the item flags for the given index.
     * @param index The model index to query.
     * @return The item flags for the specified index.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const;

    /**
     * @brief Retrieves the header data for a given section, orientation, and role.
     * @param section The section (column or row) to retrieve data for.
     * @param orientation The orientation of the header.
     * @param role The role for which the data is requested (defaults to Qt::DisplayRole).
     * @return The header data for the specified parameters.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    /**
     * @brief Returns the number of rows under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows in the model or cache.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns in the model or cache.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Sets a new source model to be cached and proxied.
     * @param newSourceModel A pointer to the new source model.
     */
    void setSourceModel(QAbstractItemModel *newSourceModel);

private:
    /** Internal cache used to store copies of the source model's data. */
    mutable QStandardItemModel cache;

    /**
     * @brief Checks whether the proxy currently has a valid external source model attached.
     * @return True if a source model is attached and is not the internal cache itself; otherwise false.
     */
    bool hasModel() const { return sourceModel() != &cache; }

private slots:
    /**
     * @brief Resets and clears the internal cache model.
     */
    void resetCacheModel();
};
#endif
