/** @file
 *
 * Model caching interface changes before sending them to global storage
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_TREE_CACHE_MODEL_H_
#define INTERFACE_TREE_CACHE_MODEL_H_

#include <ui/qt/models/interface_tree_model.h>

#include <QMap>
#include <QAbstractItemModel>
#include <QIdentityProxyModel>

/**
 * @brief A proxy model that caches edits and additions to the interface tree before applying them to the source model.
 */
class InterfaceTreeCacheModel : public QIdentityProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new InterfaceTreeCacheModel.
     * @param parent The parent QObject.
     */
    explicit InterfaceTreeCacheModel(QObject *parent);

    /**
     * @brief Destroys the InterfaceTreeCacheModel.
     */
    ~InterfaceTreeCacheModel();

    /**
     * @brief Returns the number of rows under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves data from the cache or source model for a given index and role.
     * @param index The model index.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role.
     */
    QVariant data (const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Sets data in the cache for a given index and role.
     * @param index The model index to update.
     * @param value The value to set.
     * @param role The data role being edited (defaults to Qt::EditRole).
     * @return True if successful, false otherwise.
     */
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;

    /**
     * @brief Retrieves the item flags for a given index, taking cache rules into account.
     * @param index The model index.
     * @return The item flags.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Gets the cached content for a specific column and row.
     * @param idx The row index.
     * @param col The column index.
     * @param role The data role (defaults to Qt::DisplayRole).
     * @return The cached data variant.
     */
    QVariant getColumnContent(int idx, int col, int role = Qt::DisplayRole);

#ifdef HAVE_LIBPCAP
    /**
     * @brief Generates an index for the given row and column.
     * @param row The row index.
     * @param column The column index.
     * @param parent The parent index (defaults to an invalid QModelIndex).
     * @return The corresponding model index.
     */
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Resets cached changes for a specific row.
     * @param row The row index to reset.
     */
    void reset(int row);

    /**
     * @brief Saves all cached changes to the underlying source model.
     */
    void save();

    /**
     * @brief Adds a new device to the cache.
     * @param newDevice Pointer to the new interface device definition.
     */
    void addDevice(const interface_t * newDevice);

    /**
     * @brief Marks a device for deletion from the cache.
     * @param index The model index of the device to delete.
     */
    void deleteDevice(const QModelIndex &index);
#endif

#ifdef HAVE_PCAP_REMOTE
    /**
     * @brief Checks if the interface at the given index is remote.
     * @param index The model index.
     * @return True if the interface is remote, false otherwise.
     */
    bool isRemote(const QModelIndex &index) const;
#endif

private:
    /** The underlying source model containing actual interface data. */
    InterfaceTreeModel * sourceModel;

#ifdef HAVE_LIBPCAP
    /** List of newly added devices pending save. */
    QList<interface_t> newDevices;

    /**
     * @brief Persists the newly added devices to the source model.
     */
    void saveNewDevices();
#endif

    /** Cached changes stored by row and column mapping. */
    QMap<int, QSharedPointer<QMap<InterfaceTreeColumns, QVariant> > > * storage;

    /** List of columns that are allowed to be edited. */
    QList<InterfaceTreeColumns> editableColumns;

    /** List of columns that are allowed to be checked or unchecked. */
    QList<InterfaceTreeColumns> checkableColumns;

#ifdef HAVE_LIBPCAP
    /**
     * @brief Looks up the core interface structure for a given index.
     * @param index The model index.
     * @return Pointer to the core interface_t structure.
     */
    const interface_t * lookup(const QModelIndex &index) const;
#endif

    /**
     * @brief Checks if changing a specific column is permitted.
     * @param col The column identifier.
     * @return True if changes are allowed, false otherwise.
     */
    bool changeIsAllowed(InterfaceTreeColumns col) const;

    /**
     * @brief Checks if a specific field is available for the given index.
     * @param index The model index.
     * @return True if the field is available, false otherwise.
     */
    bool isAvailableField(const QModelIndex &index) const;

    /**
     * @brief Checks if the item at the given index is allowed to be edited.
     * @param index The model index.
     * @return True if the item is editable, false otherwise.
     */
    bool isAllowedToBeEdited(const QModelIndex &index) const;

};
#endif /* INTERFACE_TREE_CACHE_MODEL_H_ */
