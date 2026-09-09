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

#pragma once

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
     * @brief Returns the underlying InterfaceTreeModel this cache wraps.
     *
     * The private @c sourceModel member hides QAbstractProxyModel's own
     * sourceModel() accessor, so callers that need the concrete type (e.g.
     * to call selectedDevices()/updateSelectedDevices()) go through this.
     * @return The wrapped InterfaceTreeModel.
     */
    InterfaceTreeModel * interfaceModel() const { return sourceModel; }

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
     * @brief Allows the display name of an extcap bookmark to be edited in place.
     *
     * Off by default, since we only enable this in the capture options dialog.
     * @param enabled Whether in-place bookmark renaming is enabled.
     */
    void setBookmarkRenameEnabled(bool enabled) { bookmarkRenameEnabled = enabled; }

    /**
     * @brief Creates a new bookmark for the extcap interface at the given index.
     *
     * If index itself refers to a bookmark, the new bookmark is added as a
     * sibling under the same parent extcap interface rather than renaming
     * the one at index. Its name follows the pattern "<interface> bookmark
     * <n>", where <n> is the lowest positive integer not already used by an
     * existing bookmark of that name (see nextBookmarkName()).
     *
     * Unlike renameBookmark(), this refreshes the interface list
     * synchronously (InterfaceListManager::refreshNow()) rather than
     * deferring it, so the returned index is immediately valid and the
     * caller can select and start editing it right away.
     * @param index The model index of the extcap interface (or one of its
     * bookmarks) to create a new bookmark under.
     * @return The model index of the newly-created bookmark, or an invalid
     * index on failure.
     */
    QModelIndex addBookmark(const QModelIndex &index);

    /**
     * @brief Removes the extcap bookmarks at the given indexes.
     *
     * Indexes that aren't extcap bookmarks are silently skipped. Persists
     * via extcap_remove_bookmark() and requests an interface list refresh
     * (deferred, like renameBookmark() - there's no follow-up UI action
     * that needs the removal to be visible immediately) so the removed
     * entries drop out of the tree.
     * @param indexes The model indexes of the bookmarks to remove.
     * @return True if at least one bookmark was removed.
     */
    bool deleteBookmarks(const QModelIndexList &indexes);

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

    /**
     * @brief Re-queries link-layer capabilities after a monitor mode toggle.
     *
     * Calling this updates the device's link-type list and active DLT for
     * the new monitor mode setting, since the set of available link-layer
     * types can differ between normal and monitor mode. It also corrects
     * the cached monitor mode checkbox state if the query reveals monitor
     * mode isn't actually supported.
     * @param index The model index of the device whose monitor mode changed.
     * @param monitor_mode The newly requested monitor mode state.
     */
    void refreshCapabilities(const QModelIndex &index, bool monitor_mode);

    /**
     * @brief Renames the extcap bookmark at the given index.
     *
     * Validates newName (non-empty, at most 200 characters, and not already
     * used by another bookmark), then applies the rename via
     * extcap_set_bookmark() and requests an interface list refresh so the
     * renamed (and now stale, pre-rename) entries are picked up. Does
     * nothing and returns false if index isn't an extcap bookmark.
     * @param index The model index of the bookmark to rename.
     * @param newName The requested new bookmark name.
     * @return true if the rename was applied, false otherwise.
     */
    bool renameBookmark(const QModelIndex &index, const QString &newName);

    /**
     * @brief Checks whether another extcap interface is already bookmarked
     * under the given name.
     * @param excludeIndex The index to exclude from the search (the
     * bookmark being renamed, which trivially already has some name).
     * @param bookmarkName The candidate bookmark name.
     * @return true if a different interface already uses bookmarkName.
     */
    bool bookmarkNameInUse(const QModelIndex &excludeIndex, const QString &bookmarkName) const;

    /**
     * @brief Computes the default name for a new bookmark of parentIfname.
     *
     * The pattern is "<parentIfname> bookmark <n>", where <n> is the lowest
     * positive integer not already used by an existing bookmark with that
     * exact prefix (e.g. given bookmarks "sshdump bookmark 1", "sshdump
     * bookmark 3" and "sshdump bookmark 4", this returns "sshdump bookmark
     * 2").
     * @param parentIfname The extcap interface the bookmark is being
     * created for.
     * @return The generated bookmark name.
     */
    QString nextBookmarkName(const QString &parentIfname) const;

    /** Whether in-place bookmark renaming is exposed (see setBookmarkRenameEnabled()). */
    bool bookmarkRenameEnabled = false;
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
