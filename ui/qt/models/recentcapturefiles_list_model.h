/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RECENTCAPTUREFILES_LIST_MODEL_H
#define RECENTCAPTUREFILES_LIST_MODEL_H

#include <QAbstractListModel>
#include <QModelIndex>
#include <QSortFilterProxyModel>
#include <QStyledItemDelegate>

/**
 * @brief Qt model for displaying recent capture files.
 *
 * This is a thin wrapper over WorkspaceState — it does not store data,
 * but provides a Qt model interface for views.
 *
 * Thread safety: Assumes single-threaded access (UI thread only).
 */
class RecentCaptureFilesListModel : public QAbstractListModel
{
    Q_OBJECT
public:
    /**
     * @brief Custom data roles for RecentCaptureFilesListModel.
     */
    enum RecentFileRoles {
        FilenameRole   = Qt::UserRole, /**< QString — absolute path of the capture file. */
        FileSizeRole,                  /**< qint64  — file size in bytes; -1 if unknown. */
        AccessibleRole                 /**< bool    — @c true if the file exists and is readable. */
    };

    /**
     * @brief Constructs the model and connects it to WorkspaceState change notifications.
     * @param parent Optional parent QObject.
     */
    explicit RecentCaptureFilesListModel(QObject *parent = nullptr);

    /**
     * @brief Destroys the model.
     */
    ~RecentCaptureFilesListModel();

    /**
     * @brief Returns the number of recent capture file entries.
     * @param parent Unused; pass a default QModelIndex for list models.
     * @return Number of entries in WorkspaceState's recent file list.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns data for the given index and role.
     * @param index Model index of the requested item.
     * @param role  Qt item data role or a RecentFileRoles value.
     * @return QVariant with the requested data, or an invalid QVariant if unavailable.
     */
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Returns item flags for the given index.
     *
     * Inaccessible files are returned as non-enabled so they cannot be opened.
     *
     * @param index Model index to query.
     * @return Qt::ItemIsEnabled | Qt::ItemIsSelectable for accessible files;
     *         Qt::ItemIsSelectable only for inaccessible ones.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const override;

private slots:
    /**
     * @brief Resets the model in response to a WorkspaceState change, causing
     *        all attached views to re-query all data.
     */
    void invalidateModel();
};


/**
 * @brief Proxy model that reverses row order for display (newest first).
 *
 * WorkspaceState stores files oldest-first to match the on-disk file format.
 * This proxy reverses the order so the UI shows the most recently used files
 * at the top of the list.
 */
class RecentCaptureFilesReverseProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs the reverse-order proxy model.
     * @param parent Optional parent QObject.
     */
    explicit RecentCaptureFilesReverseProxyModel(QObject *parent = nullptr);

    /**
     * @brief Maps a proxy index to the corresponding source index by mirroring
     *        the row about the midpoint of the list.
     * @param proxyIndex Proxy-model index to map.
     * @return Corresponding source-model index.
     */
    QModelIndex mapToSource(const QModelIndex &proxyIndex) const override;

    /**
     * @brief Maps a source index to the corresponding proxy index by mirroring
     *        the row about the midpoint of the list.
     * @param sourceIndex Source-model index to map.
     * @return Corresponding proxy-model index.
     */
    QModelIndex mapFromSource(const QModelIndex &sourceIndex) const override;
};


/**
 * @brief Item delegate that formats recent file entries with human-readable size information.
 *
 * Renders each entry as "filename (10 MB)" for accessible files, or
 * "filename (not found)" for inaccessible files. Inaccessible entries
 * are drawn in italic to provide a visual distinction.
 */
class RecentCaptureFilesDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a RecentCaptureFilesDelegate.
     * @param parent Optional parent QObject.
     */
    explicit RecentCaptureFilesDelegate(QObject *parent = nullptr);

    /**
     * @brief Returns the display string for a recent file entry.
     *
     * Formats the value as "filename (size)" or "filename (not found)".
     *
     * @param value  The raw data value from the model (typically the file path).
     * @param locale Locale used for size formatting.
     * @return Formatted display string.
     */
    QString displayText(const QVariant &value, const QLocale &locale) const override;

    /**
     * @brief Initialises the style option for rendering, applying italic style
     *        to entries whose file is inaccessible.
     * @param option Style option to populate.
     * @param index  Model index of the item being rendered.
     */
    void initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const override;

private:
    /**
     * @brief Converts a raw byte count into a human-readable size string (e.g. "1.4 MB").
     * @param bytes File size in bytes.
     * @return Localised, SI-prefixed size string.
     */
    QString formatFileSize(qint64 bytes) const;
};

#endif // RECENTCAPTUREFILES_LIST_MODEL_H
