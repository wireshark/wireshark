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
 * This is a thin wrapper over WorkspaceState - it doesn't store data,
 * just provides a Qt model interface for views.
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
        FilenameRole = Qt::UserRole,
        FileSizeRole,
        AccessibleRole
    };

    explicit RecentCaptureFilesListModel(QObject *parent = nullptr);
    ~RecentCaptureFilesListModel();

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;

private slots:
    void invalidateModel();
};

/**
 * @brief Proxy model that reverses row order for display (newest first).
 *
 * WorkspaceState stores files oldest-first (matching the file format).
 * This proxy reverses the order so the UI shows newest files at top.
 */
class RecentCaptureFilesReverseProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    explicit RecentCaptureFilesReverseProxyModel(QObject *parent = nullptr);

    QModelIndex mapToSource(const QModelIndex &proxyIndex) const override;
    QModelIndex mapFromSource(const QModelIndex &sourceIndex) const override;
};

/**
 * @brief Item delegate that formats recent file entries with size info.
 *
 * Displays: "filename (10 MB)" or "filename (not found)" for inaccessible files.
 * Inaccessible files are rendered in italic.
 */
class RecentCaptureFilesDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit RecentCaptureFilesDelegate(QObject *parent = nullptr);

    QString displayText(const QVariant &value, const QLocale &locale) const override;
    void initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const override;

private:
    QString formatFileSize(qint64 bytes) const;
};

#endif // RECENTCAPTUREFILES_LIST_MODEL_H
