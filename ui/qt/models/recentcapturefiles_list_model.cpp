/* recentcapturefiles_list_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/recentcapturefiles_list_model.h>
#include <ui/qt/utils/workspace_state.h>

#include <QFont>

// ============================================================================
// RecentCaptureFilesListModel
// ============================================================================

RecentCaptureFilesListModel::RecentCaptureFilesListModel(QObject *parent)
    : QAbstractListModel(parent)
{
    connect(WorkspaceState::instance(), &WorkspaceState::recentCaptureFilesChanged,
            this, &RecentCaptureFilesListModel::invalidateModel);
    connect(WorkspaceState::instance(), &WorkspaceState::stateLoaded,
            this, &RecentCaptureFilesListModel::invalidateModel);
    connect(WorkspaceState::instance(), &WorkspaceState::recentFileStatusChanged,
        this, [this](const QString &) { invalidateModel(); });
}

RecentCaptureFilesListModel::~RecentCaptureFilesListModel()
{
}

void RecentCaptureFilesListModel::invalidateModel()
{
    beginResetModel();
    endResetModel();
}

int RecentCaptureFilesListModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;

    return static_cast<int>(WorkspaceState::instance()->recentCaptureFiles().size());
}

QVariant RecentCaptureFilesListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    const QList<RecentFileInfo> &files = WorkspaceState::instance()->recentCaptureFiles();

    if (index.row() < 0 || index.row() >= files.size())
        return QVariant();

    const RecentFileInfo &info = files.at(index.row());

    switch (role) {
    case Qt::DisplayRole:
    case FilenameRole:
        return info.filename;
    case FileSizeRole:
        return info.size;
    case AccessibleRole:
        return info.accessible;
    default:
        return QVariant();
    }
}

Qt::ItemFlags RecentCaptureFilesListModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::NoItemFlags;

    const QList<RecentFileInfo> &files = WorkspaceState::instance()->recentCaptureFiles();

    if (index.row() < 0 || index.row() >= files.size())
        return Qt::NoItemFlags;

    const RecentFileInfo &info = files.at(index.row());

    if (info.accessible) {
        return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    }

    return Qt::NoItemFlags;
}

// ============================================================================
// RecentCaptureFilesReverseProxyModel
// ============================================================================

RecentCaptureFilesReverseProxyModel::RecentCaptureFilesReverseProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent)
{
}

QModelIndex RecentCaptureFilesReverseProxyModel::mapToSource(const QModelIndex &proxyIndex) const
{
    if (!proxyIndex.isValid() || !sourceModel())
        return QModelIndex();

    int rowCount = sourceModel()->rowCount();
    int sourceRow = rowCount - 1 - proxyIndex.row();

    if (sourceRow < 0 || sourceRow >= rowCount)
        return QModelIndex();

    return sourceModel()->index(sourceRow, proxyIndex.column());
}

QModelIndex RecentCaptureFilesReverseProxyModel::mapFromSource(const QModelIndex &sourceIndex) const
{
    if (!sourceIndex.isValid() || !sourceModel())
        return QModelIndex();

    int rowCount = sourceModel()->rowCount();
    int proxyRow = rowCount - 1 - sourceIndex.row();

    if (proxyRow < 0 || proxyRow >= rowCount)
        return QModelIndex();

    return index(proxyRow, sourceIndex.column());
}

// ============================================================================
// RecentCaptureFilesDelegate
// ============================================================================

RecentCaptureFilesDelegate::RecentCaptureFilesDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

QString RecentCaptureFilesDelegate::formatFileSize(qint64 bytes) const
{
    // Use threshold of >10 for each unit to avoid showing "0 GB" or "1 MB"
    if (bytes / 1024 / 1024 / 1024 > 10) {
        return QStringLiteral("%1 GB").arg(bytes / 1024 / 1024 / 1024);
    } else if (bytes / 1024 / 1024 > 10) {
        return QStringLiteral("%1 MB").arg(bytes / 1024 / 1024);
    } else if (bytes / 1024 > 10) {
        return QStringLiteral("%1 KB").arg(bytes / 1024);
    } else {
        return QStringLiteral("%1 Bytes").arg(bytes);
    }
}

QString RecentCaptureFilesDelegate::displayText(const QVariant &value, const QLocale &locale) const
{
    Q_UNUSED(locale);
    // This is called with DisplayRole data - we handle formatting in initStyleOption instead
    return value.toString();
}

void RecentCaptureFilesDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);

    // Get data from model via custom roles
    QString filename = index.data(RecentCaptureFilesListModel::FilenameRole).toString();
    qint64 size = index.data(RecentCaptureFilesListModel::FileSizeRole).toLongLong();
    bool accessible = index.data(RecentCaptureFilesListModel::AccessibleRole).toBool();

    // Build the display string: "filename (size)" or "filename (not found)"
    QString displayStr = filename;
    displayStr.append(" (");
    if (accessible) {
        displayStr.append(formatFileSize(size));
    } else {
        displayStr.append(QObject::tr("not found"));
    }
    displayStr.append(")");

    option->text = displayStr;

    // Set italic font for inaccessible files
    if (!accessible) {
        option->font.setItalic(true);
    }
}
