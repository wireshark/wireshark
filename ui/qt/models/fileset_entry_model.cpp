/* fileset_entry_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/fileset_entry_model.h>

#include "wsutil/utf8_entities.h"

#include <ui/qt/utils/qt_ui_utils.h>

#include <QRegularExpression>

FilesetEntryModel::FilesetEntryModel(QObject * parent) :
    QAbstractItemModel(parent)
{}

QModelIndex FilesetEntryModel::index(int row, int column, const QModelIndex &) const
{
    if (row >= entries_.count() || row < 0 || column > ColumnCount) {
        return QModelIndex();
    }

    return createIndex(row, column, const_cast<fileset_entry *>(entries_.at(row)));
}

int FilesetEntryModel::rowCount(const QModelIndex &) const
{
    return static_cast<int>(entries_.count());
}

QVariant FilesetEntryModel::data(const QModelIndex &index, int role) const
{
    if (! index.isValid() || index.row() >= rowCount())
        return QVariant();

    const fileset_entry *entry = static_cast<fileset_entry*>(index.internalPointer());
    if (role == Qt::DisplayRole && entry) {
        switch (index.column()) {
        case Name:
            return QString(entry->name);
        case Created:
        {
            QString created = nameToDate(entry->name);
            if (created.length() < 1) {
                /* if this file doesn't follow the file set pattern, */
                /* use the creation time of that file if available */
                /* https://en.wikipedia.org/wiki/ISO_8601 */
                /*
                 * macOS provides 0 if the file system doesn't support the
                 * creation time; FreeBSD provides -1.
                 *
                 * If this OS doesn't provide the creation time with stat(),
                 * it will be 0.
                 */
                if (entry->ctime > 0) {
                    created = time_tToString(entry->ctime);
                } else {
                    created = UTF8_EM_DASH;
                }
            }
            return created;
        }
        case Modified:
            return time_tToString(entry->mtime);
        case Size:
            return file_size_to_qstring(entry->size);
        default:
            break;
        }
    } else if (role == Qt::ToolTipRole) {
        return QString(tr("Open this capture file"));
    } else if (role == Qt::TextAlignmentRole) {
        switch (index.column()) {
        case Size:
            // Not perfect but better than nothing.
            return Qt::AlignRight;
        default:
            return Qt::AlignLeft;
        }
    }
    return QVariant();
}

QVariant FilesetEntryModel::headerData(int section, Qt::Orientation, int role) const
{
    if (role != Qt::DisplayRole) return QVariant();

    switch (section) {
    case Name:
        return tr("Filename");
    case Created:
        return tr("Created");
    case Modified:
        return tr("Modified");
    case Size:
        return tr("Size");
    default:
        break;
    }
    return QVariant();
}

void FilesetEntryModel::appendEntry(const fileset_entry *entry)
{
    emit beginInsertRows(QModelIndex(), rowCount(), rowCount());
    entries_ << entry;
    emit endInsertRows();
}

void FilesetEntryModel::clear()
{
    fileset_delete();
    beginResetModel();
    entries_.clear();
    endResetModel();
}

QString FilesetEntryModel::nameToDate(const char *name) const {
    char *date;
    QString dn;

    if (fileset_filename_match_pattern(name, NULL, NULL, &date) == FILESET_NO_MATCH)
        return NULL;

    dn = gchar_free_to_qstring(date);
    dn.insert(4, '-');
    dn.insert(7, '-');
    dn.insert(10, ' ');
    dn.insert(13, ':');
    dn.insert(16, ':');
    return dn;
}

QString FilesetEntryModel::time_tToString(time_t clock) const
{
    struct tm *local = localtime(&clock);
    if (!local) return UTF8_EM_DASH;

    // yyyy-MM-dd HH:mm:ss
    // The equivalent QDateTime call is pretty slow here, possibly related to QTBUG-21678
    // and/or QTBUG-41714.
    return QString("%1-%2-%3 %4:%5:%6")
            .arg(local->tm_year + 1900, 4, 10, QChar('0'))
            .arg(local->tm_mon+1, 2, 10, QChar('0'))
            .arg(local->tm_mday, 2, 10, QChar('0'))
            .arg(local->tm_hour, 2, 10, QChar('0'))
            .arg(local->tm_min, 2, 10, QChar('0'))
            .arg(local->tm_sec, 2, 10, QChar('0'));
}
