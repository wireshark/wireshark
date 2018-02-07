/* fileset_entry_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILESET_ENTRY_MODEL_H
#define FILESET_ENTRY_MODEL_H

#include <config.h>

#include <glib.h>

#include <fileset.h>

#include <QAbstractItemModel>
#include <QModelIndex>
#include <QVector>

class FilesetEntryModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    explicit FilesetEntryModel(QObject * parent = 0);

    QModelIndex index(int row, int column, const QModelIndex & = QModelIndex()) const;
    // Everything is under the root.
    virtual QModelIndex parent(const QModelIndex &) const { return QModelIndex(); }
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
    virtual int columnCount(const QModelIndex &) const { return ColumnCount; }
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    virtual QVariant headerData(int section, Qt::Orientation, int role = Qt::DisplayRole) const;

    virtual void appendEntry(const fileset_entry *entry);
    const fileset_entry *getRowEntry(int row) const { return entries_.value(row, NULL); }
    int entryCount() const { return entries_.count(); }
    // Calls fileset_delete and clears our model data.
    void clear();

private:
    QVector<const fileset_entry *> entries_;
    enum Column { Name, Created, Modified, Size, ColumnCount };

    QString nameToDate(const char *name) const ;
    QString time_tToString(time_t clock) const;
};

#endif // FILESET_ENTRY_MODEL_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
