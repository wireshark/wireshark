/* decode_as_model.h
 * Data model for Decode As records.
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

#ifndef DECODE_AS_MODEL_H
#define DECODE_AS_MODEL_H

#include <config.h>
#include <glib.h>

#include <QAbstractItemModel>
#include <QList>

#include "cfile.h"

#include <epan/packet.h>

class DecodeAsItem
{
public:
    DecodeAsItem();
    virtual ~DecodeAsItem();

    const gchar* tableName_;
    const gchar* tableUIName_;

    //save our sanity and not have to worry about memory management
    //between (lack of) persistent data in GUI and underlying data
    uint selectorUint_;
    QString selectorString_;

    QString default_proto_;
    QString current_proto_;
    dissector_handle_t  dissector_handle_;
};

class DecodeAsModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    DecodeAsModel(QObject *parent, capture_file *cf = NULL);

    enum DecodeAsColumn {
        colTable = 0,
        colSelector,
        colType,
        colDefault, // aka "initial"
        colProtocol, // aka "current"
        colDecodeAsMax //not used
    };

    Qt::ItemFlags flags(const QModelIndex &index) const;
    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);
    void fillTable();

    void setDissectorHandle(const QModelIndex &index, dissector_handle_t  dissector_handle);

    bool insertRows(int row, int count, const QModelIndex &parent = QModelIndex());
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    bool copyRow(int dst_row, int src_row);

    static QString entryString(const gchar *table_name, gpointer value);

    void applyChanges();

protected:
    static void buildChangedList(const gchar *table_name, ftenum_t selector_type,
                          gpointer key, gpointer value, gpointer user_data);
    static void buildDceRpcChangedList(gpointer data, gpointer user_data);
    static void gatherChangedEntries(const gchar *table_name, ftenum_t selector_type,
                          gpointer key, gpointer value, gpointer user_data);


private:
    capture_file *cap_file_;
    QList<DecodeAsItem *> decode_as_items_;
    QList<QPair<const char *, guint32> > changed_uint_entries_;
    QList<QPair<const char *, const char *> > changed_string_entries_;
};

#endif // DECODE_AS_MODEL_H
