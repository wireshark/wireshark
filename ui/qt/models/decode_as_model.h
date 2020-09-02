/* decode_as_model.h
 * Data model for Decode As records.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DECODE_AS_MODEL_H
#define DECODE_AS_MODEL_H

#include <config.h>
#include <glib.h>

#include <QAbstractItemModel>
#include <QList>

#include "cfile.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-dcerpc.h>

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
    decode_dcerpc_bind_values_t* selectorDCERPC_; //for special handling of DCE/RPC

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
        colTable = 0, // aka "Field" (or dissector table like "TCP Port")
        colSelector, // the actual table value (e.g., port number 80)
        colType,    // field type (e.g. "Integer, base 16")
        colDefault, // aka "initial" protocol chosen by Wireshark
        colProtocol, // aka "current" protocol selected by user
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
    void clearAll();
    bool copyRow(int dst_row, int src_row);
    bool copyFromProfile(QString filename, const gchar **err);

    static QString entryString(const gchar *table_name, gconstpointer value);

    void applyChanges();

protected:
    static void buildChangedList(const gchar *table_name, ftenum_t selector_type,
                          gpointer key, gpointer value, gpointer user_data);
    static void buildDceRpcChangedList(gpointer data, gpointer user_data);
    static void gatherChangedEntries(const gchar *table_name, ftenum_t selector_type,
                          gpointer key, gpointer value, gpointer user_data);
    static prefs_set_pref_e readDecodeAsEntry(gchar *key, const gchar *value,
                          void *user_data, gboolean return_range_errors);

private:
    capture_file *cap_file_;
    QList<DecodeAsItem *> decode_as_items_;
    QList<QPair<const char *, guint32> > changed_uint_entries_;
    QList<QPair<const char *, const char *> > changed_string_entries_;
};

#endif // DECODE_AS_MODEL_H
