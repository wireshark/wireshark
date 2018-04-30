/* decode_as_delegate.h
 * Delegates for editing various field types in a Decode As record.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DECODE_AS_DELEGATE_H
#define DECODE_AS_DELEGATE_H

#include <config.h>
#include <glib.h>

#include "cfile.h"

#include <QStyledItemDelegate>
#include <QSet>
#include <QList>
#include <ui/qt/models/decode_as_model.h>

typedef struct _packet_proto_data_t {
    const gchar* proto_name;
    const gchar* table_ui_name;
    guint8       curr_layer_num;
} packet_proto_data_t;

class DecodeAsDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    DecodeAsDelegate(QObject *parent = 0, capture_file *cf = NULL);

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const;
    void setEditorData(QWidget *editor, const QModelIndex &index) const;
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const;

#if 0
    void updateEditorGeometry(QWidget *editor,
            const QStyleOptionViewItem &option, const QModelIndex &index) const;
#endif

private:
    DecodeAsItem *indexToField(const QModelIndex &index) const;
    void collectDAProtocols(QSet<QString>& all_protocols, QList<QString>& current_list) const;
    void cachePacketProtocols();
    bool isSelectorCombo(DecodeAsItem* item) const;

    static void decodeAddProtocol(const gchar *table_name, const gchar *proto_name, gpointer value, gpointer user_data);

    capture_file *cap_file_;
    QList<packet_proto_data_t> packet_proto_list_;
};
#endif // DECODE_AS_DELEGATE_H
