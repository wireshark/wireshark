/* decode_as_delegate.h
 * Delegates for editing various field types in a Decode As record.
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
