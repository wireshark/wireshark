/** @file
 *
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

#include "cfile.h"

#include <QStyledItemDelegate>
#include <QSet>
#include <QList>
#include <ui/qt/models/decode_as_model.h>

typedef struct _packet_proto_data_t {
    const char* proto_name;
    const char* table_ui_name;
    uint8_t     curr_layer_num;
} packet_proto_data_t;

class DecodeAsDelegate : public QStyledItemDelegate
{
public:
    DecodeAsDelegate(QObject *parent = 0, capture_file *cf = NULL);

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;
    void destroyEditor(QWidget *editor, const QModelIndex &index) const override;
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

#if 0
    void updateEditorGeometry(QWidget *editor,
            const QStyleOptionViewItem &option, const QModelIndex &index) const;
#endif

private:
    DecodeAsItem *indexToField(const QModelIndex &index) const;
    void collectDAProtocols(QSet<QString>& all_protocols, QList<QString>& current_list) const;
    void cachePacketProtocols();
    bool isSelectorCombo(DecodeAsItem* item) const;

    static void decodeAddProtocol(const char *table_name, const char *proto_name, void *value, void *user_data);

    capture_file *cap_file_;
    QList<packet_proto_data_t> packet_proto_list_;
};
#endif // DECODE_AS_DELEGATE_H
