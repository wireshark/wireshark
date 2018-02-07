/* proto_tree_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROTO_TREE_MODEL_H
#define PROTO_TREE_MODEL_H

#include <ui/qt/utils/proto_node.h>

#include <QAbstractItemModel>
#include <QModelIndex>

class ProtoTreeModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    explicit ProtoTreeModel(QObject * parent = 0);

    virtual Qt::ItemFlags flags(const QModelIndex &index) const;
    QModelIndex index(int row, int, const QModelIndex &parent = QModelIndex()) const;
    virtual QModelIndex parent(const QModelIndex &index) const;
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
    virtual int columnCount(const QModelIndex &) const { return 1; }
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

    // root_node can be NULL.
    void setRootNode(proto_node *root_node);
    ProtoNode protoNodeFromIndex(const QModelIndex &index) const;
    QModelIndex indexFromProtoNode(ProtoNode &index_node) const;

    QModelIndex findFirstHfid(int hf_id);
    QModelIndex findFieldInformation(FieldInformation *finfo);

private:
    proto_node* root_node_;
    static void foreachFindHfid(proto_node *node, gpointer find_hfid_ptr);
    static void foreachFindField(proto_node *node, gpointer find_finfo_ptr);
};

#endif // PROTO_TREE_MODEL_H

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
