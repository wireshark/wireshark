/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROTO_TREE_MODEL_H
#define PROTO_TREE_MODEL_H

#include <ui/qt/utils/field_information.h>
#include <ui/qt/utils/proto_node.h>

#include <QAbstractItemModel>
#include <QModelIndex>

/**
 * @brief Item model that exposes a libwireshark proto_node tree to Qt views,
 *        enabling the packet-details tree to be driven by standard Qt model/view
 *        architecture.
 */
class ProtoTreeModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an empty ProtoTreeModel with no root node.
     * @param parent Optional parent QObject.
     */
    explicit ProtoTreeModel(QObject *parent = 0);

    /**
     * @brief Destroys the model. Does not free the underlying proto_node tree.
     */
    ~ProtoTreeModel();

    /**
     * @brief Returns the item flags for the given index.
     * @param index Model index to query.
     * @return Qt::ItemIsEnabled | Qt::ItemIsSelectable for valid indices;
     *         Qt::NoItemFlags otherwise.
     */
    virtual Qt::ItemFlags flags(const QModelIndex &index) const;

    /**
     * @brief Returns the model index for the child at @p row under @p parent.
     * @param row    Zero-based child row.
     * @param parent Parent index; an invalid index refers to the root.
     * @return Model index for the requested child, or an invalid index if out of range.
     */
    QModelIndex index(int row, int, const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the parent index of the item at @p index.
     * @param index Model index whose parent is requested.
     * @return Parent model index, or an invalid index if @p index is a top-level item.
     */
    virtual QModelIndex parent(const QModelIndex &index) const;

    /**
     * @brief Returns the number of child rows under @p parent.
     * @param parent Parent index; an invalid index refers to the root.
     * @return Number of direct children, or 0 if @p parent has no children.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns (always 1).
     * @return 1.
     */
    virtual int columnCount(const QModelIndex &) const { return 1; }

    /**
     * @brief Returns data for the given index and role.
     * @param index Model index of the requested item.
     * @param role  Qt item data role (e.g. Qt::DisplayRole).
     * @return QVariant with the requested data, or an invalid QVariant if unavailable.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

    /**
     * @brief Sets the root node of the proto_node tree exposed by this model.
     *
     * Resets the model and notifies all attached views. Passing @c nullptr
     * clears the model.
     *
     * @param root_node Pointer to the root proto_node, or @c nullptr to clear.
     */
    void setRootNode(proto_node *root_node);

    /**
     * @brief Returns the ProtoNode wrapper for the item at the given model index.
     * @param index Model index to resolve.
     * @return Pointer to the corresponding ProtoNode, or @c nullptr for invalid indices.
     */
    ProtoNode *protoNodeFromIndex(const QModelIndex &index) const;

    /**
     * @brief Returns the model index corresponding to the given ProtoNode.
     * @param index_node ProtoNode to locate within the tree.
     * @return Valid model index if found; an invalid index otherwise.
     */
    QModelIndex indexFromProtoNode(ProtoNode *index_node) const;

    /**
     * @brief Searches the tree for the first node whose header-field ID matches @p hf_id.
     * @param hf_id Wireshark header-field ID (hf_register_info index) to find.
     * @return Model index of the first matching node, or an invalid index if not found.
     */
    QModelIndex findFirstHfid(int hf_id);

    /**
     * @brief Searches the tree for the node that corresponds to the given FieldInformation.
     * @param finfo FieldInformation instance to locate.
     * @return Model index of the matching node, or an invalid index if not found.
     */
    QModelIndex findFieldInformation(FieldInformation *finfo);

private:
    ProtoNode *root_node_; /**< Root of the proto_node tree currently exposed by this model. */

    /**
     * @brief ProtoNode::foreachNode callback that stops iteration when a node
     *        with the target hf_id is found.
     * @param node         Current node being visited.
     * @param find_hfid_ptr Pointer to a find-by-hfid context structure.
     * @return @c true to stop iteration when a match is found; @c false to continue.
     */
    static bool foreachFindHfid(ProtoNode *node, void *find_hfid_ptr);

    /**
     * @brief ProtoNode::foreachNode callback that stops iteration when a node
     *        matching the target FieldInformation is found.
     * @param node          Current node being visited.
     * @param find_finfo_ptr Pointer to a find-by-finfo context structure.
     * @return @c true to stop iteration when a match is found; @c false to continue.
     */
    static bool foreachFindField(ProtoNode *node, void *find_finfo_ptr);
};

#endif // PROTO_TREE_MODEL_H
