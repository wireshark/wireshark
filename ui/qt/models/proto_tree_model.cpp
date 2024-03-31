/* proto_tree_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/proto_tree_model.h>

#include <epan/prefs.h>
#include <wsutil/wslog.h>

#include <ui/qt/utils/color_utils.h>

#include <QApplication>
#include <QPalette>
#include <QFont>

// To do:
// - Add ProtoTreeDelegate
// - Add ProtoTreeModel to CaptureFile

ProtoTreeModel::ProtoTreeModel(QObject * parent) :
    QAbstractItemModel(parent)
{
    root_node_ = new ProtoNode(NULL);
}

ProtoTreeModel::~ProtoTreeModel()
{
    delete root_node_;
}

Qt::ItemFlags ProtoTreeModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags item_flags = QAbstractItemModel::flags(index);
    if (rowCount(index) < 1) {
        item_flags |= Qt::ItemNeverHasChildren;
    }

    return item_flags;
}

QModelIndex ProtoTreeModel::index(int row, int, const QModelIndex &parent) const
{
    ProtoNode *parent_node = root_node_;

    if (parent.isValid()) {
        // index is not a top level item.
        parent_node = protoNodeFromIndex(parent);
    }

    if (! parent_node->isValid())
        return QModelIndex();

    ProtoNode *child = parent_node->child(row);
    if (! child) {
        return QModelIndex();
    }

    return createIndex(row, 0, static_cast<void *>(child));
}

QModelIndex ProtoTreeModel::parent(const QModelIndex &index) const
{
    if (!index.isValid())
        return QModelIndex();

    ProtoNode *parent_node = protoNodeFromIndex(index)->parentNode();
    return indexFromProtoNode(parent_node);
}

int ProtoTreeModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return protoNodeFromIndex(parent)->childrenCount();
    }
    return root_node_->childrenCount();
}

// The QItemDelegate documentation says
// "When displaying items from a custom model in a standard view, it is
//  often sufficient to simply ensure that the model returns appropriate
//  data for each of the roles that determine the appearance of items in
//  views."
// We might want to move this to a delegate regardless.
QVariant ProtoTreeModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    ProtoNode *index_node = protoNodeFromIndex(index);
    FieldInformation finfo(index_node);
    if (!finfo.isValid()) {
        return QVariant();
    }

    switch (role) {
    case Qt::DisplayRole:
        return index_node->labelText();
    case Qt::BackgroundRole:
    {
        switch(finfo.flag(PI_SEVERITY_MASK)) {
        case(0):
            break;
        case(PI_COMMENT):
            return ColorUtils::expert_color_comment;
        case(PI_CHAT):
            return ColorUtils::expert_color_chat;
        case(PI_NOTE):
            return ColorUtils::expert_color_note;
        case(PI_WARN):
            return ColorUtils::expert_color_warn;
        case(PI_ERROR):
            return ColorUtils::expert_color_error;
        default:
            ws_warning("Unhandled severity flag: %u", finfo.flag(PI_SEVERITY_MASK));
        }
        if (finfo.headerInfo().type == FT_PROTOCOL) {
            return QApplication::palette().window();
        }
        return QApplication::palette().base();
    }
    case Qt::ForegroundRole:
    {
        if (finfo.flag(PI_SEVERITY_MASK)) {
            return ColorUtils::expert_color_foreground;
        }
        if (finfo.isLink()) {
            return ColorUtils::themeLinkBrush();
        }
        if (finfo.headerInfo().type == FT_PROTOCOL) {
            return QApplication::palette().windowText();
        }
        return QApplication::palette().text();
    }
    case Qt::FontRole:
        if (finfo.isLink()) {
            QFont font;
            font.setUnderline(true);
            return font;
        }
    default:
        break;
    }

    return QVariant();
}

void ProtoTreeModel::setRootNode(proto_node *root_node)
{
    beginResetModel();
    delete root_node_;
    root_node_ = new ProtoNode(root_node);
    endResetModel();
    if (!root_node) return;

    int row_count = root_node_->childrenCount();
    if (row_count < 1) return;
    beginInsertRows(QModelIndex(), 0, row_count - 1);
    endInsertRows();
}

ProtoNode* ProtoTreeModel::protoNodeFromIndex(const QModelIndex &index) const
{
    return static_cast<ProtoNode*>(index.internalPointer());
}

QModelIndex ProtoTreeModel::indexFromProtoNode(ProtoNode *index_node) const
{
    if (!index_node) {
        return QModelIndex();
    }

    int row = index_node->row();

    if (!index_node->isValid() || row < 0) {
        return QModelIndex();
    }

    return createIndex(row, 0, static_cast<void *>(index_node));
}

struct find_hfid_ {
    int hfid;
    ProtoNode *node;
};

// NOLINTNEXTLINE(misc-no-recursion)
bool ProtoTreeModel::foreachFindHfid(ProtoNode *node, void *find_hfid_ptr)
{
    struct find_hfid_ *find_hfid = (struct find_hfid_ *) find_hfid_ptr;
    if (PNODE_FINFO(node->protoNode()) && PNODE_FINFO(node->protoNode())->hfinfo->id == find_hfid->hfid) {
        find_hfid->node = node;
        return true;
    }
    for (int i = 0; i < node->childrenCount(); i++) {
        // We recurse here, but we're limited by tree depth checks in epan
        if (foreachFindHfid(node->child(i), find_hfid)) {
                return true;
        }
    }
    return false;
}

QModelIndex ProtoTreeModel::findFirstHfid(int hf_id)
{
    if (!root_node_ || hf_id < 0) return QModelIndex();

    struct find_hfid_ find_hfid;
    find_hfid.hfid = hf_id;

    if (foreachFindHfid(root_node_, &find_hfid) && find_hfid.node->isValid()) {
        return indexFromProtoNode(find_hfid.node);
    }
    return QModelIndex();
}

struct find_field_info_ {
    field_info *fi;
    ProtoNode *node;
};

// NOLINTNEXTLINE(misc-no-recursion)
bool ProtoTreeModel::foreachFindField(ProtoNode *node, void *find_finfo_ptr)
{
    struct find_field_info_ *find_finfo = (struct find_field_info_ *) find_finfo_ptr;
    if (PNODE_FINFO(node->protoNode()) == find_finfo->fi) {
        find_finfo->node = node;
        return true;
    }
    for (int i = 0; i < node->childrenCount(); i++) {
        // We recurse here, but we're limited by tree depth checks in epan
        if (foreachFindField(node->child(i), find_finfo)) {
                return true;
        }
    }
    return false;
}

QModelIndex ProtoTreeModel::findFieldInformation(FieldInformation *finfo)
{
    if (!root_node_ || !finfo) return QModelIndex();
    field_info * fi = finfo->fieldInfo();
    if (!fi) return QModelIndex();

    struct find_field_info_ find_finfo;
    find_finfo.fi = fi;

    if (foreachFindField(root_node_, &find_finfo) && find_finfo.node->isValid()) {
        return indexFromProtoNode(find_finfo.node);
    }
    return QModelIndex();
}
