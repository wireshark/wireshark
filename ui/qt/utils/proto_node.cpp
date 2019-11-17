/* proto_node.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/proto_node.h>

#include <epan/prefs.h>

ProtoNode::ProtoNode(proto_node *node) :
    node_(node)
{
}

bool ProtoNode::isValid() const
{
    return node_;
}

bool ProtoNode::isChild() const
{
    return node_ && node_->parent;
}

ProtoNode ProtoNode::parentNode()
{
    if (node_) {
        return ProtoNode(node_->parent);
    }
    return ProtoNode(NULL);
}

QString ProtoNode::labelText() const
{
    if (!node_) {
        return QString();
    }
    field_info *fi = PNODE_FINFO(node_);
    if (!fi) {
        return QString();
    }

    QString label;
    /* was a free format label produced? */
    if (fi->rep) {
        label = fi->rep->representation;
    }
    else { /* no, make a generic label */
        gchar label_str[ITEM_LABEL_LENGTH];
        proto_item_fill_label(fi, label_str);
        label = label_str;
    }

    // Generated takes precedence.
    if (proto_item_is_generated(node_)) {
        label.prepend("[");
        label.append("]");
    }
    if (proto_item_is_hidden(node_)) {
        label.prepend("<");
        label.append(">");
    }
    return label;
}

int ProtoNode::childrenCount() const
{
    if (!node_) return 0;

    int row_count = 0;
    ChildIterator kids = children();
    while (kids.element().isValid())
    {
        row_count++;
        kids.next();
    }

    return row_count;
}

int ProtoNode::row()
{
    if (!isChild()) {
        return -1;
    }

    int cur_row = 0;
    ProtoNode::ChildIterator kids = parentNode().children();
    while (kids.element().isValid())
    {
        if (kids.element().protoNode() == node_) {
            break;
        }
        cur_row++;
        kids.next();
    }
    if (! kids.element().isValid()) {
        return -1;
    }
    return cur_row;
}

bool ProtoNode::isExpanded() const
{
    if (node_ && node_->finfo && node_->first_child && tree_expanded(node_->finfo->tree_type)) {
        return true;
    }
    return false;
}

proto_node * ProtoNode::protoNode() const
{
    return node_;
}

ProtoNode::ChildIterator ProtoNode::children() const
{
    proto_node *child = node_->first_child;
    while (child && isHidden(child)) {
        child = child->next;
    }

    return ProtoNode::ChildIterator(child);
}

ProtoNode::ChildIterator::ChildIterator(ProtoNode::ChildIterator::NodePtr n)
{
    node = n;
}

bool ProtoNode::ChildIterator::hasNext()
{
    if (! node || node->next == Q_NULLPTR)
        return false;
    return true;
}

ProtoNode::ChildIterator ProtoNode::ChildIterator::next()
{
    do {
        node = node->next;
    } while (node && isHidden(node));
    return *this;
}

ProtoNode ProtoNode::ChildIterator::element()
{
    return ProtoNode(node);
}

bool ProtoNode::isHidden(proto_node * node)
{
    return PROTO_ITEM_IS_HIDDEN(node) && !prefs.display_hidden_proto_items;
}

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
