/* proto_node.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/proto_node.h>
#include <ui/qt/utils/field_information.h>

#include <epan/prefs.h>

// NOLINTNEXTLINE(misc-no-recursion)
ProtoNode::ProtoNode(proto_node *node, ProtoNode *parent) :
    node_(node), parent_(parent)
{
    if (node_) {

        int num_children = 0;
        for (proto_node *child = node_->first_child; child; child = child->next) {
            if (!isHidden(child)) {
                num_children++;
            }
        }

        m_children.reserve(num_children);

        for (proto_node *child = node_->first_child; child; child = child->next) {
            if (!isHidden(child)) {
                // We recurse here, but we're limited by tree depth checks in epan
                m_children.append(new ProtoNode(child, this));
            }
        }
    }
}

ProtoNode::~ProtoNode()
{
    qDeleteAll(m_children);
}

bool ProtoNode::isValid() const
{
    return node_;
}

bool ProtoNode::isChild() const
{
    return node_ && node_->parent;
}

ProtoNode* ProtoNode::parentNode()
{
    return parent_;
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
        char label_str[ITEM_LABEL_LENGTH];
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

    return (int)m_children.count();
}

int ProtoNode::row()
{
    if (!isChild()) {
        return -1;
    }

    return (int)parent_->m_children.indexOf(const_cast<ProtoNode*>(this));
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

ProtoNode* ProtoNode::child(int row)
{
    if (row < 0 || row >= m_children.size())
        return nullptr;
    return m_children.at(row);
}

ProtoNode::ChildIterator ProtoNode::children() const
{
    /* XXX: Iterate over m_children instead?
     * Somewhat faster as m_children already excludes any hidden items. */
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
    return proto_item_is_hidden(node) && !prefs.display_hidden_proto_items;
}
