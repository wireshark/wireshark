/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROTO_NODE_H_
#define PROTO_NODE_H_

#include <config.h>

#include <epan/proto.h>

#include <QObject>
#include <QVector>

class ProtoNode
{
public:

    class ChildIterator {
    public:
        typedef struct _proto_node * NodePtr;

        ChildIterator(NodePtr n = Q_NULLPTR);

        bool hasNext();
        ChildIterator next();
        ProtoNode element();

    protected:
        NodePtr node;
    };

    explicit ProtoNode(proto_node * node = NULL, ProtoNode *parent = nullptr);
    ~ProtoNode();

    bool isValid() const;
    bool isChild() const;
    bool isExpanded() const;

    proto_node *protoNode() const;
    ProtoNode *child(int row);
    int childrenCount() const;
    int row();
    ProtoNode *parentNode();

    QString labelText() const;

    ChildIterator children() const;

private:
    proto_node * node_;
    QVector<ProtoNode*>m_children;
    ProtoNode *parent_;
    static bool isHidden(proto_node * node);
};


#endif // PROTO_NODE_H_
