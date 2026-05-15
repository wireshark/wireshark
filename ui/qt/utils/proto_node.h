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

/**
 * @brief A wrapper class for the core proto_node structure, providing tree traversal and data access.
 */
class ProtoNode
{
public:

    /**
     * @brief An iterator for traversing the child nodes of a ProtoNode.
     */
    class ChildIterator {
    public:
        /** @brief Pointer type for the underlying proto_node structure. */
        typedef struct _proto_node * NodePtr;

        /**
         * @brief Constructs a new ChildIterator.
         * @param n The starting node for the iterator, defaults to Q_NULLPTR.
         */
        ChildIterator(NodePtr n = Q_NULLPTR);

        /**
         * @brief Checks if there is a subsequent child node.
         * @return True if another child exists, false otherwise.
         */
        bool hasNext();

        /**
         * @brief Advances the iterator to the next child node.
         * @return A ChildIterator pointing to the next node.
         */
        ChildIterator next();

        /**
         * @brief Retrieves the ProtoNode element at the current iterator position.
         * @return The current ProtoNode.
         */
        ProtoNode element();

    protected:
        /** Pointer to the current underlying protocol tree node. */
        NodePtr node;
    };

    /**
     * @brief Constructs a new ProtoNode instance.
     * @param node The underlying core proto_node, defaults to NULL.
     * @param parent The parent ProtoNode, defaults to nullptr.
     */
    explicit ProtoNode(proto_node * node = NULL, ProtoNode *parent = nullptr);

    /**
     * @brief Destroys the ProtoNode.
     */
    ~ProtoNode();

    /**
     * @brief Checks if the protocol node is valid.
     * @return True if the underlying node is valid, false otherwise.
     */
    bool isValid() const;

    /**
     * @brief Checks if this node is a child of another node.
     * @return True if it is a child node, false otherwise.
     */
    bool isChild() const;

    /**
     * @brief Checks if the node is expanded in the view.
     * @return True if expanded, false otherwise.
     */
    bool isExpanded() const;

    /**
     * @brief Retrieves the underlying core proto_node structure.
     * @return A pointer to the proto_node.
     */
    proto_node *protoNode() const;

    /**
     * @brief Retrieves a specific child node by its row index.
     * @param row The index of the child node to retrieve.
     * @return A pointer to the child ProtoNode.
     */
    ProtoNode *child(int row);

    /**
     * @brief Retrieves the total number of child nodes.
     * @return The child count.
     */
    int childrenCount() const;

    /**
     * @brief Retrieves the row index of this node relative to its parent.
     * @return The row index.
     */
    int row();

    /**
     * @brief Retrieves the parent node of this node.
     * @return A pointer to the parent ProtoNode.
     */
    ProtoNode *parentNode();

    /**
     * @brief Retrieves the display label text for this node.
     * @return The label text string.
     */
    QString labelText() const;

    /**
     * @brief Retrieves a child iterator for traversing this node's children.
     * @return A ChildIterator positioned at the first child.
     */
    ChildIterator children() const;

private:
    /** Pointer to the underlying core proto_node structure. */
    proto_node * node_;

    /** Cached list of child ProtoNode instances. */
    QVector<ProtoNode*>m_children;

    /** Pointer to the parent ProtoNode. */
    ProtoNode *parent_;

    /**
     * @brief Determines if a given proto_node should be hidden from display.
     * @param node The node to check.
     * @return True if the node should be hidden, false otherwise.
     */
    static bool isHidden(proto_node * node);
};


#endif // PROTO_NODE_H_
