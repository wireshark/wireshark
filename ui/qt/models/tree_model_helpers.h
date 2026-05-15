/** @file
 *
 * Utility template classes for basic tree model functionality
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TREE_MODEL_HELPERS_H
#define TREE_MODEL_HELPERS_H

#include <config.h>
#include <ui/qt/utils/variant_pointer.h>

#include <QAbstractItemModel>

/**
 * @brief Base class to inherit basic tree item from.
 */
template <typename Item>
class ModelHelperTreeItem
{
public:
    /**
     * @brief Constructs a new ModelHelperTreeItem.
     * @param parent Pointer to the parent item.
     */
    ModelHelperTreeItem(Item* parent)
        : parent_(parent)
    {
    }

    /**
     * @brief Destroys the ModelHelperTreeItem and its children.
     */
    virtual ~ModelHelperTreeItem()
    {
        for (int row = 0; row < childItems_.count(); row++)
        {
            delete VariantPointer<Item>::asPtr(childItems_.value(row));
        }

        childItems_.clear();
    }

    /**
     * @brief Appends a child item to the end of the children list.
     * @param child Pointer to the child item to append.
     */
    void appendChild(Item* child)
    {
        childItems_.append(VariantPointer<Item>::asQVariant(child));
    }

    /**
     * @brief Prepends a child item to the beginning of the children list.
     * @param child Pointer to the child item to prepend.
     */
    void prependChild(Item* child)
    {
        childItems_.prepend(VariantPointer<Item>::asQVariant(child));
    }

    /**
     * @brief Inserts a child item at the specified row.
     * @param row The row index at which to insert the child.
     * @param child Pointer to the child item to insert.
     */
    void insertChild(int row, Item* child)
    {
        childItems_.insert(row, VariantPointer<Item>::asQVariant(child));
    }

    /**
     * @brief Removes and deletes the child item at the specified row.
     * @param row The row index of the child to remove.
     */
    void removeChild(int row)
    {
        delete VariantPointer<Item>::asPtr(childItems_.value(row));
        childItems_.removeAt(row);
    }

    /**
     * @brief Retrieves the child item at the specified row.
     * @param row The row index of the child to retrieve.
     * @return Pointer to the child item.
     */
    Item* child(int row)
    {
        return VariantPointer<Item>::asPtr(childItems_.value(row));
    }

    /**
     * @brief Gets the total number of child items.
     * @return The child count.
     */
    int childCount() const
    {
        return static_cast<int>(childItems_.count());
    }

    /**
     * @brief Gets the row index of this item relative to its parent.
     * @return The row index.
     */
    int row()
    {
        if (parent_)
        {
            return static_cast<int>(parent_->childItems_.indexOf(VariantPointer<Item>::asQVariant((Item *)this)));
        }

        return 0;
    }

    /**
     * @brief Retrieves the parent item.
     * @return Pointer to the parent item.
     */
    Item* parentItem() {return parent_; }

protected:
    /** Pointer to the parent item. */
    Item* parent_;

    /** List of child items stored as QVariants. */
    QList<QVariant> childItems_;
};

#endif // TREE_MODEL_HELPERS_H
