/* tree_model_helpers.h
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

//Base class to inherit basic tree item from
template <typename Item>
class ModelHelperTreeItem
{
public:
    ModelHelperTreeItem(Item* parent)
        : parent_(parent)
    {
    }

    virtual ~ModelHelperTreeItem()
    {
        for (int row = 0; row < childItems_.count(); row++)
        {
            delete VariantPointer<Item>::asPtr(childItems_.value(row));
        }

        childItems_.clear();
    }

    void appendChild(Item* child)
    {
        childItems_.append(VariantPointer<Item>::asQVariant(child));
    }

    void prependChild(Item* child)
    {
        childItems_.prepend(VariantPointer<Item>::asQVariant(child));
    }


    void insertChild(int row, Item* child)
    {
        childItems_.insert(row, VariantPointer<Item>::asQVariant(child));
    }

    void removeChild(int row)
    {
        delete VariantPointer<Item>::asPtr(childItems_.value(row));
        childItems_.removeAt(row);
    }

    Item* child(int row)
    {
        return VariantPointer<Item>::asPtr(childItems_.value(row));
    }

    int childCount() const
    {
        return childItems_.count();
    }

    int row()
    {
        if (parent_)
        {
            return parent_->childItems_.indexOf(VariantPointer<Item>::asQVariant((Item *)this));
        }

        return 0;
    }

    Item* parentItem() {return parent_; }

protected:
    Item* parent_;
    QList<QVariant> childItems_;
};

#endif // TREE_MODEL_HELPERS_H

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
