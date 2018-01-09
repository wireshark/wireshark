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

    int row() const
    {
        if (parent_)
            return parent_->childItems_.indexOf(VariantPointer<Item>::asQVariant((Item*)this));

        return 0;
    }

    Item* parentItem() {return parent_; }

protected:
    Item* parent_;
    QList<QVariant> childItems_;
};

//XXX - Qt 4.8 doesn't work with these types of templated classes, so save the functionality for now.
#ifdef WIRESHARK_SUPPORTS_QT_5_0_MINIMUM

//Base class to inherit basic model for tree
template <typename Item>
class ModelHelperTreeModel : public QAbstractItemModel
{
public:
    explicit ModelHelperTreeModel(QObject * parent = Q_NULLPTR) : QAbstractItemModel(parent),
        root_(NULL)
    {
    }

    virtual ~ModelHelperTreeModel()
    {
        delete root_;
    }

    virtual QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const
    {
        if (!hasIndex(row, column, parent))
            return QModelIndex();

        Item *parent_item, *child_item;

        if (!parent.isValid())
            parent_item = root_;
        else
            parent_item = static_cast<Item*>(parent.internalPointer());

        Q_ASSERT(parent_item);

        child_item = parent_item->child(row);
        if (child_item) {
            return createIndex(row, column, child_item);
        }

        return QModelIndex();
    }

    virtual QModelIndex parent(const QModelIndex& indexItem) const
    {
        if (!indexItem.isValid())
            return QModelIndex();

        Item* item = static_cast<Item*>(indexItem.internalPointer());
        if (item != NULL) {
            Item* parent_item = item->parentItem();
            if (parent_item != NULL) {
                if (parent_item == root_)
                    return QModelIndex();

                return createIndex(parent_item->row(), 0, parent_item);
            }
        }

        return QModelIndex();
    }

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const
    {
        Item *parent_item;

        if (parent.column() > 0)
            return 0;

        if (!parent.isValid())
            parent_item = root_;
        else
            parent_item = static_cast<Item*>(parent.internalPointer());

        if (parent_item == NULL)
            return 0;

        return parent_item->childCount();
    }

protected:
    Item* root_;

};
#endif



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
