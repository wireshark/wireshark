/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INHERIT_SELECTION_H
#define INHERIT_SELECTION_H

#include <wsutil/profile_inherit.h>

#include <QAbstractItemModel>
#include <QModelIndexList>
#include <QSet>
#include <QStringList>
#include <QTreeView>

#include <algorithm>

/**
 * @brief What the selected rows of a list showing inherited entries allow.
 *
 * The own entries come first, the inherited entries, which cannot be changed,
 * after them.
 */
struct InheritSelection {
    bool own_used = true;           /**< The entries of the profile are used. */
    int own_count = 0;              /**< The number of own entries. */
    int own_visible = 0;            /**< The number of own entries shown, not hidden in the view. */
    int selected_count = 0;         /**< The number of rows selected. */
    bool inherited_selected = false;/**< An inherited entry is selected. */
    bool has_inherited = false;     /**< Inherited entries are shown. */
    int first_row = -1;             /**< The first row selected. */
    int last_row = -1;              /**< The last row selected. */

    /** @brief Whether any row is selected. */
    bool selected() const { return selected_count > 0; }

    /** @brief Whether the rows selected are adjacent, as moving them needs. */
    bool contiguous() const { return selected_count == last_row - first_row + 1; }
};

/**
 * @brief Works out what the rows selected allow.
 * @param model A model with inheritMode(), ownRowCount() and isInherited(row).
 * @param indexes The selected indexes, which may hold several columns of a row.
 * @param view The view of the model, if rows may be hidden in it.
 * @return What the selection allows.
 */
template <typename Model>
InheritSelection inheritSelection(const Model *model, const QModelIndexList &indexes, const QTreeView *view = nullptr)
{
    InheritSelection sel;

    sel.own_used = model->inheritMode() != PROFILE_INHERIT_PARENT_ONLY;
    sel.own_count = model->ownRowCount();
    sel.own_visible = sel.own_count;
    for (int row = 0; view && row < sel.own_count; row++) {
        if (view->isRowHidden(row, QModelIndex()))
            sel.own_visible--;
    }
    sel.has_inherited = model->rowCount() > sel.own_count;

    QSet<int> rows;
    for (const QModelIndex &index : indexes)
        rows.insert(index.row());
    sel.selected_count = static_cast<int>(rows.count());
    for (int row : rows) {
        if (model->isInherited(row))
            sel.inherited_selected = true;
        sel.first_row = sel.first_row < 0 ? row : std::min(sel.first_row, row);
        sel.last_row = std::max(sel.last_row, row);
    }

    return sel;
}

/**
 * @brief The parent profiles the entries in use are inherited from.
 *
 * Inherited entries overridden by an own entry are not used, so a parent
 * profile having only such entries, or none, is left out.
 * @param model A model with rowCount(), isOverridden(row) and sourceProfile(row), empty for an own entry.
 * @return The profile names, in the order of the rows, nearest parent first.
 */
template <typename Model>
QStringList inheritedProfiles(const Model *model)
{
    QStringList profiles;
    for (int row = 0; row < model->rowCount(); row++) {
        QString profile = model->sourceProfile(row);
        if (!profile.isEmpty() && !model->isOverridden(row) && !profiles.contains(profile))
            profiles << profile;
    }
    return profiles;
}

/**
 * @brief Updates a path label naming the inherited profiles whenever the entries change.
 *
 * Which parent profiles the entries come from changes with the inherited
 * rows, and with the own rows, which may override inherited ones.
 * @param model The model of the entries.
 * @param receiver The dialog showing the label.
 * @param update_path_label The function updating the label.
 */
template <typename Receiver>
void followInheritedProfiles(QAbstractItemModel *model, Receiver *receiver, void (Receiver::*update_path_label)())
{
    auto update = [receiver, update_path_label]() { (receiver->*update_path_label)(); };
    QObject::connect(model, &QAbstractItemModel::rowsInserted, receiver, update);
    QObject::connect(model, &QAbstractItemModel::rowsRemoved, receiver, update);
    QObject::connect(model, &QAbstractItemModel::modelReset, receiver, update);
    QObject::connect(model, &QAbstractItemModel::dataChanged, receiver, update);
}

#endif // INHERIT_SELECTION_H
