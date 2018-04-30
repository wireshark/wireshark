/* tabnav_tree_view.cpp
 * Tree view with saner tab navigation functionality.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tabnav_tree_view.h"

TabnavTreeView::TabnavTreeView(QWidget *parent) : QTreeView(parent)
{
}

// Note: if a QTableView is used, then this is not needed anymore since Tab
// works as "expected" (move to next cell instead of row).
// Note 2: this does not help with fields with no widget (like filename).
QModelIndex TabnavTreeView::moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers)
{
    QModelIndex current = currentIndex();
    // If an item is currently selected, interpret Next/Previous. Otherwise,
    // fallback to the default selection (e.g. first row for Next).
    if (current.isValid()) {
        if (cursorAction == MoveNext) {
            if (current.column() < model()->columnCount()) {
                return current.sibling(current.row(), current.column() + 1);
            }
            return current;
        } else if (cursorAction == MovePrevious) {
            if (current.column() > 0) {
                return current.sibling(current.row(), current.column() - 1);
            }
            return current;
        }
    }

    return QTreeView::moveCursor(cursorAction, modifiers);
}

/*!
    \fn void TabnavTreeView::currentItemChanged(QModelIndex *current, QModelIndex *previous)

    This signal is emitted whenever the current item changes.

    \a previous is the item that previously had the focus; \a current is the
    new current item.
 */

void TabnavTreeView::currentChanged(const QModelIndex &current, const QModelIndex &previous)
{
    QTreeView::currentChanged(current, previous);
    emit currentItemChanged(current, previous);
}

/* * Editor modelines
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
