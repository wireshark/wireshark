/* uat_tree_view.cpp
 * Tree view of UAT data.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "uat_tree_view.h"

UatTreeView::UatTreeView(QWidget *parent) : QTreeView(parent)
{
    // start editing as soon as the field is selected or when typing starts
    setEditTriggers(editTriggers() | CurrentChanged | AnyKeyPressed);
}

// Note: if a QTableView is used, then this is not needed anymore since Tab
// works as "expected" (move to next cell instead of row).
// Note 2: this does not help with fields with no widget (like filename).
QModelIndex UatTreeView::moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers)
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

void UatTreeView::currentChanged(const QModelIndex &current, const QModelIndex &previous)
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
