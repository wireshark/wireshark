/* tabnav_tree_widget.h
 * Tree widget with saner tab navigation properties.
 *
 * Copyright 2017 Peter Wu <peter@lekensteyn.nl>
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

#ifndef TABNAV_TREE_WIDGET_H
#define TABNAV_TREE_WIDGET_H

#include <config.h>
#include <QTreeWidget>

/**
 * Like QTreeWidget, but instead of changing to the next row (same column) when
 * pressing Tab while editing, change to the next column (same row).
 */
class TabnavTreeWidget : public QTreeWidget
{
    Q_OBJECT
public:
    TabnavTreeWidget(QWidget *parent = 0);
    QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers);
};
#endif // TABNAV_TREE_WIDGET_H

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
