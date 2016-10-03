/* uat_tree_view.h
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

#ifndef UAT_TREE_VIEW_H
#define UAT_TREE_VIEW_H

#include <config.h>
#include <QTreeView>

class UatTreeView : public QTreeView
{
    Q_OBJECT
public:
    UatTreeView(QWidget *parent = 0);
    QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers);

protected slots:
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);

signals:
    void currentItemChanged(const QModelIndex &current, const QModelIndex &previous);
};
#endif // UAT_TREE_VIEW_H
