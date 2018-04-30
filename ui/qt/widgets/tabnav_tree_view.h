/* tabnav_tree_view.h
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

#ifndef TABNAV_TREE_VIEW_H
#define TABNAV_TREE_VIEW_H

#include <config.h>
#include <QTreeView>

/**
 * Like QTreeView, but instead of changing to the next row (same column) when
 * pressing Tab while editing, change to the next column (same row).
 */
class TabnavTreeView : public QTreeView
{
    Q_OBJECT

public:
    TabnavTreeView(QWidget *parent = 0);
    QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers);

protected slots:
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);

signals:
    void currentItemChanged(const QModelIndex &current, const QModelIndex &previous);
};
#endif // TABNAV_TREE_VIEW_H

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
