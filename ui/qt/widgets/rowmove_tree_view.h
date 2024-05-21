/** @file
 *
 * Tree view that uses a model's moveRows(), if implemented, to support
 * internalMoves.
 *
 * Copyright 2024 John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ROWMOVE_TREE_VIEW_H
#define ROWMOVE_TREE_VIEW_H

#include <config.h>
#include <ui/qt/widgets/tabnav_tree_view.h>

/**
 * Like QTreeView, but instead of changing to the next row (same column) when
 * pressing Tab while editing, change to the next column (same row).
 */
class RowMoveTreeView : public TabnavTreeView
{
    Q_OBJECT

public:
    RowMoveTreeView(QWidget *parent = nullptr);

protected:
    void dropEvent(QDropEvent *event) override;
};
#endif // ROWMOVE_TREE_VIEW_H
