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
 * @brief A tree view that moves to the next column (same row) on Tab while editing,
 *        rather than the next row (same column) as QTreeView does by default.
 */
class RowMoveTreeView : public TabnavTreeView
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the row-move tree view.
     * @param parent The parent widget.
     */
    RowMoveTreeView(QWidget *parent = nullptr);

protected:
    /**
     * @brief Handles drop events for row reordering within the tree.
     * @param event The drop event to process.
     */
    void dropEvent(QDropEvent *event) override;
};
#endif // ROWMOVE_TREE_VIEW_H
