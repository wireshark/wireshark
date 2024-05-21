/* @file
 * Tree view that uses the model's moveRows(), if implemented, to
 * support internalMoves. The model must also have Qt::MoveAction
 * among the supportedDropActions, and its item flags must allow drag
 * and drop.
 *
 * The normal Qt Drag and Drop approach for moves involves inserting a
 * new row and removing the original row. That has greater generality,
 * but works poorly for views like the I/O Graphs Dialog where a newly
 * inserted row would require an expensive retap.
 *
 * Copyright 2024 John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rowmove_tree_view.h"

#include <QDropEvent>

RowMoveTreeView::RowMoveTreeView(QWidget *parent) : TabnavTreeView(parent)
{
    // QTreeViews default to row selection.
    // setSelectionMode(QAbstractItemView::ContiguousSelection);
    // ContiguousSelection works, but we probably want to make sure
    // that the models we use this for can handle removing multiple
    // rows (and that the dialogs support doing that.)
    setDropIndicatorShown(true);
    // We could override dragMoveEvent to have the dropIndicator cover
    // the entire row.
    setDragDropMode(QAbstractItemView::InternalMove);
    // Classes can change this if they also support other drag and drop
    // modes.
}

void RowMoveTreeView::dropEvent(QDropEvent *event)
{
    if (event->source() == this && (event->possibleActions() & Qt::MoveAction) && !event->isAccepted()) {

        const QModelIndexList sourceIndices = selectionModel()->selectedRows();

        if (sourceIndices.empty()) {
            TabnavTreeView::dropEvent(event);
            return;
        }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        QModelIndex destIndex = indexAt(event->position().toPoint());
#else
        QModelIndex destIndex = indexAt(event->pos());
#endif
        if (!destIndex.isValid() || destIndex.row() == -1) {
            destIndex = model()->index(model()->rowCount() - 1, 0);
        }
        // dropIndicatorPosition() can be used to determine if we're slightly
        // above the item, slightly below the item, on top, or elsewhere in
        // the viewPort. We will just use the row number, table-like.
        // Note that if we setDragDropOverwriteMode(true) then there wouldn't
        // be graphical hints in between rows, but that could cause issues
        // if we added non internalMove handling; overriding dragMoveEvent
        // could also change it.

        const auto minmaxIndex = std::minmax_element(sourceIndices.begin(), sourceIndices.end(),
            [](const QModelIndex &a, const QModelIndex &b)
            { return a.row() < b.row(); }
        );

        // Only allow a contiguous selection. (This check is unnecessary
        // if the selectionMode is SingleSelection or ContiguousSelection.)
        // We could handle multiple ranges with multiple moveRows() calls
        // and QPersistentModelIndexes in place of the QModelIndexes, but
        // it gets a little confusing, especially if some indices are above
        // the target row and some are below (the default behavior would be
        // to move all the indices above to immediately below, and vice versa.)
        // Microsoft Excel doesn't allow row moves unless the selected
        // rows are contiguous, and has an alert.
        //
        // Note that selectionModel()->selection()->size() is *not*
        // guaranteed to be the minimal merged number of possible ranges
        // if the selection order was unusual, so we can't just use it.
        if ((minmaxIndex.second->row() - minmaxIndex.first->row() + 1) == sourceIndices.size()) {
            if (model()->moveRows(QModelIndex(), minmaxIndex.first->row(), static_cast<int>(sourceIndices.size()), QModelIndex(), destIndex.row())) {
                // Prevent QAbstractItemView from removing the sourceIndices
                // There's an element in the private class (dropEventMoved)
                // that QTreeWidget and QTableWidget use via the d-pointer,
                // but as long as the action is no longer a MoveAction when
                // it returns it won't get removed.
                event->setDropAction(Qt::IgnoreAction);
                event->accept();
            }
        }
    }
    TabnavTreeView::dropEvent(event);
}
