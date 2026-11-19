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

#include <algorithm>

#include <QCursor>
#include <QDrag>
#include <QDropEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPixmap>

RowMoveTreeView::RowMoveTreeView(QWidget *parent) : TabnavTreeView(parent)
{
    // QTreeViews default to row selection. Any rows can be selected,
    // but only a contiguous block can be dragged (see rowsDraggable()).
    setSelectionMode(QAbstractItemView::ExtendedSelection);
    setDropIndicatorShown(true);
    // We could override dragMoveEvent to have the dropIndicator cover
    // the entire row.
    setDragDropMode(QAbstractItemView::InternalMove);
    // Classes can change this if they also support other drag and drop
    // modes.
}

void RowMoveTreeView::moveSelectedRowsUp()
{
    moveSelectedRows(true);
}

void RowMoveTreeView::moveSelectedRowsDown()
{
    moveSelectedRows(false);
}

void RowMoveTreeView::moveSelectedRows(bool up)
{
    if (!selectionModel())
        return;

    const QModelIndexList rows = selectionModel()->selectedRows();
    if (!rowsDraggable(rows))
        return;

    const auto minmaxIndex = std::minmax_element(rows.begin(), rows.end(),
        [](const QModelIndex &a, const QModelIndex &b)
        { return a.row() < b.row(); }
    );
    int top = minmaxIndex.first->row();
    int bottom = minmaxIndex.second->row();
    // Past the rows hidden in the view, so that the move can be seen
    int destination = up ? top - 1 : bottom + 1;
    while (destination >= 0 && destination < model()->rowCount() && isRowHidden(destination, QModelIndex()))
        destination += up ? -1 : 1;
    if (destination < 0 || destination >= model()->rowCount())
        return;

    // The models refuse moves out of the rows that can be moved
    model()->moveRows(QModelIndex(), top, bottom - top + 1, QModelIndex(), destination);
    scrollTo(currentIndex());
}

void RowMoveTreeView::paintEvent(QPaintEvent *event)
{
    TabnavTreeView::paintEvent(event);

    // The dragged rows
    if (!drag_pixmap_.isNull() && drag_pos_ != QPoint(-1, -1)) {
        QPainter painter(viewport());
        painter.drawPixmap(drag_pos_ - drag_offset_, drag_pixmap_);
    }
}

void RowMoveTreeView::dragLeaveEvent(QDragLeaveEvent *event)
{
    drag_pos_ = QPoint(-1, -1);
    viewport()->update();
    TabnavTreeView::dragLeaveEvent(event);
}

void RowMoveTreeView::dragMoveEvent(QDragMoveEvent *event)
{
    TabnavTreeView::dragMoveEvent(event);
    drag_pos_ = event->position().toPoint();
    viewport()->update();
    // A drop on rows that can't be dropped on, such as inherited records,
    // or below them goes to the last row above them that can, so it is
    // refused only if there is none.
    if (event->source() == this) {
        if (dropRow(event->position().toPoint()) >= 0)
            event->accept();
        else
            event->ignore();
    }
}

void RowMoveTreeView::dropEvent(QDropEvent *event)
{
    if (event->source() == this && (event->possibleActions() & Qt::MoveAction) && !event->isAccepted()) {

        const QModelIndexList sourceIndices = selectionModel()->selectedRows();

        if (sourceIndices.empty()) {
            TabnavTreeView::dropEvent(event);
            return;
        }

        int destRow = dropRow(event->position().toPoint());
        // dropIndicatorPosition() can be used to determine if we're slightly
        // above the item, slightly below the item, on top, or elsewhere in
        // the viewPort. We will just use the row number, table-like.
        // Note that if we setDragDropOverwriteMode(true) then there wouldn't
        // be graphical hints in between rows, but that could cause issues
        // if we added non internalMove handling.

        if (rowsDraggable(sourceIndices) && destRow >= 0) {
            const auto minIndex = std::min_element(sourceIndices.begin(), sourceIndices.end(),
                [](const QModelIndex &a, const QModelIndex &b)
                { return a.row() < b.row(); }
            );
            model()->moveRows(QModelIndex(), minIndex->row(), static_cast<int>(sourceIndices.size()), QModelIndex(), destRow);
        }

        // The move is done here or not at all. QAbstractItemView would
        // otherwise pass the drop to the model's dropMimeData(), and remove
        // the source rows after a drop that returns a MoveAction. There's an
        // element in the private class (dropEventMoved) that QTreeWidget and
        // QTableWidget use via the d-pointer, but as long as the action is
        // no longer a MoveAction when it returns they won't get removed.
        event->setDropAction(Qt::IgnoreAction);
        event->accept();
        stopAutoScroll();
        setState(NoState);
        viewport()->update();
        return;
    }
    TabnavTreeView::dropEvent(event);
}

bool RowMoveTreeView::rowsDraggable(const QModelIndexList &rows) const
{
    if (!model() || rows.isEmpty())
        return false;

    for (const QModelIndex &index : rows) {
        if (!(model()->flags(index) & Qt::ItemIsDragEnabled))
            return false;
    }

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
    const auto minmaxIndex = std::minmax_element(rows.begin(), rows.end(),
        [](const QModelIndex &a, const QModelIndex &b)
        { return a.row() < b.row(); }
    );
    return (minmaxIndex.second->row() - minmaxIndex.first->row() + 1) == rows.size();
}

int RowMoveTreeView::dropRow(const QPoint &pos) const
{
    if (!model())
        return -1;

    // Below the rows is the same as on the last row
    QModelIndex index = indexAt(pos);
    int row = index.isValid() ? index.row() : model()->rowCount() - 1;
    for (; row >= 0; row--) {
        if (model()->flags(model()->index(row, 0)) & Qt::ItemIsDropEnabled)
            return row;
    }
    return -1;
}

void RowMoveTreeView::mousePressEvent(QMouseEvent *event)
{
    press_inert_ = false;
    if (event->button() == Qt::LeftButton && model()) {
        QModelIndex index = indexAt(event->position().toPoint());
        press_inert_ = index.isValid() && !(model()->flags(index) & Qt::ItemIsDragEnabled);
    }
    TabnavTreeView::mousePressEvent(event);
}

void RowMoveTreeView::mouseMoveEvent(QMouseEvent *event)
{
    // A press on a row that can't be dragged would otherwise extend the
    // selection into the rows moved over, or drag the rows of the
    // selection that can be dragged.
    if (press_inert_ && (event->buttons() & Qt::LeftButton)) {
        event->accept();
        return;
    }
    TabnavTreeView::mouseMoveEvent(event);
}

void RowMoveTreeView::mouseReleaseEvent(QMouseEvent *event)
{
    press_inert_ = false;
    TabnavTreeView::mouseReleaseEvent(event);
}

void RowMoveTreeView::startDrag(Qt::DropActions supportedActions)
{
    // QAbstractItemView drags only the indexes that can be dragged, while
    // dropEvent() moves all the selected rows.
    if (!selectionModel() || !rowsDraggable(selectionModel()->selectedRows()))
        return;

    QModelIndexList rows = selectionModel()->selectedRows();
    std::sort(rows.begin(), rows.end(), [](const QModelIndex &a, const QModelIndex &b) {
        return a.row() < b.row();
    });
    QMimeData *data = model()->mimeData(rows);
    if (!data)
        return;

    // Paint the full rows, the same on all platforms, as QAbstractItemView
    // paints only the cells on a transparent background.
    QStyleOptionViewItem option;
    initViewItemOption(&option);
    option.state |= QStyle::State_Selected | QStyle::State_Active;
    option.state &= ~(QStyle::State_MouseOver | QStyle::State_HasFocus);
    int width = viewport()->width();
    int height = 0;
    for (const QModelIndex &row : rows)
        height += visualRect(row).height();
    qreal ratio = devicePixelRatioF();
    QPixmap pixmap(QSize(width, height) * ratio);
    pixmap.setDevicePixelRatio(ratio);
    pixmap.fill(palette().color(QPalette::Base));
    {
        QPainter painter(&pixmap);
        int y = 0;
        for (const QModelIndex &row : rows) {
            int row_height = visualRect(row).height();
            for (int column = 0; column < model()->columnCount(row.parent()); column++) {
                if (isColumnHidden(column))
                    continue;
                QModelIndex index = row.siblingAtColumn(column);
                QRect rect = visualRect(index);
                option.rect = QRect(rect.x(), y, rect.width(), row_height);
                itemDelegateForIndex(index)->paint(&painter, option, index);
            }
            y += row_height;
        }
        painter.setPen(palette().color(QPalette::Mid));
        painter.drawRect(QRect(0, 0, width, height).adjusted(0, 0, -1, -1));
    }

    QPoint offset = viewport()->mapFromGlobal(QCursor::pos()) - QPoint(0, visualRect(rows.first()).top());
    offset.setX(qBound(0, offset.x(), width - 1));
    offset.setY(qBound(0, offset.y(), height - 1));

    // The rows are painted in the view. The platform gets an empty image,
    // as it may fade or scale a large one.
    drag_pixmap_ = pixmap;
    drag_offset_ = offset;
    QPixmap empty(1, 1);
    empty.fill(Qt::transparent);

    QDrag *drag = new QDrag(this);
    drag->setMimeData(data);
    drag->setPixmap(empty);
    drag->setHotSpot(QPoint(0, 0));
    // dropEvent() moves the rows, so nothing is removed after the drag
    drag->exec(supportedActions, Qt::MoveAction);

    drag_pixmap_ = QPixmap();
    drag_pos_ = QPoint(-1, -1);
    viewport()->update();
}
