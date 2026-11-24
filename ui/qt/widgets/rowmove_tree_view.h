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

#include <QPixmap>
#include <QPoint>

/**
 * @brief A tree view that moves to the next column (same row) on Tab while editing,
 *        rather than the next row (same column) as QTreeView does by default.
 *
 * Rows are moved with the model's moveRows(), by dragging them or with
 * moveSelectedRowsUp() and moveSelectedRowsDown(). The dragged rows are
 * painted in the view, the same on all platforms.
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

public slots:
    /** @brief Moves the selected rows, which must be contiguous, one row up. */
    void moveSelectedRowsUp();

    /** @brief Moves the selected rows, which must be contiguous, one row down. */
    void moveSelectedRowsDown();

protected:
    /**
     * @brief Paints the view, and the rows being dragged at the cursor.
     * @param event The paint event to process.
     */
    void paintEvent(QPaintEvent *event) override;

    /**
     * @brief Stops painting the dragged rows once the drag leaves the view.
     * @param event The drag leave event to process.
     */
    void dragLeaveEvent(QDragLeaveEvent *event) override;

    /**
     * @brief Refuses a drop only where no row takes it.
     * @param event The drag move event to process.
     */
    void dragMoveEvent(QDragMoveEvent *event) override;

    /**
     * @brief Handles drop events for row reordering within the tree.
     * @param event The drop event to process.
     */
    void dropEvent(QDropEvent *event) override;

    /**
     * @brief Notes whether the pressed row can be dragged.
     * @param event The mouse press event to process.
     */
    void mousePressEvent(QMouseEvent *event) override;

    /**
     * @brief Ignores moves after a press on a row that can't be dragged,
     *        so that neither a drag nor a drag selection starts there.
     * @param event The mouse move event to process.
     */
    void mouseMoveEvent(QMouseEvent *event) override;

    /**
     * @brief Ends the press started by mousePressEvent().
     * @param event The mouse release event to process.
     */
    void mouseReleaseEvent(QMouseEvent *event) override;

    /**
     * @brief Starts a drag only if all the selected rows can be dragged.
     *
     * The full selected rows are painted in the view while dragging, and the
     * platform shows no drag image of its own, which it may fade or scale.
     * @param supportedActions The supported drag actions.
     */
    void startDrag(Qt::DropActions supportedActions) override;

private:
    /**
     * @brief Whether rows can be dragged.
     * @param rows The rows to check.
     * @return True if the list isn't empty, the rows are contiguous and every row can be dragged.
     */
    bool rowsDraggable(const QModelIndexList &rows) const;

    /**
     * @brief The row that rows dropped at a position move to.
     *
     * A drop on a row that can't be dropped on, or below the rows, goes to
     * the last row above it that can.
     * @param pos The position in the viewport.
     * @return The row, or -1 if no row takes the drop.
     */
    int dropRow(const QPoint &pos) const;

    /**
     * @brief Moves the selected rows one row.
     * @param up True to move them up, false to move them down.
     */
    void moveSelectedRows(bool up);

    /** @brief Set while the left button is held after a press on a row that can't be dragged. */
    bool press_inert_ = false;

    QPixmap drag_pixmap_; /**< Image of the dragged rows while dragging. */
    QPoint drag_offset_; /**< Cursor position inside the drag image. */
    QPoint drag_pos_ = QPoint(-1, -1); /**< Cursor position in the viewport while dragging. */
};
#endif // ROWMOVE_TREE_VIEW_H
