/** @file
 *
 * Header file defining the PinnedColumnView class
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PINNED_COLUMN_VIEW_H
#define PINNED_COLUMN_VIEW_H

#include <QTreeView>
#include <QPainter>

class QAbstractItemModel;
class QItemSelectionModel;
class PacketList;

/**
 * @brief A QTreeView clone showing only a leftmost run of columns from a
 * shared model, used to keep "frozen" columns visible while the primary
 * packet list view scrolls horizontally.
 *
 * This view shares its model and selection model with the primary view so
 * that clicking a row here selects the same row there, and reuses the
 * primary view's item delegates so that rendering matches exactly.
 */
class PinnedColumnView : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @param packet_list The primary view this pane mirrors; passed
     * through to its own header (see PinnedColumnHeader) since header
     * mouse events need to be forwarded there.
     * @param parent The parent widget (normally the same PacketList).
     */
    explicit PinnedColumnView(PacketList *packet_list, QWidget *parent = nullptr);

    /**
     * @brief Sets how many leftmost columns (by logical/visual index,
     * which are kept identical in the packet list) should be shown.
     * @param column_count 0 hides this view entirely.
     */
    void setFrozenColumnCount(int column_count);

    /**
     * @brief Mirrors a single section's width from the primary view's header.
     * @param column The column (logical index) to mirror.
     * @param width The new width.
     */
    void mirrorSectionWidth(int column, int width);

    /**
     * @brief Forces this view's own header to the same height as the
     * primary view's header (a plain QHeaderView's sizeHint() otherwise
     * differs from PacketListHeader's zoom-aware one).
     */
    void mirrorHeaderHeight(int height);

    /**
     * @brief Forces a row-layout recompute. Must be called after this
     * view's final geometry is set, since QTreeView computes its vertical
     * scroll range from the viewport size at layout time; calling this
     * before setGeometry() gives a stale (often zero) scroll range.
     */
    void refreshLayout();

    /**
     * @brief Mirrors the primary view's sort indicator (the arrow icon)
     * onto this view's own header, which is a separate QHeaderView and
     * doesn't otherwise follow it automatically.
     */
    void mirrorSortIndicator(int column, Qt::SortOrder order);

public slots:
    /**
     * @brief Mirrors the primary view's vertical scroll position.
     * @param value The new scrollbar value.
     */
    void setVerticalScrollValue(int value);

protected:
    /**
     * @brief Forwards mouse presses to the primary packet list so that
     * selection/marking behavior matches clicking the main view exactly.
     */
    void mousePressEvent(QMouseEvent *event) override;

    // Forwards mouse releases to the primary packet list.
    void mouseReleaseEvent(QMouseEvent *event) override;

    /**
     * @brief Reports the row under the mouse to the primary packet list so
     * the hover highlight can be shown across every pane, not just this one.
     */
    void mouseMoveEvent(QMouseEvent *event) override;

    // Clears the reported hover row when the mouse leaves this view.
    void leaveEvent(QEvent *event) override;

    // Forwards context menu requests to the primary packet list.
    void contextMenuEvent(QContextMenuEvent *event) override;

    /**
     * @brief Forwards wheel scrolling to the primary packet list instead
     * of scrolling this view's own (hidden) scrollbar independently, which
     * would desync the two views' vertical positions.
     */
    void wheelEvent(QWheelEvent *event) override;

    /**
     * @brief Draws the "packet separator" line under each row, mirroring
     * PacketList::drawRow(), since gui_packet_list_separator is otherwise
     * only ever applied by that class's own override.
     */
    void drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Keeps the right-edge divider widget sized to this pane's
     * full height whenever it's resized.
     */
    void resizeEvent(QResizeEvent *event) override;

private:
    PacketList *packet_list_;
    int frozen_column_count_;

    /** A thin child widget marking the boundary between the frozen and
     * non-frozen columns. A plain QPainter(this) can't be used directly on
     * a QAbstractScrollArea-derived widget like QTreeView (Qt redirects
     * painting to the viewport, not the widget itself), so this is a real
     * (if trivial) child widget instead of a custom paintEvent(). */
    QWidget *right_divider_;
};

#endif // PINNED_COLUMN_VIEW_H
