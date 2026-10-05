/** @file
 *
 * Header file defining the PinnedRowView class
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PINNED_ROW_VIEW_H
#define PINNED_ROW_VIEW_H

#include <QTreeView>
#include <QPainter>
#include <QPersistentModelIndex>

class PacketList;

/**
 * @brief A QTreeView clone that shows every row of a PinnedRowsModel (i.e.
 * every currently pinned packet, packed together with no gaps), used to
 * keep pinned packets visible while the primary packet list view scrolls.
 *
 * The same class also serves as the "corner" widget when rows are pinned
 * at the same time as columns are frozen, by restricting the rendered
 * columns via setColumnRange().
 */
class PinnedRowView : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a PinnedRowView.
     * @param packet_list The primary PacketList this view mirrors rows
     * for and forwards mouse/context/wheel events to. Kept as an explicit
     * pointer (rather than assuming parentWidget() is the PacketList,
     * which no longer holds now that this widget lives inside
     * PacketListPane's layout alongside, not inside, PacketList).
     * @param parent The parent widget.
     */
    explicit PinnedRowView(PacketList *packet_list, QWidget *parent = nullptr);

    /**
     * @brief Restricts which columns this view renders.
     * @param first First column (logical index, inclusive) to show.
     * @param last Last column (logical index, inclusive) to show, or -1
     * for "through the last column".
     */
    void setColumnRange(int first, int last);

    /**
     * @brief Whether this instance is currently acting as the "corner"
     * widget (the frozen-column portion of the pinned-row strip, shown
     * alongside PinnedColumnView's own frozen-column overlay) rather
     * than the main pinned-row strip covering the remaining columns.
     *
     * Both first_column_ == 0 and last_column_ >= 0 are required: the
     * main pinned-row strip's own range is set to (pinned_column_boundary_,
     * -1), which also starts at column 0 whenever no columns are
     * currently frozen (pinned_column_boundary_ == 0) -- first_column_
     * == 0 alone (what right_divider_'s own visibility already checks,
     * harmlessly there since the corner instance is simply hidden
     * whenever that ambiguity would matter) can't distinguish that case
     * from the corner's own range, which is always a bounded
     * [0, boundary - 1] and so never has last_column_ == -1.
     *
     * Used by MultiColorPacketDelegate to paint this instance the same
     * flat-fill way as PinnedColumnView -- unlike the main pinned-row
     * strip, which follows the primary view's real stripe/shift-right
     * pattern -- since the corner only ever shows a narrow, frozen slice
     * of the row, same as PinnedColumnView.
     */
    bool isCornerView() const { return first_column_ == 0 && last_column_ >= 0; }

    /**
     * @brief The primary PacketList this view mirrors rows for. Used by
     * MultiColorPacketDelegate to compute the scrollbar-adjusted usable
     * width the same way drawRow()'s own scrollbar-sliver calculation does.
     */
    PacketList *packetList() const { return packet_list_; }

    // Mirrors a single section's width from the primary view's header.
    void mirrorSectionWidth(int column, int width);

    /**
     * @brief The height needed to show all of this model's rows stacked
     * with no gaps, given the shared row height. 0 if no rows are pinned.
     */
    QSize sizeHint() const override;

public slots:
    // Mirrors the primary view's horizontal scroll position.
    void setHorizontalScrollValue(int value);

protected:
    /**
     * @brief Widens this view's horizontal scroll range to the primary
     * view's. QTreeView derives the range from its own content and
     * viewport widths, which differ from the primary view's (frozen
     * columns hidden here, scrollbar width), so at the far right edge
     * this view would otherwise clamp short and stop scrolling while the
     * primary view keeps going, misaligning the pinned rows' columns.
     */
    void updateGeometries() override;

    /**
     * @brief Selects the clicked pinned row in this view's own selection
     * model (linked to the primary packet list's by PacketList), marks it
     * on a middle click, and arms a cell drag.
     */
    void mousePressEvent(QMouseEvent *event) override;

    // Ends a click, dispatching it to the column's delegate.
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

    // Forwards wheel scrolling to the primary packet list.
    void wheelEvent(QWheelEvent *event) override;

    /**
     * @brief Draws the hover highlight (which spans every pane) and the
     * "packet separator" line, mirroring PacketList::drawRow().
     */
    void drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Keeps the "corner" boundary-divider widget sized to this
     * view's full height whenever it's resized.
     */
    void resizeEvent(QResizeEvent *event) override;

private:
    PacketList *packet_list_;
    int first_column_;
    int last_column_;

    // Cell pressed with the left button, used to start a cell drag on the
    // first mouse move within it (as PacketList does). Invalid when no
    // drag is armed.
    QPersistentModelIndex drag_index_;

    /** Visual boundary marker shown only when this instance acts as the
     * "corner" widget (columns starting at 0); see PinnedColumnView. */
    QWidget *right_divider_;

    void applyColumnVisibility();
};

#endif // PINNED_ROW_VIEW_H
