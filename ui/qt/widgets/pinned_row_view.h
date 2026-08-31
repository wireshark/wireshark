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
#include <QSet>

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

    // Forwards wheel scrolling to the primary packet list.
    void wheelEvent(QWheelEvent *event) override;

    /**
     * @brief Draws the selection and hover highlights (this view's model
     * is a separate proxy, so it can't rely on a shared QItemSelectionModel
     * the way PinnedColumnView does) and the "packet separator" line,
     * mirroring PacketList::drawRow().
     */
    void drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Keeps the "corner" boundary-divider widget sized to this
     * view's full height whenever it's resized.
     */
    void resizeEvent(QResizeEvent *event) override;

    /**
     * @brief Refreshes selected_frame_nums_cache_ once per paint pass
     * before deferring to QTreeView's own paintEvent(), which calls
     * drawRow() once per visible row -- see the cache's own comment for
     * why this avoids a per-row rescan of the primary view's selection.
     *
     * Rebuilt unconditionally on every repaint (hover, scroll, resize),
     * not only when the primary view's selection has actually changed:
     * threading a dirty flag through from PacketList::selectionChanged()
     * would avoid the rebuild on paints where selection didn't change,
     * but the cost either way is bounded tightly by
     * PinnedRowsModel::kMaxPinnedRows (currently 10) pinned rows against
     * however many rows are selected in the primary view -- not worth the
     * added plumbing for a cost this small and this bounded.
     */
    void paintEvent(QPaintEvent *event) override;

private:
    PacketList *packet_list_;
    int first_column_;
    int last_column_;

    /**
     * @brief Frame numbers selected in the primary view, as of the start
     * of the current paint pass. drawRow() is called once per visible
     * pinned row per repaint, and previously called
     * packet_list_->selectedRows(true) (which itself rebuilds a QList from
     * the selection model plus a getFDataForRow() lookup per selected row)
     * and linearly scanned it for every single one of those calls;
     * refreshed once per paintEvent() instead, so each drawRow() call just
     * does an O(1) set lookup.
     */
    mutable QSet<int> selected_frame_nums_cache_;

    /** Visual boundary marker shown only when this instance acts as the
     * "corner" widget (columns starting at 0); see PinnedColumnView. */
    QWidget *right_divider_;

    void applyColumnVisibility();
};

#endif // PINNED_ROW_VIEW_H
