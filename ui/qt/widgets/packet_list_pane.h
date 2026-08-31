/** @file
 *
 * Header file defining the PacketListPane class
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LIST_PANE_H
#define PACKET_LIST_PANE_H

#include <QWidget>

class PacketList;
class PinnedRowView;
class QHBoxLayout;
class QHeaderView;

/**
 * @brief Sibling container for PacketList and its pinned-rows strip.
 *
 * QTreeView reserves viewport space for its own header internally and
 * reasserts that reservation on every geometry pass, so reserving
 * additional space above the viewport via setViewportMargins() cannot
 * coexist with it -- QTreeView silently overwrites the margin change.
 * Placing the pinned-rows strip as a genuine sibling widget in a normal
 * QVBoxLayout above PacketList instead lets Qt's own layout system
 * reserve that space, with no fight against QTreeView's internals.
 *
 * This pane owns and positions the pinned-row strip widgets
 * (pinned_row_view_/pinned_row_corner_view_); PacketList continues to
 * manage their content/properties (model, column widths, styles, fonts,
 * delegates, column visibility) exactly as before, via pointers handed
 * back to it through PacketList::setPinnedRowViews().
 *
 * Also owns a standalone duplicate header (split into
 * duplicate_header_corner_ and duplicate_header_main_, a plain QHeaderView
 * pair mirroring every column between them), shown directly above the
 * pinned-rows strip and hidden otherwise -- split the same way
 * pinned_rows_strip_ itself is split into pinned_row_corner_view_ (frozen
 * columns, never scrolled) and pinned_row_view_ (the rest, scrolled with
 * the primary view), so the frozen columns' header titles stay in place
 * while the rest scroll horizontally along with the real rows below.
 * PacketList's own native header lives inside PacketList itself (before/
 * above the scrolling rows in its own internal layout), so with the
 * pinned-rows strip sitting above PacketList as a whole, the native
 * header would end up sandwiched between the strip and the scrolling
 * rows -- below the strip, not above it. Rather than fight QTreeView's
 * internal header/viewport coupling to actually relocate the native
 * header (see the class comment above -- attempted and found to durably
 * corrupt QTreeView's own header layout, even for an all-zero margin),
 * the native header is simply hidden whenever something is pinned, and
 * this lookalike duplicate pair is shown above the strip in its place;
 * the two are never visible at the same time, so there's no risk of them
 * drifting out of sync with each other on screen.
 *
 * Deliberately plain QHeaderViews (handling their own resize-drag/
 * sort-click natively) rather than reusing PinnedColumnHeader, which
 * forwards raw mouse events to the real (in this case hidden) header to
 * drive its resize-drag state machine -- appropriate for
 * pinned_column_view_'s own header, which is always visible alongside the
 * real one and needs synced drag state, but not here: forwarding a mouse
 * event to a hidden QHeaderView was observed to trigger a paint attempt
 * on it while genuinely unpaintable (QPainter::begin failing with
 * "engine == 0"). Sync between the duplicate and real headers instead
 * happens purely at the data level (resizeSection()/setSortIndicator()
 * calls in both directions), never through forwarded input events.
 */
class PacketListPane : public QWidget
{
    Q_OBJECT
public:
    explicit PacketListPane(QWidget *parent = nullptr);

    PacketList *packetList() { return packet_list_; }

protected:
    /**
     * @brief Forwards a right-click on duplicate_header_corner_/
     * duplicate_header_main_ to the real header's own context menu
     * (Column Preferences, alignment, display format, etc.) via
     * PacketList::forwardHeaderContextMenu() -- the same forwarding
     * pinned_column_view_'s own header already uses. Needed because
     * neither duplicate header has context menu handling of its own
     * (they're plain QHeaderViews -- see the class comment for why they
     * don't reuse PinnedColumnHeader, which normally provides this). An
     * event filter rather than a QHeaderView subclass override, since
     * both are deliberately plain QHeaderViews with no subclass of their
     * own to override contextMenuEvent() on.
     */
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    PacketList *packet_list_;

    /** @brief Wraps the pinned-row strip's QHBoxLayout so the whole strip
     * can be hidden (collapsing to zero height) independent of the two
     * views' own individual visibility. */
    QWidget *pinned_rows_strip_;
    QHBoxLayout *pinned_rows_layout_;
    PinnedRowView *pinned_row_corner_view_;
    PinnedRowView *pinned_row_view_;

    /** @brief Thin horizontal divider marking the boundary between
     * pinned_rows_strip_ and packet_list_ itself, shown/hidden alongside
     * the strip (there's nothing to mark a boundary against when nothing
     * is pinned). Deliberately a real widget with its own background
     * color rather than relying on packet_list_'s default QFrame border,
     * which reads as too faint a separation from the pinned content
     * directly above it. */
    QWidget *pinned_rows_divider_;

    /** @brief Wraps duplicate_header_corner_/duplicate_header_main_ in a
     * QHBoxLayout, mirroring pinned_rows_strip_'s own corner/main split,
     * so the whole duplicate header pair can be hidden/shown as one unit
     * above the pinned-rows strip. */
    QWidget *duplicate_header_strip_;
    QHBoxLayout *duplicate_header_layout_;

    /** @brief Standalone headers shown above the pinned-rows strip in
     * place of PacketList's own (hidden while these are visible) native
     * header -- see the class comment for why. duplicate_header_corner_
     * shows the frozen columns (never scrolled); duplicate_header_main_
     * shows the rest (scrolled with the primary view's horizontal
     * scrollbar). */
    QHeaderView *duplicate_header_corner_;
    QHeaderView *duplicate_header_main_;

private slots:
    /**
     * @brief Resizes the pinned-row strip's corner widget to match the
     * primary view's current frozen-column width, and shows/hides the
     * whole strip (and the duplicate header above it, and PacketList's
     * own native header) depending on whether anything is pinned.
     * Connected to PacketList::pinnedRowsCornerWidthChanged(), which
     * already fires whenever column widths, the pinned column boundary,
     * or the pinned row set change.
     * @param corner_width Width, in pixels, of the frozen-column portion.
     * @param have_pinned_rows Whether at least one row is currently
     * pinned. Passed explicitly rather than inferred from the row views'
     * own isVisible(), since those views are nested inside the strip
     * widget being shown/hidden here -- a hidden ancestor makes
     * isVisible() false on its children regardless of their own
     * show/hide flag, so it can never observe becoming true.
     */
    void updatePinnedRowsStripWidth(int corner_width, bool have_pinned_rows);
};

#endif // PACKET_LIST_PANE_H
