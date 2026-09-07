/* packet_list_pane.cpp
 *
 * Sibling container for PacketList and its pinned-rows strip
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/packet_list_pane.h>

#include <ui/qt/packet_list.h>
#include <ui/qt/widgets/pinned_row_view.h>

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSizePolicy>
#include <QHeaderView>
#include <QSignalBlocker>
#include <QEvent>
#include <QContextMenuEvent>
#include <QScrollBar>
#include <QPalette>

namespace {

// Shared setup for duplicate_header_corner_/duplicate_header_main_ --
// see PacketListPane's own class comment for why these are plain
// QHeaderViews rather than PinnedColumnHeader instances.
void setUpDuplicateHeader(QHeaderView *header, QAbstractItemModel *model)
{
    header->setModel(model);
    header->setSectionsMovable(false);
    header->setSectionResizeMode(QHeaderView::Interactive);
    header->setSectionsClickable(true);
    header->setSortIndicatorShown(true);
    // Matches PacketListHeader's own constructor (packet_list_header.cpp):
    // a bare QHeaderView defaults to centered section-label text, not the
    // left-aligned labels the real header actually uses. This is the
    // header LABEL's alignment only (a single value for every section);
    // per-column left/center/right preferences set via the real header's
    // own right-click menu only affect cell data below it, not the header
    // row itself, in either header.
    header->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
}

} // namespace

PacketListPane::PacketListPane(QWidget *parent) :
    QWidget(parent)
{
    QVBoxLayout *outer_layout = new QVBoxLayout(this);
    outer_layout->setContentsMargins(0, 0, 0, 0);
    outer_layout->setSpacing(0);

    // packet_list_ is constructed here (rather than by our own caller) so
    // that it's a genuine child of this pane, not of whatever splitter
    // this pane itself ends up parented to -- see the class comment for
    // why the pinned-row strip needs to be a sibling widget in a normal
    // layout, above packet_list_, instead of an overlay child of it.
    packet_list_ = new PacketList(this);

    duplicate_header_strip_ = new QWidget(this);
    duplicate_header_strip_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    duplicate_header_layout_ = new QHBoxLayout(duplicate_header_strip_);
    duplicate_header_layout_->setContentsMargins(0, 0, 0, 0);
    duplicate_header_layout_->setSpacing(0);

    duplicate_header_corner_ = new QHeaderView(Qt::Horizontal, duplicate_header_strip_);
    duplicate_header_main_ = new QHeaderView(Qt::Horizontal, duplicate_header_strip_);
    setUpDuplicateHeader(duplicate_header_corner_, packet_list_->model());
    setUpDuplicateHeader(duplicate_header_main_, packet_list_->model());
    duplicate_header_corner_->setFixedHeight(packet_list_->header()->height());
    duplicate_header_main_->setFixedHeight(packet_list_->header()->height());

    // Right-click support (Column Preferences, alignment, display format,
    // etc.) is forwarded to the real header via an installed event
    // filter -- see eventFilter()'s own comment for why plain QHeaderViews
    // need this rather than handling it natively.
    duplicate_header_corner_->installEventFilter(this);
    duplicate_header_main_->installEventFilter(this);

    duplicate_header_layout_->addWidget(duplicate_header_corner_);
    duplicate_header_layout_->addWidget(duplicate_header_main_, 1);

    // Seed initial section widths/hidden state to match whatever
    // PacketList's own header already settled on during its own
    // construction (column visibility prefs, etc.) -- everything from
    // here on is kept in sync incrementally by the connect()s below.
    // Frozen/non-frozen column hiding (which of the two halves shows
    // which columns) is handled separately by pinnedColumnBoundaryChanged
    // below, since no column freeze can be active yet at this point.
    for (int col = 0; col < packet_list_->header()->count(); col++) {
        duplicate_header_corner_->resizeSection(col, packet_list_->header()->sectionSize(col));
        duplicate_header_main_->resizeSection(col, packet_list_->header()->sectionSize(col));
        bool hidden = packet_list_->header()->isSectionHidden(col);
        duplicate_header_corner_->setSectionHidden(col, hidden);
        duplicate_header_main_->setSectionHidden(col, hidden);
    }

    // Real header's own changes (from user interaction with it, or from
    // any other code path that resizes/sorts/hides a column) -> mirrored
    // onto both duplicate halves. QSignalBlocker on each in every handler
    // prevents these from bouncing back out through the opposite
    // (duplicate header -> real header) connections below.
    connect(packet_list_->header(), &QHeaderView::sectionResized, this,
            [this](int column, int, int new_width) {
        QSignalBlocker corner_blocker(duplicate_header_corner_);
        QSignalBlocker main_blocker(duplicate_header_main_);
        duplicate_header_corner_->resizeSection(column, new_width);
        duplicate_header_main_->resizeSection(column, new_width);
    });
    connect(packet_list_->header(), &QHeaderView::sortIndicatorChanged, this,
            [this](int column, Qt::SortOrder order) {
        QSignalBlocker corner_blocker(duplicate_header_corner_);
        QSignalBlocker main_blocker(duplicate_header_main_);
        duplicate_header_corner_->setSortIndicator(column, order);
        duplicate_header_main_->setSortIndicator(column, order);
    });
    connect(packet_list_, &PacketList::columnHiddenChanged, this,
            [this](int column, bool hidden) {
        QSignalBlocker corner_blocker(duplicate_header_corner_);
        QSignalBlocker main_blocker(duplicate_header_main_);
        // Combined with the frozen/non-frozen split (same as the
        // pinnedColumnBoundaryChanged handler below): applying only
        // `hidden` here would un-hide a non-frozen column on
        // duplicate_header_corner_ too (or a frozen one on
        // duplicate_header_main_) whenever a column the corner/main split
        // doesn't cover for it is shown again, duplicating that column's
        // header onto the half that shouldn't display it at all.
        bool frozen = PacketList::isColumnFrozen(column, packet_list_->pinnedColumnBoundary());
        duplicate_header_corner_->setSectionHidden(column, hidden || !frozen);
        duplicate_header_main_->setSectionHidden(column, hidden || frozen);
        /* A section transitioning hidden to visible resets to
         * QHeaderView's own default section size (see
         * pinnedColumnBoundaryChanged's own comment below). Re-apply the
         * real header's current width so a profile switch (which
         * hides/shows every column via setColumnVisibility(), e.g. to
         * apply the new profile's saved widths via
         * applyRecentColumnWidths() beforehand) doesn't have those
         * widths immediately clobbered back to the default by
         * forwardResize() below reacting to this reset.
         */
        int width = packet_list_->header()->sectionSize(column);
        duplicate_header_corner_->resizeSection(column, width);
        duplicate_header_main_->resizeSection(column, width);
    });
    // Splits which columns each half actually shows, mirroring exactly
    // how PacketList::setColumnVisibility()/setPinnedColumnBoundary()
    // split pinned_column_view_/pinned_row_view_/pinned_row_corner_view_
    // around pinned_column_boundary_: the corner half shows only frozen
    // columns, the main half only non-frozen ones (per
    // PacketList::isColumnFrozen(), the single shared definition of that
    // split). Column-visibility-driven hiding (the connection above) is
    // applied independently and combines with this via OR, same as those
    // views.
    connect(packet_list_, &PacketList::pinnedColumnBoundaryChanged, this,
            [this](int column_count) {
        QSignalBlocker corner_blocker(duplicate_header_corner_);
        QSignalBlocker main_blocker(duplicate_header_main_);
        int total_columns = duplicate_header_corner_->count();
        for (int col = 0; col < total_columns; col++) {
            bool column_hidden = packet_list_->header()->isSectionHidden(col);
            bool frozen = PacketList::isColumnFrozen(col, column_count);
            duplicate_header_corner_->setSectionHidden(col, column_hidden || !frozen);
            duplicate_header_main_->setSectionHidden(col, column_hidden || frozen);
            // A section transitioning from hidden -> visible resets to
            // QHeaderView's own default section size rather than keeping
            // whatever width it had before being hidden -- re-apply the
            // real header's current width for every column here (not just
            // the ones that changed) so freezing/unfreezing doesn't shrink
            // columns to their default/content width.
            int width = packet_list_->header()->sectionSize(col);
            duplicate_header_corner_->resizeSection(col, width);
            duplicate_header_main_->resizeSection(col, width);
        }
    });
    // duplicate_header_main_ mirrors every non-frozen column, so it needs
    // to scroll horizontally in step with the primary view too --
    // otherwise, with a column freeze active, scrolling the main view's
    // non-frozen columns leaves this header showing stale column
    // positions. duplicate_header_corner_ (the frozen columns) never
    // scrolls, matching pinned_row_corner_view_'s own behavior.
    connect(packet_list_->horizontalScrollBar(), &QScrollBar::valueChanged, this,
            [this](int value) {
        duplicate_header_main_->setOffset(value);
    });
    duplicate_header_main_->setOffset(packet_list_->horizontalScrollBar()->value());

    // Each duplicate half's own changes (from the user actually
    // interacting with it while it's the visible one) -> applied to the
    // real header's data, purely at the data level (resizeSection()/
    // setSortIndicator()), never by forwarding the raw mouse event itself
    // -- see the class comment for why forwarding input events to a
    // hidden QHeaderView is unsafe.
    //
    // Deliberately NOT blocking packet_list_->header()'s own signals here:
    // resizeSection() below needs to legitimately re-emit sectionResized()
    // on the real header, since PacketList::sectionResized() (a separate
    // slot connected to that same signal) is what actually propagates the
    // new width to pinned_row_view_/pinned_row_corner_view_/
    // pinned_column_view_ and triggers layoutPinnedOverlays() -- blocking
    // it here (as a first attempt at this did) silently broke resizing a
    // column while something is pinned: the real header's own width
    // changed, but nothing downstream of it ever found out. The
    // real-header -> duplicate-headers connection above already blocks
    // duplicate_header_corner_/duplicate_header_main_ specifically, which
    // is sufficient on its own to prevent this from looping back here.
    auto forwardResize = [this](int column, int, int new_width) {
        /* A resize to width 0 (or any width below the smallest width a
         * user drag can actually produce) never comes from a real user
         * resize drag. It comes from Qt's own QHeaderView internals
         * resetting every section on this header to a default width, on
         * a later event loop pass, in reaction to layoutChanged() or
         * headerDataChanged() on the model shared with the real packet
         * list (emitted by PacketListModel::resetColumns(), called on
         * every profile switch among other things), observed to happen
         * regardless of this header's resize mode. Forwarding that reset
         * onto the real header would clobber whatever width
         * applyRecentColumnWidths() had just correctly set there.
         * Ignoring it here and instead re asserting the real header's
         * own current width back onto both duplicate headers recovers
         * from the reset without ever letting it reach the real header.
         */
        if (new_width < 1) {
            int real_width = packet_list_->header()->sectionSize(column);
            QSignalBlocker corner_blocker(duplicate_header_corner_);
            QSignalBlocker main_blocker(duplicate_header_main_);
            duplicate_header_corner_->resizeSection(column, real_width);
            duplicate_header_main_->resizeSection(column, real_width);
            return;
        }
        packet_list_->header()->resizeSection(column, new_width);
    };
    connect(duplicate_header_corner_, &QHeaderView::sectionResized, this, forwardResize);
    connect(duplicate_header_main_, &QHeaderView::sectionResized, this, forwardResize);
    connect(duplicate_header_corner_, &QHeaderView::sectionClicked, this,
            [this](int column) {
        packet_list_->sortByColumnFromOverlay(column);
    });
    connect(duplicate_header_main_, &QHeaderView::sectionClicked, this,
            [this](int column) {
        packet_list_->sortByColumnFromOverlay(column);
    });

    duplicate_header_strip_->setVisible(false);

    pinned_rows_strip_ = new QWidget(this);
    pinned_rows_strip_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    pinned_rows_layout_ = new QHBoxLayout(pinned_rows_strip_);
    pinned_rows_layout_->setContentsMargins(0, 0, 0, 0);
    pinned_rows_layout_->setSpacing(0);

    // Both are children of pinned_rows_strip_ (not of packet_list_):
    // PacketList continues to manage their content/properties (model,
    // column widths, styles, fonts, delegates, column visibility) via the
    // pointers handed back to it below, but no longer owns or positions
    // them.
    pinned_row_corner_view_ = new PinnedRowView(packet_list_, pinned_rows_strip_);
    pinned_row_view_ = new PinnedRowView(packet_list_, pinned_rows_strip_);

    pinned_rows_layout_->addWidget(pinned_row_corner_view_);
    pinned_rows_layout_->addWidget(pinned_row_view_, 1);

    pinned_rows_strip_->setVisible(false);

    // A real widget with its own background color, the same convention
    // PinnedOverlayView::createBoundaryDivider() already uses for the
    // frozen/non-frozen column divider -- packet_list_'s own default
    // QFrame border reads as too faint a separation from the pinned
    // content directly above it.
    pinned_rows_divider_ = new QWidget(this);
    pinned_rows_divider_->setAutoFillBackground(true);
    QPalette divider_palette = pinned_rows_divider_->palette();
    divider_palette.setColor(QPalette::Window, palette().color(QPalette::Mid));
    pinned_rows_divider_->setPalette(divider_palette);
    const int divider_height = 3;
    pinned_rows_divider_->setFixedHeight(divider_height);
    pinned_rows_divider_->setVisible(false);

    outer_layout->addWidget(duplicate_header_strip_);
    outer_layout->addWidget(pinned_rows_strip_);
    outer_layout->addWidget(pinned_rows_divider_);
    outer_layout->addWidget(packet_list_, 1);

    packet_list_->setPinnedRowViews(pinned_row_view_, pinned_row_corner_view_);

    connect(packet_list_, &PacketList::pinnedRowsCornerWidthChanged,
            this, &PacketListPane::updatePinnedRowsStripWidth);
}

void PacketListPane::updatePinnedRowsStripWidth(int corner_width, bool have_pinned_rows)
{
    pinned_row_corner_view_->setFixedWidth(corner_width);
    duplicate_header_corner_->setFixedWidth(corner_width);

    // Explicitly fix the strip's height to exactly what the pinned-row
    // content needs, rather than relying on sizeHint()/updateGeometry()
    // propagating through pinned_rows_layout_ -> this widget's own outer
    // QVBoxLayout -> the QSplitter that ultimately owns this pane's
    // height. That propagation was observed to not reliably happen after
    // the strip's first transition to visible (its on-screen height got
    // stuck at whatever it was then, even though sizeHint() itself kept
    // reporting the correct, growing value on every subsequent pin).
    // setFixedHeight() sets a hard min/max on the widget itself, which
    // QLayout has no choice but to honor immediately, sidestepping
    // whatever caching/propagation gap caused that.
    int strip_height = pinned_row_view_->sizeHint().height();
    pinned_rows_strip_->setFixedHeight(strip_height);
    pinned_rows_strip_->setVisible(have_pinned_rows);
    pinned_rows_strip_->updateGeometry();
    pinned_rows_divider_->setVisible(have_pinned_rows);

    // The native header lives inside PacketList itself, below (not above)
    // the pinned-rows strip in this pane's own stacking order -- swap it
    // out for the duplicate header pair (shown here, directly above the
    // strip) whenever anything is pinned, and restore the native one
    // otherwise. See the class comment for why relocating the native
    // header itself isn't a safe option.
    if (have_pinned_rows) {
        // Full resync (not just the incremental sectionResized/
        // sortIndicatorChanged mirroring already wired up in the
        // constructor) right before this becomes visible, since it may
        // have missed section-width changes that happened while hidden
        // (e.g. resizes/moves QHeaderView doesn't emit sectionResized()
        // for, or simply drift accumulated since construction).
        {
            QSignalBlocker corner_blocker(duplicate_header_corner_);
            QSignalBlocker main_blocker(duplicate_header_main_);
            // Frozen/non-frozen split resynced here too (not just via
            // pinnedColumnBoundaryChanged, connected in the constructor):
            // a freeze set up before anything was ever pinned would
            // otherwise never reach the duplicate headers, since that
            // signal only fires on a change, not on every pin.
            int boundary = packet_list_->pinnedColumnBoundary();
            for (int col = 0; col < packet_list_->header()->count(); col++) {
                duplicate_header_corner_->resizeSection(col, packet_list_->header()->sectionSize(col));
                duplicate_header_main_->resizeSection(col, packet_list_->header()->sectionSize(col));
                bool column_hidden = packet_list_->header()->isSectionHidden(col);
                bool frozen = PacketList::isColumnFrozen(col, boundary);
                duplicate_header_corner_->setSectionHidden(col, column_hidden || !frozen);
                duplicate_header_main_->setSectionHidden(col, column_hidden || frozen);
            }
            duplicate_header_corner_->setSortIndicator(packet_list_->header()->sortIndicatorSection(),
                                                        packet_list_->header()->sortIndicatorOrder());
            duplicate_header_main_->setSortIndicator(packet_list_->header()->sortIndicatorSection(),
                                                      packet_list_->header()->sortIndicatorOrder());
        }
        // Only refresh the height while the native header is still
        // visible: this function can run more than once in a row for the
        // same have_pinned_rows=true transition (e.g. once from the pin
        // itself, again from the resulting layoutPinnedOverlays() calls),
        // and packet_list_->header()->height() reports 0 once it's
        // already been hidden by the setVisible(false) call below --
        // reading it again on a later call would otherwise clobber the
        // duplicate headers' height with that stale 0.
        if (packet_list_->header()->isVisible()) {
            duplicate_header_corner_->setFixedHeight(packet_list_->header()->height());
            duplicate_header_main_->setFixedHeight(packet_list_->header()->height());
        }
    }
    packet_list_->header()->setVisible(!have_pinned_rows);
    duplicate_header_strip_->setVisible(have_pinned_rows);

    updateGeometry();
}

bool PacketListPane::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == duplicate_header_corner_ && event->type() == QEvent::ContextMenu) {
        // duplicate_header_corner_ never scrolls (like PinnedColumnHeader,
        // it always shows the frozen columns at their unscrolled logical
        // positions), but the real header does -- its frozen columns'
        // pixel position there shifts with scroll even though they're
        // hidden underneath pinned_column_view_'s overlay. Translating
        // through the logical column index (frozenHeaderPosToReal(), the
        // same helper PinnedColumnHeader uses) rather than assuming local
        // x=0 always equals the real header's x=0 fixes this regardless
        // of the primary view's current scroll position.
        QContextMenuEvent *ctx_event = static_cast<QContextMenuEvent *>(event);
        QPoint header_pos = packet_list_->frozenHeaderPosToReal(ctx_event->pos());
        packet_list_->forwardHeaderContextMenu(ctx_event, header_pos);
        return true;
    }
    if (watched == duplicate_header_main_ && event->type() == QEvent::ContextMenu) {
        // Unlike the corner half, duplicate_header_main_ mirrors the real
        // header's own scroll offset (see its setOffset() calls above), so
        // its local x already accounts for scroll the same way the real
        // header's own coordinate space does -- it only needs a constant
        // offset by the frozen columns' width (which it doesn't show) to
        // land in the real header's space, not a scroll-aware logical
        // column translation.
        QContextMenuEvent *ctx_event = static_cast<QContextMenuEvent *>(event);
        QPoint header_pos = ctx_event->pos() + QPoint(duplicate_header_corner_->width(), 0);
        packet_list_->forwardHeaderContextMenu(ctx_event, header_pos);
        return true;
    }
    return QWidget::eventFilter(watched, event);
}
