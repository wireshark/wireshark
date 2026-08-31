/* pinned_column_view.cpp
 *
 * A QTreeView clone showing only a leftmost run of frozen columns
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/pinned_column_view.h>

#include <ui/qt/packet_list.h>
#include <ui/qt/widgets/pinned_column_header.h>
#include <ui/qt/widgets/pinned_overlay_view.h>
#include <ui/qt/models/packet_list_record.h>
#include <ui/qt/utils/color_utils.h>

#include <epan/frame_data.h>
#include <epan/prefs.h>

#include <QHeaderView>
#include <QScrollBar>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QWheelEvent>

PinnedColumnView::PinnedColumnView(PacketList *packet_list, QWidget *parent) :
    QTreeView(parent),
    packet_list_(packet_list),
    frozen_column_count_(0)
{
    PinnedOverlayView::applyCommonTreeViewSetup(this);
    setSelectionMode(QAbstractItemView::ExtendedSelection);
    // Keeping keyboard focus off this view (see applyCommonTreeViewSetup())
    // means clicking here still selects the row (via
    // PacketList::selectRowFromOverlay()), while keeping focus on the
    // primary view keeps the selection highlight rendered in its "active"
    // color everywhere, rather than the dull "inactive" Qt uses for
    // whichever separate widget doesn't currently have focus.

    // A dedicated QHeaderView subclass, rather than an installEventFilter()
    // on the default header: QHeaderView handles interactive resize (and
    // its own click-to-sort) directly in its mousePress/Move/ReleaseEvent
    // virtuals, which weren't reliably seen by an installed event filter
    // even though the resize itself worked -- overriding the virtuals
    // directly guarantees they're seen.
    PinnedColumnHeader *pinned_header = new PinnedColumnHeader(packet_list, this);
    setHeader(pinned_header);
    header()->setSectionsMovable(false);
    header()->setSectionResizeMode(QHeaderView::Interactive);
    // setSortingEnabled() on the primary QTreeView implicitly shows its
    // header's sort indicator; since this is a separate QHeaderView not
    // wired to setSortingEnabled(), that has to be requested explicitly.
    header()->setSortIndicatorShown(true);
    // Matches PacketListHeader's own constructor (packet_list_header.cpp):
    // a bare QHeaderView (which is all PinnedColumnHeader adds mouse/
    // context-menu forwarding on top of) defaults to centered
    // section-label text, not the left-aligned labels the primary
    // header actually uses.
    header()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    // This view's own header is shown (rather than hidden/collapsed) so the
    // frozen columns' titles stay put above the frozen data instead of
    // scrolling off with the primary view's header.

    // Visual boundary marker between the frozen and non-frozen columns.
    right_divider_ = PinnedOverlayView::createBoundaryDivider(this);
    right_divider_->show();
}

void PinnedColumnView::setFrozenColumnCount(int column_count)
{
    frozen_column_count_ = column_count;

    if (!model()) {
        return;
    }

    int total_columns = model()->columnCount();
    for (int i = 0; i < total_columns; i++) {
        // Combined with the primary view's own column-visibility state
        // (see PinnedRowView::applyColumnVisibility()'s own comment for
        // why): this method has no memory of a column the user explicitly
        // hid via the column header's checkbox, so applying only the
        // frozen-count split here would re-show it the next time the
        // frozen-column boundary changes.
        bool globally_hidden = packet_list_ && packet_list_->isColumnHidden(i);
        setColumnHidden(i, globally_hidden || i >= frozen_column_count_);
    }

    setVisible(frozen_column_count_ > 0);
    if (frozen_column_count_ > 0) {
        // Force a layout pass: QTreeView with setUniformRowHeights() only
        // computes row geometry lazily (normally triggered by paint or
        // scrollTo), and this view is never scrolled by the user directly.
        doItemsLayout();
    }
}

void PinnedColumnView::mirrorSectionWidth(int column, int width)
{
    PinnedOverlayView::mirrorSectionWidth(this, column, width);
}

void PinnedColumnView::mirrorHeaderHeight(int height)
{
    header()->setFixedHeight(height);
}

void PinnedColumnView::refreshLayout()
{
    if (frozen_column_count_ > 0) {
        doItemsLayout();
    }
}

void PinnedColumnView::mirrorSortIndicator(int column, Qt::SortOrder order)
{
    header()->setSortIndicator(column, order);
}

void PinnedColumnView::setVerticalScrollValue(int value)
{
    verticalScrollBar()->setValue(value);
    viewport()->update();
}

void PinnedColumnView::mousePressEvent(QMouseEvent *event)
{
    PacketList *packet_list = qobject_cast<PacketList *>(parentWidget());
    QModelIndex index = indexAt(event->pos());
    if (packet_list && index.isValid()) {
        packet_list->selectRowFromOverlay(index.row(), index.column(), event->buttons());
    }
}

void PinnedColumnView::mouseReleaseEvent(QMouseEvent *)
{
    // Selection already happened on press; nothing to do here.
}

void PinnedColumnView::mouseMoveEvent(QMouseEvent *event)
{
    PacketList *packet_list = qobject_cast<PacketList *>(parentWidget());
    if (packet_list) {
        QModelIndex index = indexAt(event->pos());
        packet_list->setHoveredRowFromOverlay(index.isValid() ? index.row() : -1);
    }
}

void PinnedColumnView::leaveEvent(QEvent *event)
{
    QTreeView::leaveEvent(event);

    PacketList *packet_list = qobject_cast<PacketList *>(parentWidget());
    if (packet_list) {
        packet_list->setHoveredRowFromOverlay(-1);
    }
}

void PinnedColumnView::contextMenuEvent(QContextMenuEvent *event)
{
    PacketList *packet_list = qobject_cast<PacketList *>(parentWidget());
    QModelIndex index = indexAt(event->pos());
    if (packet_list && index.isValid()) {
        packet_list->showContextMenuForRow(index.row(), event->globalPos());
    }
}

void PinnedColumnView::wheelEvent(QWheelEvent *event)
{
    PacketList *packet_list = qobject_cast<PacketList *>(parentWidget());
    if (packet_list) {
        packet_list->forwardWheelEvent(event);
    }
}

void PinnedColumnView::drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QTreeView::drawRow(painter, option, index);

    PacketList *packet_list = qobject_cast<PacketList *>(parentWidget());
    if (packet_list && prefs.gui_packet_list_hover_style) {
        PacketListRecord *record = model() ? static_cast<PacketListRecord *>(index.internalPointer()) : nullptr;
        frame_data *fdata = record ? record->frameData() : nullptr;
        if (fdata && (int)fdata->num == packet_list->hoveredFrameNum()) {
            QRect row_rect(0, visualRect(index).y(), viewport()->width(), visualRect(index).height());
            ColorUtils::paintHoverOverlay(painter, row_rect);
        }
    }

    if (prefs.gui_packet_list_separator) {
        QRect rect = visualRect(index);
        painter->setPen(QColor(Qt::white));
        painter->drawLine(0, rect.y() + rect.height() - 1, width(), rect.y() + rect.height() - 1);
    }
}

void PinnedColumnView::resizeEvent(QResizeEvent *event)
{
    QTreeView::resizeEvent(event);

    PinnedOverlayView::repositionBoundaryDivider(right_divider_, this);
}
