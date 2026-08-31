/* pinned_row_view.cpp
 *
 * A QTreeView clone showing every currently pinned packet
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/pinned_row_view.h>

#include <ui/qt/packet_list.h>
#include <ui/qt/models/pinned_rows_model.h>
#include <ui/qt/models/packet_list_record.h>
#include <ui/qt/widgets/pinned_overlay_view.h>
#include <ui/qt/utils/color_utils.h>

#include <epan/frame_data.h>
#include <epan/prefs.h>

#include <QHeaderView>
#include <QScrollBar>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QPaintEvent>
#include <QWheelEvent>

PinnedRowView::PinnedRowView(PacketList *packet_list, QWidget *parent) :
    QTreeView(parent),
    packet_list_(packet_list),
    first_column_(0),
    last_column_(-1)
{
    PinnedOverlayView::applyCommonTreeViewSetup(this);
    setSelectionMode(QAbstractItemView::NoSelection);
    // This view's height should always be exactly sizeHint().height() (all
    // pinned rows stacked with no gaps), never stretched to fill leftover
    // space in PacketListPane's QVBoxLayout the way QAbstractScrollArea's
    // default Expanding vertical policy would otherwise allow.
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    // The row view never needs its own header row painted; the primary
    // view's header (or the pinned column view's) already covers it.
    header()->setSectionsMovable(false);
    header()->setSectionResizeMode(QHeaderView::Fixed);
    header()->hide();

    right_divider_ = PinnedOverlayView::createBoundaryDivider(this);
    right_divider_->setVisible(false);
}

void PinnedRowView::setColumnRange(int first, int last)
{
    first_column_ = first;
    last_column_ = last;
    applyColumnVisibility();
    right_divider_->setVisible(isCornerView());

    // setColumnHidden() above (via applyColumnVisibility()) changes which
    // columns are part of this row's visible geometry, but QTreeView
    // caches row/item geometry internally and doesn't reliably recompute
    // it just because columns were hidden/shown -- observed via logging:
    // visualRect() for this index kept returning an empty QRect(0,0,0,0)
    // immediately after a freeze-column change, even though this widget
    // already had its correct, nonzero size at that point. That made
    // drawRow()'s separator line draw at y = -1 (off the top of the
    // widget) for every row, since it derives the line's position from
    // visualRect(). Forcing the layout here (rather than waiting for
    // some later resize/model-change event to trigger it implicitly)
    // makes visualRect() correct again immediately, before the very
    // next paint.
    doItemsLayout();
}

void PinnedRowView::applyColumnVisibility()
{
    if (!model()) {
        return;
    }

    int total_columns = model()->columnCount();
    int last = (last_column_ < 0) ? total_columns - 1 : last_column_;
    for (int i = 0; i < total_columns; i++) {
        // Combines the frozen/non-frozen range split (this method's own
        // purpose) with the primary view's own column-visibility state:
        // this method runs on every pin/unpin/refresh (via
        // PacketList::updatePinnedRowVisibility()), not just when the
        // range itself actually changes, so applying only the range split
        // here would silently re-show a column the user explicitly hid
        // via the column header's "Show/hide column" checkbox --
        // PacketList::setColumnVisibility() already applied that hidden
        // state once, but this method has no memory of it and would
        // otherwise overwrite it back to visible on the next pin/refresh.
        bool globally_hidden = packet_list_ && packet_list_->isColumnHidden(i);
        setColumnHidden(i, globally_hidden || i < first_column_ || i > last);
    }
}

void PinnedRowView::mirrorSectionWidth(int column, int width)
{
    PinnedOverlayView::mirrorSectionWidth(this, column, width);
}

void PinnedRowView::setHorizontalScrollValue(int value)
{
    horizontalScrollBar()->setValue(value);
}

QSize PinnedRowView::sizeHint() const
{
    QSize hint = QTreeView::sizeHint();
    int rows = model() ? model()->rowCount() : 0;
    // Query the primary view for its row height rather than this view's
    // own sizeHintForRow(0): this view starts hidden and may not have
    // laid out any rows yet the first time one is pinned, so its own
    // sizeHintForRow() can't be relied on to reflect the real per-row
    // height at that point.
    int row_height = packet_list_ ? packet_list_->pinnedRowHeight() : 0;
    hint.setHeight(row_height > 0 ? row_height * rows : 0);
    return hint;
}

void PinnedRowView::mousePressEvent(QMouseEvent *event)
{
    PacketList *packet_list = packet_list_;
    PinnedRowsModel *pinned_model = qobject_cast<PinnedRowsModel *>(model());
    QModelIndex index = indexAt(event->pos());
    if (!packet_list || !pinned_model || !index.isValid()) {
        return;
    }

    QModelIndex source_index = pinned_model->mapToSource(index);
    if (source_index.isValid()) {
        // Still visible in the primary (filtered) view: use the normal,
        // row-based path, which also supports middle-click-to-mark.
        packet_list->selectRowFromOverlay(source_index.row(), source_index.column(), event->buttons());
        return;
    }

    // Filtered out of the primary view entirely -- there's no row there
    // to select via the row-based path above, but selectFrameFromOverlay()
    // can still select it directly by frame number (see its own comment
    // for why that's possible: cf_select_packet() works against the
    // capture file's own frame array, not a row in this view's model).
    if (PacketListRecord *record = static_cast<PacketListRecord *>(index.internalPointer())) {
        if (frame_data *fdata = record->frameData()) {
            packet_list->selectFrameFromOverlay((int)fdata->num);
        }
    }
}

void PinnedRowView::mouseReleaseEvent(QMouseEvent *)
{
    // Selection already happened on press; nothing to do here.
}

void PinnedRowView::mouseMoveEvent(QMouseEvent *event)
{
    PacketList *packet_list = packet_list_;
    if (!packet_list) {
        return;
    }

    // Read the frame number straight off this index's own internal
    // pointer (the physical PacketListRecord -- see
    // PinnedRowsModel::index()) rather than via mapToSource(), which
    // only resolves while the packet is still visible in the primary
    // (filtered) view. Hovering a pinned packet that's been filtered out
    // should still highlight it here, even though there's no
    // corresponding row in the primary view to sync a selection to.
    QModelIndex index = indexAt(event->pos());
    PacketListRecord *record = index.isValid() ?
        static_cast<PacketListRecord *>(index.internalPointer()) : nullptr;
    frame_data *fdata = record ? record->frameData() : nullptr;
    packet_list->setHoveredFrameNum(fdata ? (int)fdata->num : -1);
}

void PinnedRowView::leaveEvent(QEvent *event)
{
    QTreeView::leaveEvent(event);

    PacketList *packet_list = packet_list_;
    if (packet_list) {
        packet_list->setHoveredFrameNum(-1);
    }
}

void PinnedRowView::contextMenuEvent(QContextMenuEvent *event)
{
    PacketList *packet_list = packet_list_;
    PinnedRowsModel *pinned_model = qobject_cast<PinnedRowsModel *>(model());
    QModelIndex index = indexAt(event->pos());
    if (!packet_list || !pinned_model || !index.isValid()) {
        return;
    }

    QModelIndex source_index = pinned_model->mapToSource(index);
    if (source_index.isValid()) {
        packet_list->showContextMenuForRow(source_index.row(), event->globalPos(), /* from_pinned_row_strip */ true);
        return;
    }

    // Filtered out of the primary view -- no row there to resolve via
    // mapToSource(); showContextMenuForFrame() selects and shows the menu
    // directly by frame number instead (see selectFrameFromOverlay()).
    if (PacketListRecord *record = static_cast<PacketListRecord *>(index.internalPointer())) {
        if (frame_data *fdata = record->frameData()) {
            packet_list->showContextMenuForFrame((int)fdata->num, event->globalPos(), /* from_pinned_row_strip */ true);
        }
    }
}

void PinnedRowView::wheelEvent(QWheelEvent *event)
{
    PacketList *packet_list = packet_list_;
    if (packet_list) {
        packet_list->forwardWheelEvent(event);
    }
}

void PinnedRowView::paintEvent(QPaintEvent *event)
{
    selected_frame_nums_cache_.clear();
    if (packet_list_) {
        const QList<int> selected = packet_list_->selectedRows(true);
        selected_frame_nums_cache_ = QSet<int>(selected.begin(), selected.end());
    }

    QTreeView::paintEvent(event);
}

void PinnedRowView::drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    PacketList *packet_list = packet_list_;
    // index's own internal pointer is the physical PacketListRecord (see
    // PinnedRowsModel::index()), valid regardless of whether this pinned
    // packet currently passes the display filter -- unlike routing
    // through mapToSource(), which only resolves while the packet is
    // still visible in the primary (filtered) view.
    frame_data *fdata = nullptr;
    if (PacketListRecord *record = static_cast<PacketListRecord *>(index.internalPointer())) {
        fdata = record->frameData();
    }

    // This view's model is a separate proxy (PinnedRowsModel), so it can't
    // rely on a shared QItemSelectionModel with the primary view the way
    // PinnedColumnView does -- selection is checked by frame number
    // instead. Checking both selected_frame_nums_cache_ (the normal,
    // possibly multi-row case -- rows that exist in the primary view's own
    // model, refreshed once per paint pass by paintEvent() rather than
    // rescanning packet_list->selectedRows(true) here on every row) and
    // currentFrameNum() (cap_file_->current_frame, kept correct by
    // cf_select_packet() even for a pinned packet selected via
    // selectFrameFromOverlay() with no row in the primary view at all,
    // e.g. filtered out, so it could never appear in selectedRows())
    // covers both.
    bool is_selected = packet_list && fdata &&
        ((int)fdata->num == packet_list->currentFrameNum() ||
         selected_frame_nums_cache_.contains((int)fdata->num));

    // This view's model is a separate proxy with no shared
    // QItemSelectionModel with the primary view (see is_selected's own
    // comment above), so Qt never actually sets QStyle::State_Selected on
    // its own -- set it here so the rest of drawRow()'s normal machinery
    // (the "QTreeView::item:selected:active"/":!active" stylesheet
    // selectors colorsChanged() applies to this same widget, and
    // MultiColorPacketDelegate's own State_Selected bail-out) picks the
    // packet list's real selection colors exactly, rather than
    // reimplementing them by hand with a manually-painted overlay.
    QStyleOptionViewItem selected_option = option;
    if (is_selected) {
        selected_option.state |= QStyle::State_Selected;
    }

    QTreeView::drawRow(painter, selected_option, index);

    // The hover highlight is driven by hovered_frame_num_ rather than Qt's
    // native per-widget hover state, since the mouse hovering a pinned
    // overlay view needs to highlight this row here too -- native :hover
    // styling only ever reacts to the mouse being over this specific
    // widget. Painted last with a translucent color (rather than before
    // the base drawRow(), like a normal CSS background) since delegates
    // paint an opaque item background themselves, which would otherwise
    // hide a highlight painted underneath it. Painted even on a selected
    // row so hover wins over selection, matching PacketList::drawRow().
    if (packet_list && prefs.gui_packet_list_hover_style) {
        if (fdata && (int)fdata->num == packet_list->hoveredFrameNum()) {
            QRect row_rect(0, option.rect.y(), viewport()->width(), option.rect.height());
            ColorUtils::paintHoverOverlay(painter, row_rect);
        }
    }

    if (prefs.gui_packet_list_separator) {
        // option.rect (this row's geometry as QTreeView is actually
        // painting it right now) rather than visualRect(index) (a
        // separate, independently-cached query that was observed to
        // return an empty QRect(0,0,0,0) immediately after a
        // freeze-column change, even while this exact row was
        // legitimately being painted with a real, nonzero rect via
        // option.rect at the same moment).
        painter->setPen(QColor(Qt::white));
        painter->drawLine(0, option.rect.y() + option.rect.height() - 1,
                           width(), option.rect.y() + option.rect.height() - 1);
    }

    // This view has no scrollbar of its own (Qt::ScrollBarAlwaysOff), so
    // the pinned-row strip as a whole is wider than the primary view's
    // viewport by whatever width the primary view's own OverlayScrollBar
    // reserves -- otherwise-identical content would end up
    // misaligned/differently colored out there. Rather than compress
    // this view's own rendering to match, paint that trailing sliver
    // over in a flat grey matching the scrollbar's own chrome, the same
    // convention right_divider_ already uses for its own
    // scrollbar-adjacent divider color.
    //
    // Only the main (non-corner) instance can ever need this: the
    // sliver is always at the far right of the whole strip, which is
    // always inside the main instance's own territory. Comparing against
    // parentWidget()->width() (pinned_rows_strip_, the QHBoxLayout
    // container holding both the corner and main instances together)
    // rather than this->viewport()->width() matters once a column
    // freeze is active: this instance's own viewport only spans its
    // share of the strip (the non-frozen columns) at that point, not
    // the strip's full combined width, so comparing against it directly
    // produced a negative "scrollbar width" and silently skipped
    // painting anything.
    if (packet_list && !isCornerView() && parentWidget()) {
        int scrollbar_width = parentWidget()->width() - packet_list->viewport()->width();
        if (scrollbar_width > 0) {
            // The strip's true right edge, expressed in this instance's
            // own local coordinate space (where fillRect() below actually
            // paints): parentWidget()->width() is the full strip's width,
            // but this instance's own local x=0 starts at this->x() within
            // that strip (the frozen columns' width, once a freeze is
            // active) -- subtracting that offset, not just using
            // parentWidget()->width() directly, keeps the sliver anchored
            // to the strip's real right edge instead of one that would
            // fall outside this instance's own local bounds entirely.
            int strip_right_edge_local = parentWidget()->width() - x();
            QRect scrollbar_rect(strip_right_edge_local - scrollbar_width, option.rect.y(),
                                  scrollbar_width, option.rect.height());
            painter->fillRect(scrollbar_rect, palette().color(QPalette::Mid));
        }
    }
}

void PinnedRowView::resizeEvent(QResizeEvent *event)
{
    QTreeView::resizeEvent(event);

    // Only the "corner" instance (columns starting at the very left) sits
    // at the frozen/non-frozen boundary; the main pinned-row instance
    // (columns after the boundary) doesn't need this divider.
    right_divider_->setVisible(isCornerView());
    PinnedOverlayView::repositionBoundaryDivider(right_divider_, this);
}
