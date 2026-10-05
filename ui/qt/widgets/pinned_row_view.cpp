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

#include <epan/column.h>
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
    // The selection model (shared with the corner view, and linked to the
    // primary view's) is set by PacketList::setPinnedRowViews().
    setSelectionMode(QAbstractItemView::ExtendedSelection);
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
    QScrollBar *scroll_bar = horizontalScrollBar();
    // Make sure the range can hold the primary view's position before
    // applying it, so the value isn't clamped.
    if (value > scroll_bar->maximum()) {
        scroll_bar->setRange(scroll_bar->minimum(), value);
    }
    scroll_bar->setValue(value);
}

void PinnedRowView::updateGeometries()
{
    QTreeView::updateGeometries();

    if (packet_list_) {
        QScrollBar *scroll_bar = horizontalScrollBar();
        int primary_max = packet_list_->horizontalScrollBar()->maximum();
        if (primary_max > scroll_bar->maximum()) {
            scroll_bar->setRange(scroll_bar->minimum(), primary_max);
        }
        scroll_bar->setValue(packet_list_->horizontalScrollBar()->value());
    }
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
    drag_index_ = QPersistentModelIndex();

    // Select natively in this view's own selection model, so Ctrl/Shift
    // ranges are scoped to the strip's own row order. The selection is
    // linked to the primary view's by PacketList: a packet that has a row
    // there is selected in both.
    QTreeView::mousePressEvent(event);

    if (!packet_list || !pinned_model || !index.isValid()) {
        return;
    }

    QModelIndex source_index = pinned_model->mapToSource(index);
    if (event->button() == Qt::LeftButton) {
        drag_index_ = index;
    }
    if (event->buttons() & Qt::MiddleButton) {
        packet_list->toggleFrameMarkFromClick(source_index);
    }
}

void PinnedRowView::mouseReleaseEvent(QMouseEvent *event)
{
    drag_index_ = QPersistentModelIndex();

    // Also dispatches to the column's delegate, e.g. for the tag column's
    // click-to-open-link handling.
    QTreeView::mouseReleaseEvent(event);
}

void PinnedRowView::mouseMoveEvent(QMouseEvent *event)
{
    PacketList *packet_list = packet_list_;
    PinnedRowsModel *pinned_model = qobject_cast<PinnedRowsModel *>(model());
    if (!packet_list || !pinned_model) {
        return;
    }

    // Read the frame number straight off this index's own internal
    // pointer (the PacketListRecord -- see PinnedRowsModel::index()), so
    // hovering a pinned packet that's been filtered out of the primary
    // view still highlights it here.
    QModelIndex index = indexAt(event->pos());
    PacketListRecord *record = index.isValid() ?
        static_cast<PacketListRecord *>(index.internalPointer()) : nullptr;
    frame_data *fdata = record ? record->frameData() : nullptr;
    packet_list->setHoveredFrameNum(fdata ? (int)fdata->num : -1);

    // Starting a cell drag replaces QAbstractItemView's drag-to-select.
    if ((event->buttons() & Qt::LeftButton) && drag_index_.isValid() && index == drag_index_) {
        drag_index_ = QPersistentModelIndex();
        packet_list->startCellDragForSourceIndex(pinned_model->mapToSource(index));
    }
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

    // Same as a right-click in the primary view (see
    // PacketList::contextMenuEvent()).
    if (packet_list->multiSelectActive()) {
        selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }
    packet_list->showContextMenuForSourceIndex(pinned_model->mapToSource(index), event->globalPos(),
                                               /* from_pinned_row_strip */ true);
}

void PinnedRowView::wheelEvent(QWheelEvent *event)
{
    PacketList *packet_list = packet_list_;
    if (packet_list) {
        packet_list->forwardWheelEvent(event);
    }
}

void PinnedRowView::drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    PacketList *packet_list = packet_list_;
    // index's own internal pointer is the PacketListRecord (see
    // PinnedRowsModel::index()).
    frame_data *fdata = nullptr;
    if (PacketListRecord *record = static_cast<PacketListRecord *>(index.internalPointer())) {
        fdata = record->frameData();
    }

    QTreeView::drawRow(painter, option, index);

    // The hover highlight is driven by hovered_frame_num_ rather than Qt's
    // native per-widget hover state, since the mouse hovering a pinned
    // overlay view needs to highlight this row here too -- native :hover
    // styling only ever reacts to the mouse being over this specific
    // widget. Painted even on a selected row so hover wins over
    // selection, matching PacketList::drawRow(). Uses
    // ColorUtils::paintFlatCell() rather than re-invoking each column's
    // delegate with overridden palette roles -- see
    // PacketList::drawRow()'s own comment (this mirrors it exactly) for
    // why: QStyledItemDelegate::paint() re-fetches Qt::BackgroundRole
    // from the model via initStyleOption(), clobbering any
    // backgroundBrush/palette override made beforehand, so a
    // colored/marked/ignored row's own background always won that fight
    // instead of the flat hover color.
    if (packet_list && prefs.gui_packet_list_hover_style) {
        if (fdata && (int)fdata->num == packet_list->hoveredFrameNum()) {
            QColor hover_bg = ColorUtils::hoverBackground();
            QColor text_color = palette().color(QPalette::Text);
            for (int visual_col = 0; visual_col < header()->count(); visual_col++) {
                int logical_col = header()->logicalIndex(visual_col);
                if (isColumnHidden(logical_col)) {
                    continue;
                }
                QModelIndex col_index = index.siblingAtColumn(logical_col);
                QStyleOptionViewItem col_option = option;
                col_option.rect = visualRect(col_index);
                if (get_column_format(logical_col) == COL_TAG) {
                    // See PacketList::drawRow()'s own comment for why the tag
                    // column needs its content painted separately rather than
                    // through paintFlatCell().
                    painter->save();
                    painter->fillRect(col_option.rect, hover_bg);
                    painter->restore();
                    packet_list->tagColumnDelegate().paintContent(painter, col_option, col_index);
                    continue;
                }
                ColorUtils::paintFlatCell(painter, this, col_option, col_index, hover_bg, text_color);
            }
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
