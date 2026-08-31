/* multi_color_packet_delegate.cpp
 *
 * Custom Qt delegate for rendering multi-color stripes in the GUI packet list
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "multi_color_packet_delegate.h"
#include "packet_list_record.h"
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/packet_list.h>
#include <ui/qt/widgets/pinned_column_view.h>
#include <ui/qt/widgets/pinned_row_view.h>

#include <epan/color_filters.h>
#include <epan/prefs.h>
#include <ui/recent.h>

#include <QAbstractScrollArea>
#include <QPainter>
#include <QPainterPath>
#include <QPolygon>
#include <QApplication>

// Resolved once per paint() call (see OverlayWidget's own comment) rather
// than every helper independently re-running its own qobject_cast chain --
// paint() is called once per visible cell on every repaint (scroll, hover,
// resize), so this avoids up to 4 redundant RTTI walks per cell.
OverlayWidget OverlayWidget::resolve(const QWidget *widget)
{
    OverlayWidget result;
    result.column_view = qobject_cast<const PinnedColumnView *>(widget);
    result.row_view = qobject_cast<const PinnedRowView *>(widget);
    return result;
}

// The frozen-column overlay (PinnedColumnView, and the pinned-row strip's
// own "corner" PinnedRowView instance -- see PinnedRowView::isCornerView())
// renders a single narrow, frozen slice of a row in isolation, so a
// multi-color stripe pattern sized to its own (much narrower) viewport
// width would look nothing like the pattern painted in the primary,
// full-width view. Paint a flat primary-color fill there instead so the
// frozen columns visually match the rest of the row.
//
// The pinned-row strip's main (non-corner) instance is not included here:
// unlike the frozen-column overlays, it's expected to visually follow the
// same multi-color mode as the primary view (full stripes or
// shift-right), just scaled to its own width via usableWidth() below -- a
// flat fill there would show only the first matching rule's color, which
// doesn't reflect the multi-color rule set at all.
static bool isPinnedOverlayWidget(const OverlayWidget &widget)
{
    if (widget.column_view) {
        return true;
    }
    if (widget.row_view) {
        return widget.row_view->isCornerView();
    }
    return false;
}

// Returns the usable width for stripe painting.
// option.widget is the QAbstractItemView (outer widget). Qt sizes its
// viewport to exclude the full OverlayScrollBar (minimap + button), so
// the viewport width is exactly the paintable content area.
//
// The pinned-row strip's main instance has no scrollbar of its own
// (unlike the primary view, whose OverlayScrollBar takes up real width),
// so its own viewport is wider than the primary view's by that amount.
// Rather than compress the stripe pattern to match the primary view's
// narrower width here, PinnedRowView::drawRow() instead paints that
// trailing sliver over in a flat grey matching the scrollbar's own
// color, after the normal per-column delegate painting below -- see its
// own comment for why. The stripe pattern itself, though, still needs to
// be sized to the same width the primary view uses (its own viewport,
// which excludes its scrollbar) -- comparing against
// parentWidget()->width() directly (which includes the grey sliver's
// reserved space) stretched the pattern wider than the primary view's,
// creeping every stripe boundary rightward as pinned rows accumulated.
//
// When a column freeze is active, the main instance's own viewport only
// spans its share of the strip (the non-frozen columns) -- it no longer
// reflects the full row width the stripe pattern needs to be computed
// against (that's parentWidget()->width() minus the scrollbar sliver,
// the same quantity PinnedRowView::drawRow()'s own scrollbar-sliver
// calculation uses). Without the parentWidget()->width() part of this,
// the stripe pattern was sized to only the non-frozen portion's width
// while still being positioned starting at this view's own local x=0,
// which is the frozen boundary rather than the row's true left edge --
// shifting every stripe boundary to the right by the frozen columns'
// width once frozen, and back once unfrozen.
static int usableWidth(const QWidget *widget, const OverlayWidget &overlay)
{
    if (!widget) return 2000;
    if (overlay.row_view && !overlay.row_view->isCornerView() &&
        overlay.row_view->parentWidget() && overlay.row_view->packetList()) {
        int scrollbar_width = overlay.row_view->parentWidget()->width() - overlay.row_view->packetList()->viewport()->width();
        return overlay.row_view->parentWidget()->width() - qMax(scrollbar_width, 0);
    }
    if (const QAbstractScrollArea *sa = qobject_cast<const QAbstractScrollArea *>(widget))
        return sa->viewport()->width();
    return widget->width();
}

// The stripe/shift-right patterns painted by drawStripedBackground() and
// drawShiftRightBackground() are computed in full-row coordinate space
// (0..usableWidth()), matching the primary view where each column's own
// option.rect already sits at that column's true offset within the row.
//
// The pinned-row strip's main (non-corner) instance breaks that
// assumption once a column freeze is active: its own frozen columns are
// hidden (zero width), so its first visible column's option.rect starts
// at local x=0 -- not at the frozen columns' combined width, which is
// where that column actually sits in the full row usableWidth() is
// computed against. Left uncorrected, the whole pattern would be
// computed for the full row but painted as if this view's local origin
// were the row's true left edge, shifting every stripe boundary left by
// the frozen width.
//
// This instance is a direct child of pinned_rows_strip_'s QHBoxLayout,
// laid out immediately after the corner instance (see
// PacketListPane), so its own x() within that shared parent is exactly
// the frozen columns' combined width -- the same offset needed here.
static int xOffset(const OverlayWidget &overlay)
{
    if (overlay.row_view && !overlay.row_view->isCornerView()) {
        return overlay.row_view->x();
    }
    return 0;
}

MultiColorPacketDelegate::MultiColorPacketDelegate(QWidget *parent)
    : QStyledItemDelegate(parent)
{
}

void MultiColorPacketDelegate::paint(QPainter *painter,
                                     const QStyleOptionViewItem &option,
                                     const QModelIndex &index) const
{
    PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
    if (!record) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    const frame_data *fdata = record->frameData();
    if (!fdata) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    // Check if colorization is enabled (respects "Draw packets using coloring rules" button)
    if (!recent.packet_list_colorize) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    // Check if multi-color row painting is active (skip Off and Scrollbar Only modes)
    if (prefs.gui_packet_list_multi_color_mode == PACKET_LIST_MULTI_COLOR_MODE_OFF ||
        prefs.gui_packet_list_multi_color_mode == PACKET_LIST_MULTI_COLOR_MODE_SCROLLBAR_ONLY ||
        !record->hasMultipleColors()) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    // Handle priority: ignored > marked > colored
    if (fdata->ignored || fdata->marked) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    // Conversation color filters take full precedence — render as solid single color
    if (fdata->color_filter &&
        strncmp(((const color_filter_t *)fdata->color_filter)->filter_name,
                CONVERSATION_COLOR_PREFIX, strlen(CONVERSATION_COLOR_PREFIX)) == 0) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    // If selected or hovered, use default rendering to show feedback
    if (option.state & (QStyle::State_Selected | QStyle::State_MouseOver)) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    // Collect colors from matching filters (skip paused filters)
    QList<QColor> bg_colors;
    const color_filter_t *primary_filter = NULL;
    const GSList *filters = record->matchingColorFilters();
    for (const GSList *item = filters; item != NULL; item = g_slist_next(item)) {
        const color_filter_t *colorf = (const color_filter_t *)item->data;
        // Skip session-disabled (paused) filters
        if (!color_filter_is_session_disabled(colorf->filter_name)) {
            bg_colors.append(ColorUtils::fromColorT(&colorf->bg_color));
            if (!primary_filter) {
                primary_filter = colorf;  // First non-paused filter is primary
            }
        }
    }

    if (bg_colors.isEmpty()) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    // Draw custom multi-color background
    painter->save();

    // Get primary color filter for text color
    QColor primary_fg = ColorUtils::fromColorT(&primary_filter->fg_color);

    OverlayWidget overlay = OverlayWidget::resolve(option.widget);

    if (isPinnedOverlayWidget(overlay)) {
        // A frozen-column overlay (PinnedColumnView, or the pinned-row
        // strip's own corner PinnedRowView instance) only ever shows a
        // narrow, frozen slice of the row; painting a flat fill (rather
        // than stripes sized to that slice's own width) keeps it
        // visually consistent with the full-width pattern in the
        // primary view. The pinned-row strip's main (non-corner)
        // instance is deliberately excluded from this (see
        // isPinnedOverlayWidget()) so it falls through to the same
        // stripe/shift-right rendering as the primary view below, just
        // scaled to its own narrower width.
        painter->setClipRect(option.rect);
        painter->fillRect(option.rect, bg_colors.first());
    } else if (prefs.gui_packet_list_multi_color_mode == PACKET_LIST_MULTI_COLOR_MODE_SHIFT_RIGHT) {
        // Shift Right mode: primary color at configured percentage, remainder as stripes
        drawShiftRightBackground(painter, option, bg_colors, overlay);
    } else {
        // Full stripes mode
        drawStripedBackground(painter, option, bg_colors, overlay);
        // Calculate foreground based on average luminance for full stripes
        primary_fg = calculateForeground(bg_colors);
    }

    // Now draw the text properly using Qt's rendering
    QStyleOptionViewItem text_option = option;
    initStyleOption(&text_option, index);

    // Clear background rendering flags
    text_option.backgroundBrush = QBrush();
    text_option.palette.setBrush(QPalette::Base, QBrush());
    text_option.palette.setBrush(QPalette::Window, QBrush());

    // Set custom text color
    text_option.palette.setColor(QPalette::Text, primary_fg);
    text_option.palette.setColor(QPalette::WindowText, primary_fg);
    text_option.palette.setColor(QPalette::HighlightedText, primary_fg);

    // Use the widget style to draw the item content (text, icons) without background
    QApplication::style()->drawControl(QStyle::CE_ItemViewItem, &text_option, painter, nullptr);

    painter->restore();
}

void MultiColorPacketDelegate::drawStripedBackground(QPainter *painter,
                                                     const QStyleOptionViewItem &option,
                                                     const QList<QColor> &colors,
                                                     const OverlayWidget &overlay) const
{
    if (colors.isEmpty()) return;

    int totalWidth = usableWidth(option.widget, overlay);
    int offset = xOffset(overlay);
    int num_colors = static_cast<int>(colors.size());
    int stripe_width = totalWidth / num_colors;
    int row_height = option.rect.height();
    int y_top = option.rect.y();
    int y_bottom = y_top + row_height;

    gui_packet_list_multi_color_separator_e sep = prefs.gui_packet_list_multi_color_separator;

    for (int i = 0; i < num_colors; ++i) {
        int x_start = i * stripe_width - offset;
        int x_end = (i == num_colors - 1) ? totalWidth - offset : (i + 1) * stripe_width - offset;

        painter->save();
        painter->setClipRect(option.rect);
        painter->setBrush(colors[i]);
        painter->setPen(Qt::NoPen);

        if (sep == PACKET_LIST_MULTI_COLOR_SEPARATOR_VERTICAL) {
            painter->fillRect(QRect(x_start, y_top, x_end - x_start, row_height), colors[i]);
        } else if (sep == PACKET_LIST_MULTI_COLOR_SEPARATOR_BUBBLE) {
            // Half-moon bubble separator: arcs bulge rightward at each junction
            int radius = row_height / 2;
            QPainterPath path;
            path.moveTo(x_start, y_top);
            path.lineTo(x_end, y_top);
            if (i < num_colors - 1) {
                // Right edge: arc from (x_end, y_top) to (x_end, y_bottom), bulging right
                path.arcTo(x_end - radius, y_top, 2 * radius, row_height, 90, -180);
            } else {
                path.lineTo(x_end, y_bottom);
            }
            path.lineTo(x_start, y_bottom);
            if (i > 0) {
                // Left edge: matching arc from (x_start, y_bottom) to (x_start, y_top), bulging right
                path.arcTo(x_start - radius, y_top, 2 * radius, row_height, 270, 180);
            }
            path.closeSubpath();
            painter->drawPath(path);
        } else {
            // Diagonal (default): trapezoid with 45-degree edges
            const int DIAG = row_height;
            QPolygon trapezoid;
            if (i == 0) {
                trapezoid << QPoint(x_start, y_top)
                          << QPoint(x_start, y_bottom)
                          << QPoint(x_end + DIAG, y_bottom)
                          << QPoint(x_end, y_top);
            } else if (i == num_colors - 1) {
                trapezoid << QPoint(x_start, y_top)
                          << QPoint(x_start + DIAG, y_bottom)
                          << QPoint(x_end, y_bottom)
                          << QPoint(x_end, y_top);
            } else {
                trapezoid << QPoint(x_start, y_top)
                          << QPoint(x_start + DIAG, y_bottom)
                          << QPoint(x_end + DIAG, y_bottom)
                          << QPoint(x_end, y_top);
            }
            painter->drawPolygon(trapezoid);
        }

        painter->restore();
    }
}

void MultiColorPacketDelegate::drawShiftRightBackground(QPainter *painter,
                                                        const QStyleOptionViewItem &option,
                                                        const QList<QColor> &colors,
                                                        const OverlayWidget &overlay) const
{
    if (colors.isEmpty()) return;

    int totalWidth = usableWidth(option.widget, overlay);
    int offset = xOffset(overlay);
    int row_height = option.rect.height();
    int y_top = option.rect.y();
    int y_bottom = y_top + row_height;

    // If only one color, fill 100% (no stripes needed)
    if (colors.size() == 1) {
        painter->save();
        painter->setClipRect(option.rect);
        painter->fillRect(QRect(-offset, y_top, totalWidth, row_height), colors[0]);
        painter->restore();
        return;
    }

    gui_packet_list_multi_color_separator_e sep = prefs.gui_packet_list_multi_color_separator;

    // Multiple colors: primary color takes configured %, remainder as stripes
    double primary_frac = prefs.gui_packet_list_multi_color_shift_percent / 100.0;
    int primaryWidth = static_cast<int>(totalWidth * primary_frac);
    int stripesWidth = totalWidth - primaryWidth;

    // Draw primary color block
    painter->save();
    painter->setClipRect(option.rect);
    painter->setBrush(colors[0]);
    painter->setPen(Qt::NoPen);

    int x0 = -offset;
    int x_primary_end = primaryWidth - offset;

    if (sep == PACKET_LIST_MULTI_COLOR_SEPARATOR_VERTICAL) {
        painter->fillRect(QRect(x0, y_top, x_primary_end - x0, row_height), colors[0]);
    } else if (sep == PACKET_LIST_MULTI_COLOR_SEPARATOR_BUBBLE) {
        int radius = row_height / 2;
        QPainterPath path;
        path.moveTo(x0, y_top);
        path.lineTo(x_primary_end, y_top);
        path.arcTo(x_primary_end - radius, y_top, 2 * radius, row_height, 90, -180);
        path.lineTo(x0, y_bottom);
        path.closeSubpath();
        painter->drawPath(path);
    } else {
        // Diagonal
        const int DIAG = row_height;
        QPolygon primaryTrapezoid;
        primaryTrapezoid << QPoint(x0, y_top)
                         << QPoint(x0, y_bottom)
                         << QPoint(x_primary_end + DIAG, y_bottom)
                         << QPoint(x_primary_end, y_top);
        painter->drawPolygon(primaryTrapezoid);
    }
    painter->restore();

    // Draw stripes in the remainder with additional colors (skip colors[0])
    int num_additional = static_cast<int>(colors.size()) - 1;
    if (num_additional > 0) {
        int stripe_width = stripesWidth / num_additional;

        for (int i = 0; i < num_additional; ++i) {
            int x_start = primaryWidth + i * stripe_width - offset;
            int x_end = (i == num_additional - 1) ? totalWidth - offset : primaryWidth + (i + 1) * stripe_width - offset;

            painter->save();
            painter->setClipRect(option.rect);
            painter->setBrush(colors[i + 1]);
            painter->setPen(Qt::NoPen);

            if (sep == PACKET_LIST_MULTI_COLOR_SEPARATOR_VERTICAL) {
                painter->fillRect(QRect(x_start, y_top, x_end - x_start, row_height), colors[i + 1]);
            } else if (sep == PACKET_LIST_MULTI_COLOR_SEPARATOR_BUBBLE) {
                int radius = row_height / 2;
                QPainterPath path;
                path.moveTo(x_start, y_top);
                path.lineTo(x_end, y_top);
                if (i < num_additional - 1) {
                    path.arcTo(x_end - radius, y_top, 2 * radius, row_height, 90, -180);
                } else {
                    path.lineTo(x_end, y_bottom);
                }
                path.lineTo(x_start, y_bottom);
                // Left edge: concave arc matching previous stripe's right arc
                path.arcTo(x_start - radius, y_top, 2 * radius, row_height, 270, 180);
                path.closeSubpath();
                painter->drawPath(path);
            } else {
                // Diagonal
                const int DIAG = row_height;
                QPolygon trapezoid;
                if (i == 0) {
                    trapezoid << QPoint(x_start, y_top)
                              << QPoint(x_start + DIAG, y_bottom)
                              << QPoint(x_end + DIAG, y_bottom)
                              << QPoint(x_end, y_top);
                } else if (i == num_additional - 1) {
                    trapezoid << QPoint(x_start, y_top)
                              << QPoint(x_start + DIAG, y_bottom)
                              << QPoint(x_end, y_bottom)
                              << QPoint(x_end, y_top);
                } else {
                    trapezoid << QPoint(x_start, y_top)
                              << QPoint(x_start + DIAG, y_bottom)
                              << QPoint(x_end + DIAG, y_bottom)
                              << QPoint(x_end, y_top);
                }
                painter->drawPolygon(trapezoid);
            }

            painter->restore();
        }
    }
}

QColor MultiColorPacketDelegate::calculateForeground(const QList<QColor> &backgrounds) const
{
    // Calculate average luminance of all background colors
    double total_luma = 0.0;
    for (const QColor &bg : backgrounds) {
        // Use ITU-R BT.709 coefficients
        double luma = 0.2126 * bg.redF() +
                     0.7152 * bg.greenF() +
                     0.0722 * bg.blueF();
        total_luma += luma;
    }
    double avg_luma = total_luma / backgrounds.size();

    // Return black for light backgrounds, white for dark backgrounds
    return (avg_luma > 0.5) ? Qt::black : Qt::white;
}
