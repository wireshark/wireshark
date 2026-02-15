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

#include <epan/color_filters.h>
#include <epan/prefs.h>
#include <ui/recent.h>

#include <QAbstractScrollArea>
#include <QPainter>
#include <QPainterPath>
#include <QPolygon>
#include <QApplication>

// Returns the usable width for stripe painting.
// option.widget is the QAbstractItemView (outer widget). Qt sizes its
// viewport to exclude the full OverlayScrollBar (minimap + button), so
// the viewport width is exactly the paintable content area.
static int usableWidth(const QWidget *widget)
{
    if (!widget) return 2000;
    if (const QAbstractScrollArea *sa = qobject_cast<const QAbstractScrollArea *>(widget))
        return sa->viewport()->width();
    return widget->width();
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

    if (prefs.gui_packet_list_multi_color_mode == PACKET_LIST_MULTI_COLOR_MODE_SHIFT_RIGHT) {
        // Shift Right mode: primary color at configured percentage, remainder as stripes
        drawShiftRightBackground(painter, option, bg_colors);
    } else {
        // Full stripes mode
        drawStripedBackground(painter, option, bg_colors);
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
                                                     const QList<QColor> &colors) const
{
    if (colors.isEmpty()) return;

    int totalWidth = usableWidth(option.widget);
    int num_colors = static_cast<int>(colors.size());
    int stripe_width = totalWidth / num_colors;
    int row_height = option.rect.height();
    int y_top = option.rect.y();
    int y_bottom = y_top + row_height;

    gui_packet_list_multi_color_separator_e sep = prefs.gui_packet_list_multi_color_separator;

    for (int i = 0; i < num_colors; ++i) {
        int x_start = i * stripe_width;
        int x_end = (i == num_colors - 1) ? totalWidth : (i + 1) * stripe_width;

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
                                                        const QList<QColor> &colors) const
{
    if (colors.isEmpty()) return;

    int totalWidth = usableWidth(option.widget);
    int row_height = option.rect.height();
    int y_top = option.rect.y();
    int y_bottom = y_top + row_height;

    // If only one color, fill 100% (no stripes needed)
    if (colors.size() == 1) {
        painter->save();
        painter->setClipRect(option.rect);
        painter->fillRect(QRect(0, y_top, totalWidth, row_height), colors[0]);
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

    if (sep == PACKET_LIST_MULTI_COLOR_SEPARATOR_VERTICAL) {
        painter->fillRect(QRect(0, y_top, primaryWidth, row_height), colors[0]);
    } else if (sep == PACKET_LIST_MULTI_COLOR_SEPARATOR_BUBBLE) {
        int radius = row_height / 2;
        QPainterPath path;
        path.moveTo(0, y_top);
        path.lineTo(primaryWidth, y_top);
        path.arcTo(primaryWidth - radius, y_top, 2 * radius, row_height, 90, -180);
        path.lineTo(0, y_bottom);
        path.closeSubpath();
        painter->drawPath(path);
    } else {
        // Diagonal
        const int DIAG = row_height;
        QPolygon primaryTrapezoid;
        primaryTrapezoid << QPoint(0, y_top)
                         << QPoint(0, y_bottom)
                         << QPoint(primaryWidth + DIAG, y_bottom)
                         << QPoint(primaryWidth, y_top);
        painter->drawPolygon(primaryTrapezoid);
    }
    painter->restore();

    // Draw stripes in the remainder with additional colors (skip colors[0])
    int num_additional = static_cast<int>(colors.size()) - 1;
    if (num_additional > 0) {
        int stripe_width = stripesWidth / num_additional;

        for (int i = 0; i < num_additional; ++i) {
            int x_start = primaryWidth + i * stripe_width;
            int x_end = (i == num_additional - 1) ? totalWidth : primaryWidth + (i + 1) * stripe_width;

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
