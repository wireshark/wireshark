/* timeline_delegate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "timeline_delegate.h"

#include "color_utils.h"

#include <QApplication>
#include <QPainter>

// XXX We might want to move this to conversation_dialog.cpp.

// PercentBarDelegate uses a stronger blend value, but its bars are also
// more of a prominent feature. Make the blend weaker here so that we don't
// obscure our text.
static const double bar_blend_ = 0.08;

TimelineDelegate::TimelineDelegate(QWidget *parent) :
    QStyledItemDelegate(parent)
{}

void TimelineDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                               const QModelIndex &index) const
{
    QStyleOptionViewItem option_vi = option;
    QStyledItemDelegate::initStyleOption(&option_vi, index);

    struct timeline_span span_px = index.data(Qt::UserRole).value<struct timeline_span>();

    // Paint our rect with no text using the current style, then draw our
    // bar and text over it.
    QStyledItemDelegate::paint(painter, option, index);

    if (QApplication::style()->objectName().contains("vista")) {
        // QWindowsVistaStyle::drawControl does this internally. Unfortunately there
        // doesn't appear to be a more general way to do this.
        option_vi.palette.setColor(QPalette::All, QPalette::HighlightedText,
                               option_vi.palette.color(QPalette::Active, QPalette::Text));
    }

    QPalette::ColorGroup cg = option_vi.state & QStyle::State_Enabled
                              ? QPalette::Normal : QPalette::Disabled;
    QColor text_color = option_vi.palette.color(cg, QPalette::Text);
    QColor bar_color = ColorUtils::alphaBlend(option_vi.palette.windowText(),
                                              option_vi.palette.window(), bar_blend_);

    if (cg == QPalette::Normal && !(option_vi.state & QStyle::State_Active))
        cg = QPalette::Inactive;
    if (option_vi.state & QStyle::State_Selected) {
        text_color = option_vi.palette.color(cg, QPalette::HighlightedText);
        bar_color = ColorUtils::alphaBlend(option_vi.palette.color(cg, QPalette::Window),
                                           option_vi.palette.color(cg, QPalette::Highlight),
                                           bar_blend_);
    }

    painter->save();
    int border_radius = 3; // We use 3 px elsewhere, e.g. filter combos.
    QRect timeline_rect = option.rect;
    timeline_rect.adjust(span_px.start, 1, 0, -1);
    timeline_rect.setWidth(span_px.width);
    painter->setClipRect(option.rect);
    painter->setPen(Qt::NoPen);
    painter->setBrush(bar_color);
    painter->drawRoundedRect(timeline_rect, border_radius, border_radius);
    painter->restore();

    painter->save();
    painter->setPen(text_color);
    painter->drawText(option.rect, Qt::AlignCenter, index.data(Qt::DisplayRole).toString());
    painter->restore();
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
