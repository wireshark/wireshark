/* percent_bar_delegate.cpp
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

#include "percent_bar_delegate.h"

#include "color_utils.h"

#include <QApplication>
#include <QPainter>

static const int bar_em_width_ = 8;
static const double bar_blend_ = 0.15;

void PercentBarDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                               const QModelIndex &index) const
{
    QStyleOptionViewItemV4 optv4 = option;
    QStyledItemDelegate::initStyleOption(&optv4, index);

    QStyledItemDelegate::paint(painter, option, index);

    bool ok = false;
    double value = index.data(Qt::UserRole).toDouble(&ok);

    if (!ok || !index.data(Qt::DisplayRole).toString().isEmpty()) {
        // We don't have a valid value or the item has visible text.
        return;
    }

    painter->save();

    if (QApplication::style()->objectName().contains("vista")) {
        // QWindowsVistaStyle::drawControl does this internally. Unfortunately there
        // doesn't appear to be a more general way to do this.
        optv4.palette.setColor(QPalette::All, QPalette::HighlightedText,
                               optv4.palette.color(QPalette::Active, QPalette::Text));
    }

    QColor bar_color = ColorUtils::alphaBlend(optv4.palette.windowText(),
                                              optv4.palette.window(), bar_blend_);
    QPalette::ColorGroup cg = optv4.state & QStyle::State_Enabled
                              ? QPalette::Normal : QPalette::Disabled;
    if (cg == QPalette::Normal && !(optv4.state & QStyle::State_Active))
        cg = QPalette::Inactive;
    if (optv4.state & QStyle::State_Selected) {
        painter->setPen(optv4.palette.color(cg, QPalette::HighlightedText));
        bar_color = ColorUtils::alphaBlend(optv4.palette.color(cg, QPalette::Window),
                                           optv4.palette.color(cg, QPalette::Highlight),
                                           bar_blend_);
    } else {
        painter->setPen(optv4.palette.color(cg, QPalette::Text));
    }

    QRect pct_rect = option.rect;
    pct_rect.adjust(1, 1, -1, -1);
    pct_rect.setWidth(((pct_rect.width() * value) / 100.0) + 0.5);
    painter->fillRect(pct_rect, bar_color);

    QString pct_str = QString::number(value, 'f', 1);
    painter->drawText(option.rect, Qt::AlignCenter, pct_str);

    painter->restore();
}

QSize PercentBarDelegate::sizeHint(const QStyleOptionViewItem &option,
                                   const QModelIndex &index) const
{
    return QSize(option.fontMetrics.height() * bar_em_width_,
                 QStyledItemDelegate::sizeHint(option, index).height());
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
