/* percent_bar_delegate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/percent_bar_delegate.h>

#include <ui/qt/utils/color_utils.h>

#include <QApplication>
#include <QPainter>

static const int bar_em_width_ = 8;
static const double bar_blend_ = 0.15;

void PercentBarDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                               const QModelIndex &index) const
{
    QStyleOptionViewItem option_vi = option;
    QStyledItemDelegate::initStyleOption(&option_vi, index);

    // Paint our rect with no text using the current style, then draw our
    // bar and text over it.
    QStyledItemDelegate::paint(painter, option, index);

    bool ok = false;
    double value = index.data(Qt::UserRole).toDouble(&ok);

    if (!ok || !index.data(Qt::DisplayRole).toString().isEmpty()) {
        // We don't have a valid value or the item has visible text.
        return;
    }

    // If our value is out range our caller has a bug. Clamp the graph and
    // Print the numeric value so that the bug is obvious.
    QString pct_str = QString::number(value, 'f', 1);
    if (value < 0) {
        value = 0;
    }
    if (value > 100.0) {
        value = 100.0;
    }

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
    QRect pct_rect = option.rect;
    pct_rect.adjust(1, 1, -1, -1);
    pct_rect.setWidth(((pct_rect.width() * value) / 100.0) + 0.5);
    painter->setPen(Qt::NoPen);
    painter->setBrush(bar_color);
    painter->drawRoundedRect(pct_rect, border_radius, border_radius);
    painter->restore();

    painter->save();
    painter->setPen(text_color);
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
