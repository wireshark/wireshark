/* in_packet_find_delegate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "in_packet_find_delegate.h"
#include <ui/qt/in_packet_search.h>

#include <QApplication>
#include <QPainter>
#include <QStyle>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

InPacketFindDelegate::InPacketFindDelegate(InPacketSearch *search, QObject *parent) :
    QStyledItemDelegate(parent),
    search_(search)
{
}

void InPacketFindDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
{
    if (search_ && search_->highlightsVisible()) {
        bool is_current = search_->isCurrentMatch(index);
        bool is_match = is_current || search_->isMatch(index);

        if (is_match) {
            painter->save();

            const QColor match_color = ThemeManager::instance()->color(ThemeManager::HighlightColorOrange);
            const QColor current_color = ThemeManager::instance()->color(ThemeManager::AccentError);
            const QColor border_color = ThemeManager::instance()->color(ThemeManager::PaletteMid);

            QRect rect = option.rect;

            if (is_current) {
                painter->fillRect(rect, current_color);
                painter->setPen(QPen(border_color, 1));
                painter->drawRect(rect.adjusted(0, 0, -1, -1));
            } else {
                painter->fillRect(rect, match_color);
            }

            painter->restore();

            // Draw the item over the fill with text that contrasts with it.
            QStyleOptionViewItem opt(option);
            initStyleOption(&opt, index);
            const QColor fill = is_current ? current_color : match_color;
            const QColor text = ColorMath::contrastingText(fill);
            opt.palette.setColor(QPalette::All, QPalette::Text, text);
            if (!(opt.state & QStyle::State_Selected)) {
                opt.backgroundBrush = QBrush();
            }
            const QWidget *w = opt.widget;
            QStyle *s = w ? w->style() : QApplication::style();
            s->drawControl(QStyle::CE_ItemViewItem, &opt, painter, w);
            return;
        }
    }

    QStyledItemDelegate::paint(painter, option, index);
}
