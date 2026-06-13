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

#include <QPainter>
#include <ui/qt/utils/theme_manager.h>

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
        }
    }

    QStyledItemDelegate::paint(painter, option, index);
}
