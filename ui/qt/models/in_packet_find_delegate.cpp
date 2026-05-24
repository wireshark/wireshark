/* in_packet_find_delegate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "in_packet_find_delegate.h"
#include <ui/qt/in_packet_find_bar.h>

#include <QPainter>

InPacketFindDelegate::InPacketFindDelegate(InPacketFindBar *find_bar, QObject *parent) :
    QStyledItemDelegate(parent),
    find_bar_(find_bar)
{
}

void InPacketFindDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
{
    if (find_bar_ && find_bar_->isVisible()) {
        bool is_current = find_bar_->isCurrentMatch(index);
        bool is_match = is_current || find_bar_->isMatch(index);

        if (is_match) {
            painter->save();

            bool dark = find_bar_->isDarkMode();
            QColor match_color = dark ? QColor(0xb8, 0x9a, 0x00) : QColor(0xf6, 0xd3, 0x2d);
            QColor current_color = dark ? QColor(0xc8, 0x50, 0x00) : QColor(0xe6, 0x60, 0x00);

            QRect rect = option.rect;

            if (is_current) {
                painter->fillRect(rect, current_color);
                painter->setPen(QPen(current_color.darker(130), 1));
                painter->drawRect(rect.adjusted(0, 0, -1, -1));
            } else {
                painter->fillRect(rect, match_color);
            }

            painter->restore();
        }
    }

    // Draw the standard content on top
    QStyledItemDelegate::paint(painter, option, index);
}
