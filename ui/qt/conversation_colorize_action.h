/* conversation_colorize_action.h
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

#ifndef CONVERSATIONCOLORIZEACTION_H
#define CONVERSATIONCOLORIZEACTION_H

#include <QAction>

struct conversation_filter_s;
struct _packet_info;

// Actions for "Conversation Filter" and "Colorize with Filter" menu items.

class ConversationAction : public QAction
{
    Q_OBJECT
public:
    ConversationAction(QObject *parent, struct conversation_filter_s *conv_filter = NULL);

    bool isFilterValid(struct _packet_info *pinfo);

    const QByteArray filter() { return filter_ba_; }

    void setColorNumber(int color_number) { color_number_ = color_number; }
    int colorNumber() { return color_number_; }

public slots:
    // Exactly one of these should be connected.
    void setPacketInfo(struct _packet_info *pinfo);
    void setFieldFilter(const QByteArray field_filter);

private:
    struct conversation_filter_s *conv_filter_;
    QByteArray filter_ba_;
    int color_number_;
};

class ColorizeAction : public QAction
{
    Q_OBJECT
public:
    ColorizeAction(QObject *parent) : QAction(parent),
        color_number_(-1)
    {}

    const QByteArray filter() { return filter_ba_; }

    void setColorNumber(int color_number) { color_number_ = color_number; }
    int colorNumber() { return color_number_; }

public slots:
    void setFieldFilter(const QByteArray field_filter) { filter_ba_ = field_filter; }

private:
    QByteArray filter_ba_;
    int color_number_;
};

#endif // CONVERSATIONCOLORIZEACTION_H

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
