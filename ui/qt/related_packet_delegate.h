/* related_packet_delegate.h
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

#ifndef RELATED_PACKET_DELEGATE_H
#define RELATED_PACKET_DELEGATE_H

#include "config.h"

#include "epan/conversation.h"

#include <QList>
#include <QStyledItemDelegate>

class RelatedPacketDelegate : public QStyledItemDelegate
{
public:
    RelatedPacketDelegate(QWidget *parent = 0) : QStyledItemDelegate(parent) { clear(); }
    void clear();
    void addRelatedFrame(int frame_num);
    void setConversationSpan(int first_frame, int last_frame);

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const;

private:
    QList<int> related_frames_;
    int first_frame_;
    int last_frame_;

signals:


};

#endif // RELATED_PACKET_DELEGATE_H

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
