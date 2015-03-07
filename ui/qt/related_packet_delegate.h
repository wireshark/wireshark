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

#include <config.h>

#include "epan/conversation.h"

#include <QHash>
#include <QStyledItemDelegate>

class QPainter;
struct conversation;

class RelatedPacketDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    RelatedPacketDelegate(QWidget *parent = 0);
    void clear();
    void setCurrentFrame(guint32 current_frame) { current_frame_ = current_frame; }
    void setConversation(struct conversation *conv);

public slots:
    void addRelatedFrame(int frame_num, ft_framenum_type_t framenum_type = FT_FRAMENUM_NONE);

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const;

private:
    QHash<int, ft_framenum_type_t> related_frames_;
    struct conversation *conv_;
    guint32 current_frame_;

    void drawArrow(QPainter *painter, const QPoint tail, const QPoint head, int head_size) const;
    void drawCheckMark(QPainter *painter, const QRect bbox) const;
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
