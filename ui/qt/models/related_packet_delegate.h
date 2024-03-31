/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
    void setCurrentFrame(uint32_t current_frame);
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
    uint32_t current_frame_;

    void drawArrow(QPainter *painter, const QPoint tail, const QPoint head, int head_size) const;
    void drawChevrons(QPainter *painter, const QPoint tail, const QPoint head, int head_size) const;
    void drawCheckMark(QPainter *painter, const QRect bbox) const;
};

#endif // RELATED_PACKET_DELEGATE_H
