/* related_packet_delegate.cpp
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

#include "related_packet_delegate.h"
#include "packet_list_record.h"

#include <QPainter>
#include <QApplication>

void RelatedPacketDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const
{
    int en_w = option.fontMetrics.height() / 2;

    QStyleOptionViewItemV4 optv4 = option;
    QStyledItemDelegate::initStyleOption(&optv4, index);

    optv4.features |= QStyleOptionViewItemV4::HasDecoration;
    optv4.decorationSize.setHeight(1);
    optv4.decorationSize.setWidth(en_w);
    QStyledItemDelegate::paint(painter, optv4, index);

    frame_data *fd;
    PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
    if (!record || (fd = record->getFdata()) == NULL) {
        return;
    }

    painter->save();

    if (QApplication::style()->objectName().contains("vista")) {
        // QWindowsVistaStyle::drawControl does this internally. Unfortunately there
        // doesn't appear to be a more general way to do this.
        optv4.palette.setColor(QPalette::All, QPalette::HighlightedText, optv4.palette.color(QPalette::Active, QPalette::Text));
    }

    QPalette::ColorGroup cg = optv4.state & QStyle::State_Enabled
                              ? QPalette::Normal : QPalette::Disabled;
    QColor fg;
    if (cg == QPalette::Normal && !(optv4.state & QStyle::State_Active))
        cg = QPalette::Inactive;
    if (optv4.state & QStyle::State_Selected) {
        fg = optv4.palette.color(cg, QPalette::HighlightedText);
    } else {
        fg = optv4.palette.color(cg, QPalette::Text);
    }
    qreal alpha = 0.20; // Arbitrary. Should arguably be a preference.

    // We draw in the same place more than once so we first draw on a
    // QImage at 100% opacity then draw that on our packet list item.
    QImage overlay = QImage(en_w * 2, optv4.rect.height(), QImage::Format_ARGB32_Premultiplied);
    QPainter op(&overlay);

    overlay.fill(Qt::transparent);
    op.setPen(fg);
    op.translate(en_w + 0.5, 0.5);
    op.setRenderHint(QPainter::Antialiasing, true);

    // The current decorations are based on what looked good and were easy
    // to code. W might want to improve them by drawing small dots or tick
    // marks for frames in the same conversation XOR draw a gap for unrelated
    // frames.
    if (first_frame_ > 0 && last_frame_ > 0 && first_frame_ != last_frame_) {
        int height = optv4.rect.height();
        if ((int) fd->num == first_frame_) {
            op.drawLine(0, height / 2, 0, height);
            op.drawLine(1, height / 2, en_w, height / 2);
        } else if ((int) fd->num > first_frame_ && (int) fd->num < last_frame_) {
            op.drawLine(0, 0, 0, height);
        } else if ((int) fd->num == last_frame_) {
            op.drawLine(0, 0, 0, height / 2);
            op.drawLine(1, height / 2, en_w, height / 2);
        }
    }
    if (related_frames_.contains(fd->num)) {
        op.setBrush(fg);
        op.drawEllipse(QPointF(0.0, optv4.rect.height() / 2), 2, 2);
    }

    painter->setOpacity(alpha);
    painter->drawImage(optv4.rect.x(), optv4.rect.y(), overlay);
    painter->restore();
}

QSize RelatedPacketDelegate::sizeHint(const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const {
    return QSize(option.fontMetrics.height() + QStyledItemDelegate::sizeHint(option, index).width(),
                 QStyledItemDelegate::sizeHint(option, index).height());
}

void RelatedPacketDelegate::clear()
{
    related_frames_.clear();
    first_frame_ = last_frame_ = -1;
}

void RelatedPacketDelegate::addRelatedFrame(int frame_num)
{
    related_frames_ << frame_num;
}

void RelatedPacketDelegate::setConversationSpan(int first_frame, int last_frame)
{
    first_frame_ = first_frame;
    last_frame_ = last_frame;
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
