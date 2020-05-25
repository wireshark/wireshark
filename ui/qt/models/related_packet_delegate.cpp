/* related_packet_delegate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/related_packet_delegate.h>
#include "packet_list_record.h"

#include <ui/qt/utils/color_utils.h>

#include <ui/qt/main_window.h>
#include <ui/qt/wireshark_application.h>

#include <QApplication>
#include <QPainter>

// To do:
// - Add other frame types and symbols. If `tshark -G fields | grep FT_FRAMENUM`
//   is any indication, we should add "reassembly" and "reassembly error"
//   fields.
// - Don't add *too* many frame types and symbols. The goal is context, not
//   clutter.
// - Add tooltips. It looks like this needs to be done in ::helpEvent
//   or PacketListModel::data.
// - Add "Go -> Next Related" and "Go -> Previous Related"?
// - Apply as filter?

RelatedPacketDelegate::RelatedPacketDelegate(QWidget *parent) :
    QStyledItemDelegate(parent),
    conv_(NULL),
    current_frame_(0)
{
    clear();
}

void RelatedPacketDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const
{

    /* This prevents the drawing of related objects, if multiple lines are being selected */
    if (wsApp && wsApp->mainWindow())
    {
        MainWindow * mw = qobject_cast<MainWindow *>(wsApp->mainWindow());
        if (mw && mw->hasSelection())
        {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }
    }

    QStyleOptionViewItem option_vi = option;
    QStyledItemDelegate::initStyleOption(&option_vi, index);
    int em_w = option_vi.fontMetrics.height();
    int en_w = (em_w + 1) / 2;
    int line_w = (option_vi.fontMetrics.lineWidth());

    option_vi.features |= QStyleOptionViewItem::HasDecoration;
    option_vi.decorationSize.setHeight(1);
    option_vi.decorationSize.setWidth(em_w);
    QStyledItemDelegate::paint(painter, option_vi, index);

    guint32 setup_frame = 0, last_frame = 0;
    if (conv_) {
        setup_frame = (int) conv_->setup_frame;
        last_frame = (int) conv_->last_frame;
    }

    const frame_data *fd;
    PacketListRecord *record = static_cast<PacketListRecord*>(index.internalPointer());
    if (!record || (fd = record->frameData()) == NULL) {
        return;
    }

    painter->save();

    if (QApplication::style()->objectName().contains("vista")) {
        // QWindowsVistaStyle::drawControl does this internally. Unfortunately there
        // doesn't appear to be a more general way to do this.
        option_vi.palette.setColor(QPalette::All, QPalette::HighlightedText, option_vi.palette.color(QPalette::Active, QPalette::Text));
    }

    QPalette::ColorGroup cg = option_vi.state & QStyle::State_Enabled
                              ? QPalette::Normal : QPalette::Disabled;
    QColor fg;
    if (cg == QPalette::Normal && !(option_vi.state & QStyle::State_Active))
        cg = QPalette::Inactive;
#if !defined(Q_OS_WIN)
    if (option_vi.state & QStyle::State_MouseOver) {
        fg = QApplication::palette().text().color();
    } else
#endif
    if (option_vi.state & QStyle::State_Selected) {
        fg = option_vi.palette.color(cg, QPalette::HighlightedText);
    } else {
        fg = option_vi.palette.color(cg, QPalette::Text);
    }

    fg = ColorUtils::alphaBlend(fg, option_vi.palette.color(cg, QPalette::Base), 0.5);
    QPen line_pen(fg);
    line_pen.setWidth(line_w);
    line_pen.setJoinStyle(Qt::RoundJoin);

    painter->setPen(line_pen);
    painter->translate(option_vi.rect.x(), option_vi.rect.y());
    painter->translate(en_w + 0.5, 0.5);
    painter->setRenderHint(QPainter::Antialiasing, true);
    int height = option_vi.rect.height();

    // Uncomment to make the boundary visible.
//    painter->save();
//    painter->setPen(Qt::darkRed);
//    painter->drawRect(QRectF(0.5, 0.5, en_w - 1, height - 1));
//    painter->restore();

    // The current decorations are based on what looked good and were easy
    // to code.

    // It might be useful to have a JACKPOT_MODE define that shows each
    // decoration in sequence in order to make it easier to create
    // screenshots for the User's Guide.

    // Vertical line. Lower and upper half for the start and end of the
    // conversation respectively, solid for conversation member, dashed
    // for other packets in the start-end range.
    if (setup_frame > 0 && last_frame > 0 && setup_frame != last_frame) {
        if (fd->num == setup_frame) {
            QPoint start_line[] = {
                QPoint(en_w - 1, height / 2),
                QPoint(0, height / 2),
                QPoint(0, height)
            };
            painter->drawPolyline(start_line, 3);
        } else if (fd->num > setup_frame && fd->num < last_frame) {
            painter->save();
            if (conv_->conv_index != record->conversation()) {
                QPen other_pen(line_pen);
                other_pen.setStyle(Qt::DashLine);
                painter->setPen(other_pen);
            }
            painter->drawLine(0, 0, 0, height);
            painter->restore();
        } else if (fd->num == last_frame) {
            QPoint end_line[] = {
                QPoint(en_w - 1, height / 2),
                QPoint(0, height / 2),
                QPoint(0, 0)
            };
            painter->drawPolyline(end_line, 3);
        }
    }

    // Related packet indicator. Rightward arrow for requests, leftward
    // arrow for responses, circle for others.
    // XXX These are comically oversized when we have multi-line rows.
    if (related_frames_.contains(fd->num)) {
        painter->setBrush(fg);
        switch (related_frames_[fd->num]) {
        // Request and response arrows are moved forward one pixel in order to
        // maximize white space between the heads and the conversation line.
        case FT_FRAMENUM_REQUEST:
        {
            int hh = height / 2;
            QPoint tail(2 - en_w, hh);
            QPoint head(en_w, hh);
            drawArrow(painter, tail, head, hh / 2);
            break;
        }
        case FT_FRAMENUM_RESPONSE:
        {
            int hh = height / 2;
            QPoint tail(en_w - 1, hh);
            QPoint head(1 - en_w, hh);
            drawArrow(painter, tail, head, hh / 2);
            break;
        }
        case FT_FRAMENUM_ACK:
        {
            QRect bbox (2 - en_w, height / 3, em_w - 2, height / 2);
            drawCheckMark(painter, bbox);
            break;
        }
        case FT_FRAMENUM_DUP_ACK:
        {
            QRect bbox (2 - en_w, (height / 3) - (line_w * 2), em_w - 2, height / 2);
            drawCheckMark(painter, bbox);
            bbox.moveTop(bbox.top() + (line_w * 3));
            drawCheckMark(painter, bbox);
            break;
        }
        case FT_FRAMENUM_RETRANS_PREV:
        {
            int hh = height / 2;
            QPoint tail(2 - en_w, hh);
            QPoint head(en_w, hh);
            drawChevrons(painter, tail, head, hh / 2);
            break;
        }
        case FT_FRAMENUM_RETRANS_NEXT:
        {
            int hh = height / 2;
            QPoint tail(en_w - 1, hh);
            QPoint head(1 - en_w, hh);
            drawChevrons(painter, tail, head, hh / 2);
            break;
        }
        case FT_FRAMENUM_NONE:
        default:
            painter->drawEllipse(QPointF(0.0, option_vi.rect.height() / 2), 2, 2);
        }
    }

    painter->restore();
}

QSize RelatedPacketDelegate::sizeHint(const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
{
    /* This prevents the sizeHint for the delegate, if multiple lines are being selected */
    if (wsApp && wsApp->mainWindow())
    {
        MainWindow * mw = qobject_cast<MainWindow *>(wsApp->mainWindow());
        if (mw && mw->selectedRows().count() > 1)
            return QStyledItemDelegate::sizeHint(option, index);
    }

    return QSize(option.fontMetrics.height() + QStyledItemDelegate::sizeHint(option, index).width(),
                 QStyledItemDelegate::sizeHint(option, index).height());
}

void RelatedPacketDelegate::drawArrow(QPainter *painter, const QPoint tail, const QPoint head, int head_size) const
{
    int x_mul = head.x() > tail.x() ? -1 : 1;
    QPoint head_points[] = {
        head,
        QPoint(head.x() + (head_size * x_mul), head.y() + (head_size / 2)),
        QPoint(head.x() + (head_size * x_mul), head.y() - (head_size / 2)),
    };

    painter->drawLine(tail.x(), tail.y(), head.x() + (head_size * x_mul), head.y());
    painter->drawPolygon(head_points, 3);
}

void RelatedPacketDelegate::drawChevrons(QPainter *painter, const QPoint tail, const QPoint head, int head_size) const
{
    int x_mul = head.x() > tail.x() ? -1 : 1;
    QPoint head_points1[] = {
        head,
        QPoint(head.x() + (head_size * x_mul), head.y() + (head_size / 2)),
        QPoint(head.x() + (head_size * x_mul), head.y() - (head_size / 2)),
    };
    QPoint head2(head.x() + (head_size * x_mul), head.y());
    QPoint head_points2[] = {
        head2,
        QPoint(head2.x() + (head_size * x_mul), head2.y() + (head_size / 2)),
        QPoint(head2.x() + (head_size * x_mul), head2.y() - (head_size / 2)),
    };

    painter->drawPolygon(head_points1, 3);
    painter->drawPolygon(head_points2, 3);
}

void RelatedPacketDelegate::drawCheckMark(QPainter *painter, const QRect bbox) const
{
    QPoint cm_points[] = {
        QPoint(bbox.x(), bbox.y() + (bbox.height() / 2)),
        QPoint(bbox.x() + (bbox.width() / 4), bbox.y() + (bbox.height() * 3 / 4)),
        bbox.topRight()
    };
    painter->drawPolyline(cm_points, 3);
}

void RelatedPacketDelegate::clear()
{
    related_frames_.clear();
    current_frame_ = 0;
    conv_ = NULL;
}

void RelatedPacketDelegate::setCurrentFrame(guint32 current_frame)
 {
    current_frame_ = current_frame;
    foreach (ft_framenum_type_t framenum_type, related_frames_) {
        addRelatedFrame(-1, framenum_type); /* No need to check if this element belongs to the hash... */
    }
 }

void RelatedPacketDelegate::addRelatedFrame(int frame_num, ft_framenum_type_t framenum_type)
{
    if (frame_num != -1 && !related_frames_.contains(frame_num))
        related_frames_[frame_num] = framenum_type;

    // Last match wins. Last match might not make sense, however.
    if (current_frame_ > 0) {
        switch (framenum_type) {
        case FT_FRAMENUM_REQUEST:
            related_frames_[current_frame_] = FT_FRAMENUM_RESPONSE;
            break;
        case FT_FRAMENUM_RESPONSE:
            related_frames_[current_frame_] = FT_FRAMENUM_REQUEST;
            break;
        default:
            break;
        }
    }
}

void RelatedPacketDelegate::setConversation(conversation *conv)
{
    conv_ = conv;
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
