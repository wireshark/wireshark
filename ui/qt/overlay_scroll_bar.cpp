/* overlay_scroll_bar.cpp
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

#include "overlay_scroll_bar.h"

#include "color_utils.h"

#include <QMouseEvent>
#include <QPainter>
#include <QProxyStyle>
#include <QResizeEvent>
#include <QStyleOptionSlider>

// To do:
// - We could graph something useful (e.g. delay times) in packet_map_img_.
//   https://www.wireshark.org/lists/ethereal-dev/200011/msg00122.html
// - Properly handle transience.

// We want a normal scrollbar with space on either side on which we can draw
// and receive mouse events. Adding space using a stylesheet loses native
// styling on Windows. Overriding QProxyStyle::drawComplexControl (which is
// called by QScrollBar::paintEvent) results in odd behavior on Windows.
//
// The best solution so far seems to be to simply create a normal-sized child
// scrollbar, manually position it, and synchronize it with its parent. We
// can then alter the parent's mouse and paint behavior to our heart's
// content.

class OsbProxyStyle : public QProxyStyle
{
  public:
    // Disable transient behavior. Mainly for OS X but possibly applies to
    // other platforms. If we want to enable transience we'll have to
    // handle the following at a minimum:
    //
    // setProperty("visible") from QScrollbarStyleAnimation.
    // Other visibility changes.
    // HoverEnter & HoverLeave events from QAbstractScrollArea.
    // Size (and possibly opacity) changes while painting.
    //
    // Another approach would be to flip the child-parent relationship
    // and make the parent a normal scroll bar with a manually-placed
    // packet map child. This might make the packet list geometry a bit
    // wonky, however.

    virtual int styleHint(StyleHint hint, const QStyleOption *option = NULL, const QWidget *widget = NULL, QStyleHintReturn *returnData = NULL) const {
#if QT_VERSION >= QT_VERSION_CHECK(5, 3, 0)
        if (hint == SH_ScrollBar_Transient) return false;
#endif

        return QProxyStyle::styleHint(hint, option, widget, returnData);
    }
};

OverlayScrollBar::OverlayScrollBar(Qt::Orientation orientation, QWidget *parent) :
    QScrollBar(orientation, parent = 0),
    child_sb_(orientation, this),
    packet_map_img_(QImage()),
    packet_map_width_(0),
    marked_packet_width_(0),
    packet_count_(-1),
    start_pos_(-1),
    end_pos_(-1),
    selected_pos_(-1)
{
    setStyle(new OsbProxyStyle);

    child_sb_.raise();
    child_sb_.installEventFilter(this);
    child_sb_.setStyle(new OsbProxyStyle);

    // XXX Do we need to connect anything else?
    connect(this, SIGNAL(rangeChanged(int,int)), this, SLOT(setChildRange(int,int)));
    connect(this, SIGNAL(valueChanged(int)), &child_sb_, SLOT(setValue(int)));

    connect(&child_sb_, SIGNAL(valueChanged(int)), this, SLOT(setValue(int)));
}

QSize OverlayScrollBar::sizeHint() const
{
    return QSize(packet_map_width_ + child_sb_.sizeHint().width(),
                 QScrollBar::sizeHint().height());
}

void OverlayScrollBar::setNearOverlayImage(QImage &overlay_image, int packet_count, int start_pos, int end_pos, int selected_pos)
{
    int old_width = packet_map_img_.width();
    packet_map_img_ = overlay_image;
    packet_count_ = packet_count;
    start_pos_ = start_pos;
    end_pos_ = end_pos;
    selected_pos_ = selected_pos;

    if (old_width != packet_map_img_.width()) {
        qreal dp_ratio = 1.0;
    #if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
        dp_ratio = devicePixelRatio();
    #endif

        packet_map_width_ = packet_map_img_.width() / dp_ratio;

        updateGeometry();
    }
    update();
}

void OverlayScrollBar::setMarkedPacketImage(QImage &mp_image)
{
    qreal dp_ratio = 1.0;
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
    dp_ratio = devicePixelRatio();
#endif

    marked_packet_img_ = mp_image;
    marked_packet_width_ = mp_image.width() / dp_ratio;

    child_sb_.update();
}

QRect OverlayScrollBar::grooveRect()
{
    QStyleOptionSlider opt;

    initStyleOption(&opt);
    opt.rect = child_sb_.rect();

    return child_sb_.style()->subControlRect(QStyle::CC_ScrollBar, &opt, QStyle::SC_ScrollBarGroove, &child_sb_);
}

void OverlayScrollBar::resizeEvent(QResizeEvent *event)
{
    QScrollBar::resizeEvent(event);

    child_sb_.move(packet_map_width_, 0);
    child_sb_.resize(child_sb_.sizeHint().width(), height());
}

void OverlayScrollBar::paintEvent(QPaintEvent *event)
{
    qreal dp_ratio = 1.0;
    QSize pm_size(packet_map_width_, geometry().height());
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
    dp_ratio = devicePixelRatio();
    pm_size *= dp_ratio;
#endif

    QPainter painter(this);

    painter.fillRect(event->rect(), palette().base());

    if (!packet_map_img_.isNull()) {
        QImage packet_map(pm_size, QImage::Format_ARGB32_Premultiplied);
        packet_map.fill(Qt::transparent);

        // Draw the image supplied by the packet list.
        QPainter pm_painter(&packet_map);
        pm_painter.setPen(Qt::NoPen);

        QRect near_dest(0, 0, pm_size.width(), pm_size.height());
        pm_painter.drawImage(near_dest, packet_map_img_.scaled(near_dest.size(), Qt::IgnoreAspectRatio, Qt::SmoothTransformation));

        // Selected packet indicator
        if (selected_pos_ >= 0 && selected_pos_ < packet_map_img_.height()) {
            pm_painter.save();
            int no_pos = near_dest.height() * selected_pos_ / packet_map_img_.height();
            pm_painter.setBrush(palette().highlight().color());
            pm_painter.drawRect(0, no_pos, pm_size.width(), dp_ratio);
            pm_painter.restore();
        }

        // Borders
        pm_painter.save();
        QColor border_color(ColorUtils::alphaBlend(palette().text(), palette().window(), 0.25));
        pm_painter.setPen(border_color);
        pm_painter.drawLine(near_dest.topLeft(), near_dest.bottomLeft());
        pm_painter.drawLine(near_dest.topRight(), near_dest.bottomRight());
        pm_painter.drawLine(near_dest.bottomLeft(), near_dest.bottomRight());
        pm_painter.restore();

        // Draw the map.
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
        packet_map.setDevicePixelRatio(dp_ratio);
#endif
        painter.drawImage(0, 0, packet_map);
    }
}

bool OverlayScrollBar::eventFilter(QObject *watched, QEvent *event)
{
    bool ret = false;
    if (watched == &child_sb_ && event->type() == QEvent::Paint) {
        // Paint the scrollbar first.
        child_sb_.event(event);
        ret = true;

        if (!marked_packet_img_.isNull()) {
            QRect groove_rect = grooveRect();
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
            qreal dp_ratio = 1.0;
            dp_ratio = devicePixelRatio();
            groove_rect.setTopLeft(groove_rect.topLeft() * dp_ratio);
            groove_rect.setSize(groove_rect.size() * dp_ratio);
#endif

            QImage marked_map(groove_rect.width(), groove_rect.height(), QImage::Format_ARGB32_Premultiplied);
            marked_map.fill(Qt::transparent);

            QPainter mm_painter(&marked_map);
            mm_painter.setPen(Qt::NoPen);

            QRect far_dest(0, 0, groove_rect.width(), groove_rect.height());
            mm_painter.drawImage(far_dest, marked_packet_img_.scaled(far_dest.size(), Qt::IgnoreAspectRatio, Qt::SmoothTransformation));

    #if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
            marked_map.setDevicePixelRatio(dp_ratio);
    #endif
            QPainter painter(&child_sb_);
            painter.drawImage(groove_rect.left(), groove_rect.top(), marked_map);
        }
    }

    return ret;
}

void OverlayScrollBar::mouseReleaseEvent(QMouseEvent *event)
{
    QRect pm_r(0, 0, packet_map_width_, height());

    if (pm_r.contains(event->pos()) && geometry().height() > 0 && packet_count_ > 0 && pageStep() > 0) {
        double map_ratio = double(end_pos_ - start_pos_) / geometry().height();
        int clicked_packet = (event->pos().y() * map_ratio) + start_pos_;
        double packet_to_sb_value = double(maximum() - minimum()) / packet_count_;
        int top_pad = pageStep() / 4; // Land near, but not at, the top.

        setValue((clicked_packet * packet_to_sb_value) + top_pad);
    }
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
