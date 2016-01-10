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

#include <QPainter>
#include <QResizeEvent>
#include <QStyle>
#include <QStyleOptionSlider>

// To do:
// - The slider hole doesn't match up with the slider on OS X + Qt 5.3.2.
// - Instead of drawing the map over the scrollbar we could draw it to the
//   right of the scrollbar. Many text editors to this. It would let us
//   widen the map a bit, which would in turn let us add frame size or
//   timing information.

OverlayScrollBar::OverlayScrollBar(Qt::Orientation orientation, QWidget *parent) :
    QScrollBar(orientation, parent = 0),
    near_overlay_(QImage()),
    far_overlay_(QImage()),
    selected_pos_(-1)
{}

QSize OverlayScrollBar::sizeHint() const
{
    return QSize(QScrollBar::sizeHint().width() + (far_overlay_.width() * 2), QScrollBar::sizeHint().height());
}

void OverlayScrollBar::setNearOverlayImage(QImage &overlay_image, int selected_pos)
{
    near_overlay_ = overlay_image;
    selected_pos_ = selected_pos;
    update();
}

void OverlayScrollBar::setFarOverlayImage(QImage &overlay_image)
{
    int old_width = far_overlay_.width();
    far_overlay_ = overlay_image;
    if (old_width != far_overlay_.width()) {
        updateGeometry();
    }
    update();
}

QRect OverlayScrollBar::grooveRect()
{
    QStyleOptionSlider opt;
    initStyleOption(&opt);

    return style()->subControlRect(QStyle::CC_ScrollBar, &opt, QStyle::SC_ScrollBarGroove, this);
}

void OverlayScrollBar::paintEvent(QPaintEvent *event)
{
    QScrollBar::paintEvent(event);
    if (!near_overlay_.isNull()) {
        QRect groove_rect = grooveRect();
        QSize gr_size = groove_rect.size();
        qreal dp_ratio = 1.0;
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
        dp_ratio = devicePixelRatio();
        gr_size *= dp_ratio;
#endif
        QImage groove_overlay(gr_size, QImage::Format_ARGB32_Premultiplied);
        groove_overlay.fill(Qt::transparent);

        // Draw the image supplied by the packet list and apply a mask.
        QPainter go_painter(&groove_overlay);
        go_painter.setPen(Qt::NoPen);

        int fo_width = far_overlay_.width();
        QRect near_dest(fo_width, 0, gr_size.width() - (fo_width * 2), gr_size.height());
        go_painter.drawImage(near_dest, near_overlay_.scaled(near_dest.size(), Qt::IgnoreAspectRatio, Qt::SmoothTransformation));
        if (fo_width > 0) {
            QRect far_dest(0, 0, fo_width, gr_size.height());
            go_painter.drawImage(far_dest, far_overlay_);
            far_dest.moveLeft(gr_size.width() - fo_width);
            go_painter.drawImage(far_dest, far_overlay_.mirrored(true, false));
        }

        // Selected packet indicator
        if (selected_pos_ >= 0 && selected_pos_ < near_overlay_.height()) {
            int no_pos = near_dest.height() * selected_pos_ / near_overlay_.height();
            go_painter.save();
            go_painter.setBrush(palette().highlight().color());
            go_painter.drawRect(0, no_pos, gr_size.width(), dp_ratio);
            go_painter.restore();
        }

        // Outline
        QRect near_outline(near_dest);
        near_outline.adjust(0, 0, -1, -1);
        go_painter.save();
        QColor no_fg(palette().text().color());
        no_fg.setAlphaF(0.25);
        go_painter.setPen(no_fg);
        go_painter.drawRect(near_outline);
        go_painter.restore();

        // Punch a hole for the slider.
        QStyleOptionSlider opt;
        initStyleOption(&opt);

        QRect slider_rect = style()->subControlRect(QStyle::CC_ScrollBar, &opt, QStyle::SC_ScrollBarSlider, this);
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
        slider_rect.setHeight(slider_rect.height() * devicePixelRatio());
        slider_rect.setWidth(slider_rect.width() * devicePixelRatio());
        slider_rect.moveTop((slider_rect.top() - groove_rect.top()) * devicePixelRatio());
#else
        slider_rect.moveTop(slider_rect.top() - groove_rect.top());
#endif
        slider_rect.adjust(fo_width + 1, 1, -1 - fo_width, -1);

        go_painter.save();
        go_painter.setCompositionMode(QPainter::CompositionMode_DestinationIn);
        QColor slider_hole(Qt::white);
        slider_hole.setAlphaF(0.1);
        go_painter.setBrush(slider_hole);
        go_painter.drawRect(slider_rect);
        go_painter.restore();

        // Draw over the groove.
        QPainter painter(this);
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
        groove_overlay.setDevicePixelRatio(devicePixelRatio());
#endif
        painter.drawImage(groove_rect.topLeft(), groove_overlay);
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
