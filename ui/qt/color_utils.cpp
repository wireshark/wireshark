/* color_utils.cpp
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

#include "color_utils.h"

#include "tango_colors.h"

const QColor ColorUtils::expert_color_comment    = QColor ( 0xb7, 0xf7, 0x74 );        /* Green */
const QColor ColorUtils::expert_color_chat       = QColor ( 0x80, 0xb7, 0xf7 );        /* Light blue */
const QColor ColorUtils::expert_color_note       = QColor ( 0xa0, 0xff, 0xff );        /* Bright turquoise */
const QColor ColorUtils::expert_color_warn       = QColor ( 0xf7, 0xf2, 0x53 );        /* Yellow */
const QColor ColorUtils::expert_color_error      = QColor ( 0xff, 0x5c, 0x5c );        /* Pale red */
const QColor ColorUtils::expert_color_foreground = QColor ( 0x00, 0x00, 0x00 );        /* Black */
const QColor ColorUtils::hidden_proto_item       = QColor ( 0x44, 0x44, 0x44 );        /* Gray */

ColorUtils::ColorUtils(QObject *parent) :
    QObject(parent)
{
}

//
// A color_t has RGB values in [0,65535].
// Qt RGB colors have RGB values in [0,255].
//
// 65535/255 = 257 = 0x0101, so converting from [0,255] to
// [0,65535] involves just shifting the 8-bit value left 8 bits
// and ORing them together.
//
// Converting from [0,65535] to [0,255] without rounding involves
// just shifting the 16-bit value right 8 bits; I guess you could
// round them by adding 0x80 to the value before shifting.
//
QColor ColorUtils::fromColorT (const color_t *color) {
    if (!color) return QColor();
    // Convert [0,65535] values to [0,255] values
    return QColor(color->red >> 8, color->green >> 8, color->blue >> 8);
}

QColor ColorUtils::fromColorT(color_t color)
{
    return fromColorT(&color);
}

const color_t ColorUtils::toColorT(const QColor color)
{
    color_t colort;

    // Convert [0,255] values to [0,65535] values
    colort.red = (color.red() << 8) | color.red();
    colort.green = (color.green() << 8) | color.green();
    colort.blue = (color.blue() << 8) | color.blue();

    return colort;
}

QRgb ColorUtils::alphaBlend(const QColor &color1, const QColor &color2, qreal alpha)
{
    alpha = qBound(qreal(0.0), alpha, qreal(1.0));

    int r1 = color1.red() * alpha;
    int g1 = color1.green() * alpha;
    int b1 = color1.blue() * alpha;
    int r2 = color2.red() * (1 - alpha);
    int g2 = color2.green() * (1 - alpha);
    int b2 = color2.blue() * (1 - alpha);

    QColor alpha_color(r1 + r2, g1 + g2, b1 + b2);
    return alpha_color.rgb();
}

QRgb ColorUtils::alphaBlend(const QBrush &brush1, const QBrush &brush2, qreal alpha)
{
    return alphaBlend(brush1.color(), brush2.color(), alpha);
}

QList<QRgb> ColorUtils::graph_colors_;
const QList<QRgb> ColorUtils::graphColors()
{
    if (graph_colors_.isEmpty()) {
        // Available graph colors
        // XXX - Add custom
        graph_colors_ = QList<QRgb>()
                << tango_aluminium_6 // Bar outline (use black instead)?
                << tango_sky_blue_5
                << tango_butter_6
                << tango_chameleon_5
                << tango_scarlet_red_5
                << tango_plum_5
                << tango_orange_6
                << tango_aluminium_3
                << tango_sky_blue_3
                << tango_butter_3
                << tango_chameleon_3
                << tango_scarlet_red_3
                << tango_plum_3
                << tango_orange_3;
    }
    return graph_colors_;
}

QRgb ColorUtils::graphColor(int item)
{
    if (graph_colors_.isEmpty()) graphColors(); // Init list.
    return graph_colors_[item % graph_colors_.size()];
}

QList<QRgb> ColorUtils::sequence_colors_;
QRgb ColorUtils::sequenceColor(int item)
{
    if (sequence_colors_.isEmpty()) {
        // Available sequence colors. Copied from gtk/graph_analysis.c.
        // XXX - Add custom?
        sequence_colors_ = QList<QRgb>()
                << qRgb(144, 238, 144)
                << qRgb(255, 160, 123)
                << qRgb(255, 182, 193)
                << qRgb(250, 250, 210)
                << qRgb(255, 255, 52)
                << qRgb(103, 205, 170)
                << qRgb(224, 255, 255)
                << qRgb(176, 196, 222)
                << qRgb(135, 206, 254)
                << qRgb(211, 211, 211);
    }
    return sequence_colors_[item % sequence_colors_.size()];
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
