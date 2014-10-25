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


/*
 * Initialize a color with R, G, and B values, including any toolkit-dependent
 * work that needs to be done.
 */
gboolean
initialize_color(color_t *color, guint16 red, guint16 green, guint16 blue)
{
    QColor qc;

    // color_t uses 16-bit components to match Gtk+. Qt use 8.
    qc.setRgb(red>>8, green>>8, blue>>8);
    if (!qc.isValid())
        return FALSE;

    // Match what color_filters.c does.
    color->red = red;
    color->green = green;
    color->blue = blue;
    color->pixel = 0;
    return TRUE;
}

ColorUtils::ColorUtils(QObject *parent) :
    QObject(parent)
{
}

QColor ColorUtils::fromColorT (color_t *color) {
    if (!color) return QColor();
    return QColor(color->red >> 8, color->green >> 8, color->blue >> 8);
}

QColor ColorUtils::fromColorT(color_t color)
{
    return fromColorT(&color);
}

QRgb ColorUtils::alphaBlend(const QColor &color1, const QColor &color2, qreal alpha)
{
    alpha = qBound(0.0, alpha, 1.0);

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
