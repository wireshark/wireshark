/* color_utils.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/tango_colors.h>
#include <ui/qt/utils/theme_manager.h>

#include <QApplication>
#include <QPalette>

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

QBrush ColorUtils::themeLinkBrush()
{
    return qApp->palette().link();
}

QString ColorUtils::themeLinkStyle()
{
    QString link_style;

    if (ThemeManager::isDark()) {
        link_style = QStringLiteral("<style>a:link { color: %1; }</style>")
                .arg(themeLinkBrush().color().name());
    }
    return link_style;
}

const QColor ColorUtils::hoverBackground()
{
    QPalette hover_palette = QApplication::palette();
#if defined(Q_OS_MAC)
    hover_palette.setCurrentColorGroup(QPalette::Active);
    return hover_palette.highlight().color();
#else
    return ColorUtils::alphaBlend(hover_palette.window(), hover_palette.highlight(), 0.5);
#endif
}

const QColor ColorUtils::warningBackground()
{
    if (ThemeManager::isDark()) {
        return QColor(tango_butter_6);
    }
    return QColor(tango_butter_2);
}

const QColor ColorUtils::disabledForeground()
{
    return alphaBlend(QApplication::palette().windowText(), QApplication::palette().window(), 0.65);
}
