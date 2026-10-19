/* color_utils.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

#include <QAbstractItemView>
#include <QApplication>
#include <QPainter>
#include <QPalette>
#include <QStyle>

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

QString ColorUtils::itemHoverStyleSheet(const QString &selector)
{
    // Read the application palette: ThemeManager installs it before
    // emitting themeChanged, while a widget's own palette may not have
    // been propagated yet when its restyle slot runs.
    const QPalette pal = QApplication::palette();
    const QColor hover_bg = ColorMath::selectionHoverFill(pal.color(QPalette::Base),
                                                          pal.color(QPalette::Highlight));
    const QColor hover_fg = ColorMath::readableText(pal.color(QPalette::Text), hover_bg);
    return QStringLiteral("%1:item:hover { background-color: %2; color: %3; }")
            .arg(selector, hover_bg.name(), hover_fg.name());
}

void ColorUtils::paintFlatCell(QPainter *painter, const QAbstractItemView *view,
                                const QStyleOptionViewItem &option, const QModelIndex &index,
                                const QColor &bg, const QColor &fg)
{
    painter->save();
    painter->fillRect(option.rect, bg);
    painter->restore();

    QStyleOptionViewItem cell_option = option;
    cell_option.features |= QStyleOptionViewItem::HasDisplay;
    cell_option.text = index.data(Qt::DisplayRole).toString();
    cell_option.icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
    QVariant alignment = index.data(Qt::TextAlignmentRole);
    if (alignment.isValid()) {
        cell_option.displayAlignment = Qt::Alignment(alignment.toInt());
    }
    cell_option.backgroundBrush = QBrush();
    cell_option.palette.setBrush(QPalette::Base, QBrush());
    cell_option.palette.setBrush(QPalette::Window, QBrush());
    cell_option.palette.setColor(QPalette::Text, fg);
    cell_option.palette.setColor(QPalette::WindowText, fg);
    cell_option.palette.setColor(QPalette::HighlightedText, fg);

    QStyle *style = view->style() ? view->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &cell_option, painter, view);
}

const QColor ColorUtils::warningBackground()
{
    return ThemeManager::instance()->color(ThemeManager::FilterDeprecated);
}

QColor ColorUtils::rowSeparatorColor(const QPalette &palette)
{
    const QColor base = palette.color(QPalette::Base);
    if (ColorMath::isDark(base)) {
        return ColorMath::mix(base, palette.color(QPalette::Text), 0.5);
    }
    return base;
}

const QColor ColorUtils::disabledForeground()
{
    return alphaBlend(QApplication::palette().windowText(), QApplication::palette().window(), 0.65);
}
