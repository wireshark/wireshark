/* stock_icon.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/utils/themes/themed_icon.h>

// Stock icons. Based on gtk/stock_icons.h

// Toolbar icon sizes:
// macOS freestanding: 32x32, 32x32@2x, segmented (inside a button): <= 19x19
// Windows: 16x16, 24x24, 32x32
// GNOME: 24x24 (default), 48x48

// References:
//
// https://specifications.freedesktop.org/icon-theme-spec/icon-theme-spec-latest.html
// https://specifications.freedesktop.org/icon-naming-spec/icon-naming-spec-latest.html
//
// https://mithatkonar.com/wiki/doku.php/qt/icons
//
// https://web.archive.org/web/20140829010224/https://developer.apple.com/library/mac/documentation/userexperience/conceptual/applehiguidelines/IconsImages/IconsImages.html
// https://developer.apple.com/design/human-interface-guidelines/macos/icons-and-images/image-size-and-resolution/
// https://developer.apple.com/design/human-interface-guidelines/macos/icons-and-images/app-icon/
// https://docs.microsoft.com/en-us/windows/win32/uxguide/vis-icons
// https://developer.gnome.org/hig/stable/icons-and-artwork.html.en
// https://docs.microsoft.com/en-us/visualstudio/designers/the-visual-studio-image-library

// To do:
// - 32x32, 48x48, 64x64, and unscaled (.svg) icons.
// - Indent find & go actions when those panes are open.
// - Replace or remove:
//   WIRESHARK_STOCK_CAPTURE_FILTER x-capture-filter
//   WIRESHARK_STOCK_DISPLAY_FILTER x-display-filter
//   GTK_STOCK_SELECT_COLOR x-coloring-rules
//   GTK_STOCK_PREFERENCES preferences-system
//   GTK_STOCK_HELP help-contents

#include <QApplication>
#include <QFile>
#include <QFontMetrics>
#include <QMap>
#include <QPainter>
#include <QPainterPath>
#include <QStyle>
#include <QStyleOption>


StockIcon::StockIcon(const char *icon_name) :
    QIcon()
{
    ThemedIcon themed_icon(icon_name);
    swap(themed_icon);
}

// Create a square icon filled with the specified color.
QIcon StockIcon::colorIcon(const QRgb bg_color, const QRgb fg_color, const QString glyph)
{
    return colorIcon(QColor(bg_color), fg_color, glyph);
}

QIcon StockIcon::colorIcon(const QColor bg_color, const QRgb fg_color, const QString glyph)
{
    QList<int> sizes = QList<int>() << 48 << 32 << 24 << 16 << 12;
    QIcon color_icon;

    foreach (int size, sizes) {
        QPixmap pm(size, size);
        QPainter painter(&pm);
        QRect border(0, 0, size - 1, size - 1);
        painter.setPen(fg_color);
        painter.setBrush(QColor(bg_color));
        painter.drawRect(border);

        if (!glyph.isEmpty()) {
            QFont font(qApp->font());
            font.setPointSizeF(size / 2.0);
            painter.setFont(font);
            QRectF bounding = painter.boundingRect(pm.rect(), glyph, Qt::AlignHCenter | Qt::AlignVCenter);
            painter.drawText(bounding, glyph);
        }

        color_icon.addPixmap(pm);
    }
    return color_icon;
}

// Create a triangle icon filled with the specified color.
QIcon StockIcon::colorIconTriangle(const QRgb bg_color, const QRgb fg_color)
{
    QList<int> sizes = QList<int>() << 48 << 32 << 24 << 16 << 12;
    QIcon color_icon;

    foreach (int size, sizes) {
        QPixmap pm(size, size);
        QPainter painter(&pm);
        QPainterPath triangle;
        pm.fill();
        painter.fillRect(0, 0, size-1, size-1, Qt::transparent);
        painter.setPen(fg_color);
        painter.setBrush(QColor(bg_color));
        triangle.moveTo(0, size-1);
        triangle.lineTo(size-1, size-1);
        triangle.lineTo((size-1)/2, 0);
        triangle.closeSubpath();
        painter.fillPath(triangle, QColor(bg_color));

        color_icon.addPixmap(pm);
    }
    return color_icon;
}

// Create a cross icon filled with the specified color.
QIcon StockIcon::colorIconCross(const QRgb bg_color, const QRgb fg_color)
{
    QList<int> sizes = QList<int>() << 48 << 32 << 24 << 16 << 12;
    QIcon color_icon;

    foreach (int size, sizes) {
        QPixmap pm(size, size);
        QPainter painter(&pm);
        QPainterPath cross;
        pm.fill();
        painter.fillRect(0, 0, size-1, size-1, Qt::transparent);
        painter.setPen(QPen(QBrush(bg_color), 3));
        painter.setBrush(QColor(fg_color));
        cross.moveTo(0, 0);
        cross.lineTo(size-1, size-1);
        cross.moveTo(0, size-1);
        cross.lineTo(size-1, 0);
        painter.drawPath(cross);

        color_icon.addPixmap(pm);
    }
    return color_icon;
}

// Create a circle icon filled with the specified color.
QIcon StockIcon::colorIconCircle(const QRgb bg_color, const QRgb fg_color)
{
    QList<int> sizes = QList<int>() << 48 << 32 << 24 << 16 << 12;
    QIcon color_icon;

    foreach (int size, sizes) {
        QPixmap pm(size, size);
        QPainter painter(&pm);
        QRect border(2, 2, size - 3, size - 3);
        pm.fill();
        painter.fillRect(0, 0, size-1, size-1, Qt::transparent);
        painter.setPen(QPen(QBrush(bg_color), 3));
        painter.setBrush(QColor(fg_color));
        painter.setBrush(QColor(bg_color));
        painter.drawEllipse(border);

        color_icon.addPixmap(pm);
    }
    return color_icon;
}
