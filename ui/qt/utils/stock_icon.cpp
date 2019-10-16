/* stock_icon.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/stock_icon.h>

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

#include "wireshark_application.h"

#include <QFile>
#include <QFontMetrics>
#include <QMap>
#include <QPainter>
#include <QStyle>
#include <QStyleOption>

static const QString path_pfx_ = ":/stock_icons/";

// Map FreeDesktop icon names to Qt standard pixmaps.
static QMap<QString, QStyle::StandardPixmap> icon_name_to_standard_pixmap_;

StockIcon::StockIcon(const QString icon_name) :
    QIcon()
{
    if (icon_name_to_standard_pixmap_.isEmpty()) {
        fillIconNameMap();
    }

    // Does our theme contain this icon?
    // X11 only as per the QIcon documentation.
    if (hasThemeIcon(icon_name)) {
        QIcon theme_icon = fromTheme(icon_name);
        swap(theme_icon);
        return;
    }

    // Is this is an icon we've manually mapped to a standard pixmap below?
    if (icon_name_to_standard_pixmap_.contains(icon_name)) {
        QIcon standard_icon = wsApp->style()->standardIcon(icon_name_to_standard_pixmap_[icon_name]);
        swap(standard_icon);
        return;
    }

    // Is this one of our locally sourced, cage-free, organic icons?
    QStringList types = QStringList() << "8x8" << "14x14" << "16x16" << "24x14" << "24x24";
    QList<QIcon::Mode> icon_modes = QList<QIcon::Mode>()
            << QIcon::Disabled
            << QIcon::Active
            << QIcon::Selected;
    foreach (QString type, types) {
        // First, check for a template (mask) icon
        // Templates should be monochrome as described at
        // https://developer.apple.com/design/human-interface-guidelines/macos/icons-and-images/custom-icons/
        // Transparency is supported.
        QString icon_path_template = path_pfx_ + QString("%1/%2.template.png").arg(type).arg(icon_name);
        if (QFile::exists(icon_path_template)) {
            QIcon mask_icon = QIcon();
            mask_icon.addFile(icon_path_template);

            foreach(QSize sz, mask_icon.availableSizes()) {
                QPixmap mask_pm = mask_icon.pixmap(sz);
                QImage normal_img(sz, QImage::Format_ARGB32);
                QPainter painter(&normal_img);
                QBrush br(wsApp->palette().color(QPalette::Active, QPalette::WindowText));
                painter.fillRect(0, 0, sz.width(), sz.height(), br);
                painter.setCompositionMode(QPainter::CompositionMode_DestinationIn);
                painter.drawPixmap(0, 0, mask_pm);

                QPixmap normal_pm = QPixmap::fromImage(normal_img);
                addPixmap(normal_pm, QIcon::Normal, QIcon::On);
                addPixmap(normal_pm, QIcon::Normal, QIcon::Off);

                QStyleOption opt = {};
                opt.palette = wsApp->palette();
                foreach (QIcon::Mode icon_mode, icon_modes) {
                    QPixmap mode_pm = wsApp->style()->generatedIconPixmap(icon_mode, normal_pm, &opt);
                    addPixmap(mode_pm, icon_mode, QIcon::On);
                    addPixmap(mode_pm, icon_mode, QIcon::Off);
                }
            }
            continue;
        }

        // Regular full-color icons
        QString icon_path = path_pfx_ + QString("%1/%2.png").arg(type).arg(icon_name);
        if (QFile::exists(icon_path)) {
            addFile(icon_path);
        }

        // Along with each name check for "<name>.active" and
        // "<name>.selected" for the Active and Selected modes, and
        // "<name>.on" to use for the on (checked) state.
        // XXX Allow more (or all) combinations.
        QString icon_path_active = path_pfx_ + QString("%1/%2.active.png").arg(type).arg(icon_name);
        if (QFile::exists(icon_path_active)) {
            addFile(icon_path_active, QSize(), QIcon::Active, QIcon::On);
        }

        QString icon_path_selected = path_pfx_ + QString("%1/%2.selected.png").arg(type).arg(icon_name);
        if (QFile::exists(icon_path_selected)) {
            addFile(icon_path_selected, QSize(), QIcon::Selected, QIcon::On);
        }

        QString icon_path_on = path_pfx_ + QString("%1/%2.on.png").arg(type).arg(icon_name);
        if (QFile::exists(icon_path_on)) {
            addFile(icon_path_on, QSize(), QIcon::Normal, QIcon::On);
        }
    }
}

// Create a square icon filled with the specified color.
QIcon StockIcon::colorIcon(const QRgb bg_color, const QRgb fg_color, const QString glyph)
{
    QList<int> sizes = QList<int>() << 12 << 16 << 24 << 32 << 48;
    QIcon color_icon;

    foreach (int size, sizes) {
        QPixmap pm(size, size);
        QPainter painter(&pm);
        QRect border(0, 0, size - 1, size - 1);
        painter.setPen(fg_color);
        painter.setBrush(QColor(bg_color));
        painter.drawRect(border);

        if (!glyph.isEmpty()) {
            QFont font(wsApp->font());
            font.setPointSizeF(size / 2.0);
            painter.setFont(font);
            QRectF bounding = painter.boundingRect(pm.rect(), glyph, Qt::AlignHCenter | Qt::AlignVCenter);
            painter.drawText(bounding, glyph);
        }

        color_icon.addPixmap(pm);
    }
    return color_icon;
}

void StockIcon::fillIconNameMap()
{
    // Note that some of Qt's standard pixmaps are awful. We shouldn't add an
    // entry just because a match can be made.
    icon_name_to_standard_pixmap_["document-open"] = QStyle::SP_DirIcon;
    icon_name_to_standard_pixmap_["media-playback-pause"] = QStyle::SP_MediaPause;
    icon_name_to_standard_pixmap_["media-playback-start"] = QStyle::SP_MediaPlay;
    icon_name_to_standard_pixmap_["media-playback-stop"] = QStyle::SP_MediaStop;
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
