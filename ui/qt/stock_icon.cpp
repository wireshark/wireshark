/* stock_icon.cpp
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

#include "stock_icon.h"

// Stock icons. Based on gtk/stock_icons.h

// Toolbar icon sizes:
// OS X freestanding: 32x32, 32x32@2x, segmented (inside a button): <= 19x19
// Windows: 16x16, 24x24, 32x32
// GNOME: 24x24 (default), 48x48

// References:
//
// http://standards.freedesktop.org/icon-theme-spec/icon-theme-spec-latest.html
// http://standards.freedesktop.org/icon-naming-spec/icon-naming-spec-latest.html
//
// http://mithatkonar.com/wiki/doku.php/qt/icons
//
// https://developer.apple.com/library/mac/documentation/userexperience/conceptual/applehiguidelines/IconsImages/IconsImages.html#//apple_ref/doc/uid/20000967-TPXREF102
// http://msdn.microsoft.com/en-us/library/windows/desktop/dn742485.aspx
// https://developer.gnome.org/hig-book/stable/icons-types.html.en
// http://msdn.microsoft.com/en-us/library/ms246582.aspx

// To do:
// - 32x32, 48x48, 64x64, and unscaled (.svg) icons
// - Indent find & go actions when those panes are open.
// - Replace or remove:
//   WIRESHARK_STOCK_CAPTURE_FILTER x-capture-filter
//   WIRESHARK_STOCK_DISPLAY_FILTER x-display-filter
//   GTK_STOCK_SELECT_COLOR x-coloring-rules
//   GTK_STOCK_PREFERENCES preferences-system
//   GTK_STOCK_HELP help-contents

#include "wireshark_application.h"

#include <QFile>
#include <QStyle>

QString path_pfx_ = ":/icons/toolbar/";

StockIcon::StockIcon(const char *icon_name) :
    QIcon()
{
    if (strcmp(icon_name, "document-open") == 0) {
        QIcon dir_icon = fromTheme(icon_name, wsApp->style()->standardIcon(QStyle::SP_DirIcon));
#if QT_VERSION >= QT_VERSION_CHECK(4, 8, 0)
        swap(dir_icon);
#endif
        return;
    }

    if (hasThemeIcon(icon_name)) {
        QIcon theme_icon = fromTheme(icon_name);
#if QT_VERSION >= QT_VERSION_CHECK(4, 8, 0)
        swap(theme_icon);
#endif
        return;
    } else {
        QStringList types = QStringList() << "16x16" << "24x24";
        foreach (QString type, types) {
            // Along with each name check for "<name>.on" to use for the on (checked) state.
            // XXX Add checks for each combination of QIcon::Mode + QIcon::State
            QString icon_path = path_pfx_ + QString("%1/%2.png").arg(type).arg(icon_name);
            QString icon_path_on = path_pfx_ + QString("%1/%2.on.png").arg(type).arg(icon_name);
            if (QFile::exists(icon_path)) {
                addFile(icon_path);
            }
            if (QFile::exists(icon_path_on)) {
                addFile(icon_path_on, QSize(), QIcon::Normal, QIcon::On);
            }
        }
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
