/* qt_ui_utils.cpp
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

#include <string.h>
#include <stdlib.h>

#include "qt_ui_utils.h"

#include <ui/recent.h>
#include <ui/ui_util.h>

#include <wsutil/str_util.h>

#include <QFontDatabase>

/* Make the format_size_flags_e enum usable in C++ */
format_size_flags_e operator|(format_size_flags_e lhs, format_size_flags_e rhs) {
    return (format_size_flags_e) ((int)lhs| (int)rhs);
}


/*
 * We might want to create our own "wsstring" class with convenience
 * methods for handling g_malloc()ed strings, GStrings, and a shortcut
 * to .toUtf8().constData().
 */

gchar *qstring_strdup(QString q_string) {
    return g_strdup(q_string.toUtf8().constData());
}

QString gchar_free_to_qstring(gchar *glib_string) {
    QString *qt_string = new QString(glib_string);
    g_free(glib_string);
    return *qt_string;
}

void smooth_font_size(QFont &font) {
    QFontDatabase fdb;
    QList<int> size_list = fdb.smoothSizes(font.family(), font.styleName());

    if (size_list.size() < 2) return;

    int last_size = size_list.takeFirst();
    foreach (int cur_size, size_list) {
        if (font.pointSize() > last_size && font.pointSize() <= cur_size) {
            font.setPointSize(cur_size);
            return;
        }
        last_size = cur_size;
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
