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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qt_ui_utils.h"

#include <epan/addr_resolv.h>
#include <epan/range.h>
#include <epan/to_str.h>
#include <epan/value_string.h>

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
    QString qt_string(glib_string);
    g_free(glib_string);
    return qt_string;
}

QByteArray gstring_free_to_qbytearray(GString *glib_gstring)
{
    QByteArray qt_ba(glib_gstring->str);
    g_string_free(glib_gstring, TRUE);
    return qt_ba;
}

const QString address_to_qstring(const _address *address)
{
    QString address_qstr = QString();
    if (address) {
        gchar *address_gchar_p = address_to_str(NULL, address);
        address_qstr = address_gchar_p;
        wmem_free(NULL, address_gchar_p);
    }
    return address_qstr;
}

const QString address_to_display_qstring(const _address *address)
{
    QString address_qstr = QString();
    if (address) {
        const gchar *address_gchar_p = address_to_display(NULL, address);
        address_qstr = address_gchar_p;
        wmem_free(NULL, (void *) address_gchar_p);
    }
    return address_qstr;
}

const QString val_to_qstring(const guint32 val, const value_string *vs, const char *fmt)
{
    QString val_qstr = QString();
    gchar* gchar_p = val_to_str_wmem(NULL, val, vs, fmt);
    val_qstr = gchar_p;
    wmem_free(NULL, gchar_p);

    return val_qstr;
}

const QString val_ext_to_qstring(const guint32 val, value_string_ext *vse, const char *fmt)
{
    QString val_qstr = QString();
    gchar* gchar_p = val_to_str_ext_wmem(NULL, val, vse, fmt);
    val_qstr = gchar_p;
    wmem_free(NULL, gchar_p);

    return val_qstr;
}

const QString range_to_qstring(const epan_range *range)
{
    QString range_qstr = QString();
    if (range) {
        const gchar *range_gchar_p = range_convert_range(NULL, range);
        range_qstr = range_gchar_p;
        wmem_free(NULL, (void *) range_gchar_p);
    }
    return range_qstr;
}

const QString bits_s_to_qstring(const double bits_s)
{
    return gchar_free_to_qstring(
                format_size(bits_s, format_size_unit_none|format_size_prefix_si));
}

const QString file_size_to_qstring(const gint64 size)
{
    return gchar_free_to_qstring(
                format_size(size, format_size_unit_bytes|format_size_prefix_si));
}

void smooth_font_size(QFont &font) {
    QFontDatabase fdb;
#if QT_VERSION < QT_VERSION_CHECK(4, 8, 0)
    QList<int> size_list = fdb.smoothSizes(font.family(), "");
#else
    QList<int> size_list = fdb.smoothSizes(font.family(), font.styleName());
#endif

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
