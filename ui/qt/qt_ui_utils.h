/* qt_gui_utils.h
 * Declarations of GTK+-specific UI utility routines
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

#ifndef __QT_UI_UTILS_H__
#define __QT_UI_UTILS_H__

// xxx - copied from ui/gtk/gui_utils.h

/** @file
 *  Utility functions for working with the Wireshark and GLib APIs.
 */

#include <config.h>

#include <glib.h>

#include <QString>

class QFont;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// These are defined elsewhere in ../gtk/
#define RECENT_KEY_CAPTURE_FILE   "recent.capture_file"
#define RECENT_KEY_REMOTE_HOST "recent.remote_host"

struct _address;
struct epan_range;

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** Create a glib-compatible copy of a QString.
 *
 * @param q_string A QString.
 *
 * @return A copy of the QString. UTF-8 allocated with g_malloc().
 */
gchar *qstring_strdup(QString q_string);

/** Transfer ownership of a GLib character string to a newly constructed QString
 *
 * @param glib_string A string allocated with g_malloc() or NULL. Will be
 * freed.
 *
 * @return A QString instance created from the input string.
 */
QString gchar_free_to_qstring(gchar *glib_string);

/** Transfer ownership of a GLib character string to a newly constructed QByteArray
 *
 * @param glib_string A string allocated with g_malloc() or NULL. Will be
 * freed.
 *
 * @return A QByteArray instance created from the input string.
 */
QByteArray gstring_free_to_qbytearray(GString *glib_gstring);

/** Convert an address to a QString using address_to_str().
 *
 * @param address A pointer to an address.
 *
 * @return A QString representation of the address. May be the null string (QString())
 */
const QString address_to_qstring(const struct _address *address);

/** Convert an address to a QString using address_to_display().
 *
 * @param address A pointer to an address.
 *
 * @return A QString representation of the address. May be the null string (QString())
 */
const QString address_to_display_qstring(const struct _address *address);

/** Convert a value_string to a QString using val_to_str_wmem().
 *
 * @param val The value to convert to string.
 * @param vs value_string array.
 * @param fmt Formatting for value not in array.
 *
 * @return A QString representation of the value_string.
 */
const QString val_to_qstring(const guint32 val, const struct _value_string *vs, const char *fmt)
G_GNUC_PRINTF(3, 0);

/** Convert a value_string_ext to a QString using val_to_str_ext_wmem().
 *
 * @param val The value to convert to string.
 * @param vse value_string_ext array.
 * @param fmt Formatting for value not in array.
 *
 * @return A QString representation of the value_string_ext.
 */
const QString val_ext_to_qstring(const guint32 val, struct _value_string_ext *vse, const char *fmt)
G_GNUC_PRINTF(3, 0);

/** Convert a range to a QString using range_convert_range().
 *
 * @param range A pointer to an range struct.
 *
 * @return A QString representation of the address. May be the null string (QString())
 */
const QString range_to_qstring(const struct epan_range *range);

/** Convert a bits per second value to a human-readable QString using format_size().
 *
 * @param bits_s The value to convert to string.
 *
 * @return A QString representation of the data rate in SI units.
 */
const QString bits_s_to_qstring(const double bits_s);

/** Convert a file size value to a human-readable QString using format_size().
 *
 * @param size The value to convert to string.
 *
 * @return A QString representation of the file size in SI units.
 */
const QString file_size_to_qstring(const gint64 size);

/**
 * Round the current size of a font up to its next "smooth" size.
 * If a smooth size can't be found the font is left unchanged.
 *
 * @param font The font to smooth.
 */
void smooth_font_size(QFont &font);

#endif /* __QT_UI_UTILS__H__ */

// XXX Add a routine to fetch the HWND corresponding to a widget using QPlatformIntegration

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
