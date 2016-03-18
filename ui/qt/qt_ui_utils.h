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

class QAction;
class QFont;
class QRect;

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

/** Transfer ownership of a GLib character string to a newly constructed QString
 *
 * @param glib_string A string allocated with g_malloc() or NULL. Will be
 * freed.
 *
 * @return A QByteArray instance created from the input string.
 */
QByteArray gchar_free_to_qbytearray(gchar *glib_string);

/** Transfer ownership of a GLib character string to a newly constructed QByteArray
 *
 * @param glib_gstring A string allocated with g_malloc() or NULL. Will be
 * freed.
 *
 * @return A QByteArray instance created from the input string.
 */
QByteArray gstring_free_to_qbytearray(GString *glib_gstring);

/** Convert an integer to a formatted string representation.
 *
 * @param value The integer to format.
 * @param field_width Width of the output, not including any base prefix.
 *        Output will be zero-padded.
 * @param base Number base between 2 and 36 (limited by QString::arg).
 *
 * @return A QString representation of the integer
 */
const QString int_to_qstring(qint64 value, int field_width = 0, int base = 10);

/** Convert an address to a QString using address_to_str().
 *
 * @param address A pointer to an address.
 * @param enclose Enclose IPv6 addresses in square brackets.
 *
 * @return A QString representation of the address. May be the null string (QString())
 */
const QString address_to_qstring(const struct _address *address, bool enclose = false);

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

/** Convert a time_t value to a human-readable QString using QDateTime.
 *
 * @param ti_time The value to convert.
 *
 * @return A QString representation of the file size in SI units.
 */
const QString time_t_to_qstring(time_t ti_time);

/**
 * Round the current size of a font up to its next "smooth" size.
 * If a smooth size can't be found the font is left unchanged.
 *
 * @param font The font to smooth.
 */
void smooth_font_size(QFont &font);

/**
 * Compare the text of two QActions. Useful for passing to std::sort.
 *
 * @param a1 First action
 * @param a2 Second action
 */
bool qActionLessThan(const QAction *a1, const QAction *a2);

/**
 * Compare two QStrings, ignoring case. Useful for passing to std::sort.
 *
 * @param s1 First string
 * @param s2 Second string
 */
bool qStringCaseLessThan(const QString &s1, const QString &s2);

/**
 * Given the path to a file, open its containing folder in the desktop
 * shell. Highlight the file if possible.
 *
 * @param file_path Path to the file.
 */
void desktop_show_in_folder(const QString file_path);

/**
 * Test to see if a rect is visible on screen.
 *
 * @param rect The rect to test, typically a "recent.gui_geometry_*" setting.
 * @return true if the rect is completely enclosed by one of the display
 * screens, false otherwise.
 */
bool rect_on_screen(const QRect &rect);
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
