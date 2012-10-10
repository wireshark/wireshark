/* str_util.c
 * String utility routines
 *
 * $Id$
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

#include "config.h"

#include <glib.h>
#include "str_util.h"

#include <ctype.h>

/* Convert all ASCII letters to lower case, in place. */
gchar *
ascii_strdown_inplace(gchar *str)
{
	gchar *s;

	for (s = str; *s; s++)
		*s = g_ascii_tolower (*s);

        return (str);
}

/* Convert all ASCII letters to upper case, in place. */
gchar *
ascii_strup_inplace(gchar *str)
{
	gchar *s;

	for (s = str; *s; s++)
		*s = g_ascii_toupper (*s);

        return (str);
}

/* Check if an entire string is printable. */
gboolean
isprint_string(guchar *str)
{
	guint pos;

	/* Loop until we reach the end of the string (a null) */
	for(pos = 0; str[pos] != '\0'; pos++){
		if(!isprint(str[pos])){
			/* The string contains a non-printable character */
			return FALSE;
		}
	}

	/* The string contains only printable characters */
	return TRUE;
}

/* Check if an entire string is digits. */
gboolean
isdigit_string(guchar *str)
{
	guint pos;

	/* Loop until we reach the end of the string (a null) */
	for(pos = 0; str[pos] != '\0'; pos++){
		if(!isdigit(str[pos])){
			/* The string contains a non-digit character */
			return FALSE;
		}
	}

	/* The string contains only digits */
	return TRUE;
}

#define FORMAT_SIZE_UNIT_MASK 0x00ff
#define FORMAT_SIZE_PFX_MASK 0xff00

/* Given a size, return its value in a human-readable format */
gchar *format_size(gint64 size, format_size_flags_e flags) {
	GString *human_str = g_string_new("");
	int power = 1000;
	int pfx_off = 0;
	gboolean is_small = FALSE;
	const gchar *prefix[] = {"T", "G", "M", "k", "Ti", "Gi", "Mi", "Ki"};
	gchar *ret_val;

	if ((flags & FORMAT_SIZE_PFX_MASK) == format_size_prefix_iec) {
		pfx_off = 4;
		power = 1024;
	}

        if (size / power / power / power / power >= 10) {
		g_string_printf(human_str, "%" G_GINT64_MODIFIER "d %s", size / power / power / power / power, prefix[pfx_off]);
	} else if (size / power / power / power >= 10) {
		g_string_printf(human_str, "%" G_GINT64_MODIFIER "d %s", size / power / power / power, prefix[pfx_off+1]);
	} else if (size / power / power >= 10) {
		g_string_printf(human_str, "%" G_GINT64_MODIFIER "d %s", size / power / power, prefix[pfx_off+2]);
	} else if (size / power >= 10) {
		g_string_printf(human_str, "%" G_GINT64_MODIFIER "d %s", size / power, prefix[pfx_off+3]);
        } else {
		g_string_printf(human_str, "%" G_GINT64_MODIFIER "d ", size);
		is_small = TRUE;
	}

	switch (flags & FORMAT_SIZE_UNIT_MASK) {
		case format_size_unit_none:
			break;
		case format_size_unit_bytes:
			g_string_append(human_str, is_small ? "bytes" : "B");
			break;
		case format_size_unit_bits:
			g_string_append(human_str, is_small ? "bits" : "b");
			break;
		case format_size_unit_bits_s:
			g_string_append(human_str, is_small ? "bits/s" : "bps");
			break;
		default:
			g_assert_not_reached();
	}

	ret_val = human_str->str;
	g_string_free(human_str, FALSE);
	return ret_val;
}
