/* strtoi.c
 * Utilities to convert strings to integers
 *
 * Copyright 2016, Dario Lombardo
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

#include "strtoi.h"
#include <errno.h>

gboolean ws_strtoi64(const gchar* str, gint64* cint)
{
	gchar* endptr;
	gint64 val;

	errno = 0;
	val = g_ascii_strtoll(str, &endptr, 10);
	if ((val == 0 && endptr == str) || (*endptr != 0)) {
		*cint = 0;
		errno = EINVAL;
		return FALSE;
	}
	if ((val == G_MAXINT64 || val == G_MININT64) && errno == ERANGE) {
		*cint = 0;
		/* errno is already set */
		return FALSE;
	}
	*cint = val;
	return TRUE;
}

gboolean ws_strtou64(const gchar* str, guint64* cint)
{
	gchar* endptr;
	guint64 val;

	if (str[0] == '-' || str[0] == '+') {
		/*
		 * Unsigned numbers don't have a sign.
		 */
		errno = EINVAL;
		return FALSE;
	}
	errno = 0;
	val = g_ascii_strtoull(str, &endptr, 10);
	if ((val == 0 && endptr == str) || (*endptr != 0)) {
		*cint = 0;
		errno = EINVAL;
		return FALSE;
	}
	if (val == G_MAXUINT64 && errno == ERANGE) {
		*cint = 0;
		return FALSE;
	}
	*cint = val;
	return TRUE;
}

#define DEFINE_WS_STRTOI_BITS(bits) \
gboolean ws_strtoi##bits(const gchar* str, gint##bits* cint) \
{ \
	gint64 val; \
	if (!ws_strtoi64(str, &val)) { \
		return FALSE; \
	} \
	if (val < G_MININT##bits || val > G_MAXINT##bits) { \
		*cint = 0; \
		errno = ERANGE; \
		return FALSE; \
	} \
	*cint = (gint##bits)val; \
	return TRUE; \
}

DEFINE_WS_STRTOI_BITS(32);
DEFINE_WS_STRTOI_BITS(16);
DEFINE_WS_STRTOI_BITS(8);

#define DEFINE_WS_STRTOU_BITS(bits) \
int ws_strtou##bits(const gchar* str, guint##bits* cint) \
{ \
	guint64 val; \
	if (!ws_strtou64(str, &val)) { \
		return FALSE; \
	} \
	if (val > G_MAXUINT##bits) { \
		*cint = 0; \
		errno = ERANGE; \
		return FALSE; \
	} \
	*cint = (guint##bits)val; \
	return TRUE; \
}

DEFINE_WS_STRTOU_BITS(32);
DEFINE_WS_STRTOU_BITS(16);
DEFINE_WS_STRTOU_BITS(8);

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
