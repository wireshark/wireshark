/* ws_mempbrk.c
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
#include "ws_symbol_export.h"
#ifdef HAVE_SSE4_2
#include "ws_cpuid.h"
#endif
#include "ws_mempbrk.h"

const guint8 *
_ws_mempbrk(const guint8* haystack, size_t haystacklen, const guint8 *needles)
{
	gchar         tmp[256] = { 0 };
	const guint8 *haystack_end;

	while (*needles)
		tmp[*needles++] = 1;

	haystack_end = haystack + haystacklen;
	while (haystack < haystack_end) {
		if (tmp[*haystack])
			return haystack;
		haystack++;
	}

	return NULL;
}

WS_DLL_PUBLIC const guint8 *
ws_mempbrk(const guint8* haystack, size_t haystacklen, const guint8 *needles)
{
#ifdef HAVE_SSE4_2
	static int have_sse42 = -1;
#endif
	if (*needles == 0)
		return NULL;

#ifdef HAVE_SSE4_2
	if G_UNLIKELY(have_sse42 < 0)
		have_sse42 = ws_cpuid_sse42();

	if (haystacklen >= 16 && have_sse42)
		return _ws_mempbrk_sse42(haystack, haystacklen, needles);
#endif

	return _ws_mempbrk(haystack, haystacklen, needles);
}
