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

/* see bug 10798: there is a bug in the compiler the buildbots use for Mac OSX
   and SSE4.2, so we're not going to use SSE4.2 with Mac OSX right now, for
   older Mac OSX compilers.
 */
#ifdef __APPLE__
#if defined(__clang__) && (__clang_major__ >= 6)
/* allow HAVE_SSE4_2 to be used for clang 6.0+ case because we know it works */
#else
/* don't allow it otherwise, for Mac OSX */
#undef HAVE_SSE4_2
#endif
#endif

#include <glib.h>
#include "ws_symbol_export.h"
#include "ws_mempbrk.h"
#include "ws_mempbrk_int.h"

void
ws_mempbrk_compile(ws_mempbrk_pattern* pattern, const gchar *needles)
{
    const gchar *n = needles;
    while (*n) {
        pattern->patt[(int)*n] = 1;
        n++;
    }

#ifdef HAVE_SSE4_2
    ws_mempbrk_sse42_compile(pattern, needles);
#endif
}


const guint8 *
ws_mempbrk_portable_exec(const guint8* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, guchar *found_needle)
{
    const guint8 *haystack_end = haystack + haystacklen;

    while (haystack < haystack_end) {
        if (pattern->patt[*haystack]) {
            if (found_needle)
                *found_needle = *haystack;
            return haystack;
        }
        haystack++;
    }

    return NULL;
}


WS_DLL_PUBLIC const guint8 *
ws_mempbrk_exec(const guint8* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, guchar *found_needle)
{
#ifdef HAVE_SSE4_2
    if (haystacklen >= 16 && pattern->use_sse42)
        return ws_mempbrk_sse42_exec(haystack, haystacklen, pattern, found_needle);
#endif

    return ws_mempbrk_portable_exec(haystack, haystacklen, pattern, found_needle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
