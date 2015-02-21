/* ws_mempbrk.h
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

#ifndef __WS_MEMPBRK_H__
#define __WS_MEMPBRK_H__

#include "ws_symbol_export.h"

#ifdef HAVE_SSE4_2
#include <emmintrin.h>
#endif

/** The pattern object used for ws_mempbrk_exec().
 */
typedef struct {
    gchar patt[256];
#ifdef HAVE_SSE4_2
    gboolean use_sse42;
    __m128i mask;
#endif
} ws_mempbrk_pattern;

/** Compile the pattern for the needles to find using ws_mempbrk_exec().
 */
WS_DLL_PUBLIC void ws_mempbrk_compile(ws_mempbrk_pattern* pattern, const gchar *needles);

/** Scan for the needles specified by the compiled pattern.
 */
WS_DLL_PUBLIC const guint8 *ws_mempbrk_exec(const guint8* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, guchar *found_needle);

#endif /* __WS_MEMPBRK_H__ */
