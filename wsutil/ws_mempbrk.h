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

/** The pattern object used for tvb_pbrk_pattern_guint8().
 */
typedef struct {
    gchar patt[256];
    gboolean use_sse42;
    void *mask;
} tvb_pbrk_pattern;

/** The value to use when initializing a tvb_pbrk_pattern variable.
 * For example:
 *    static tvb_pbrk_pattern pbrk_mypattern = INIT_PBRK_PATTERN;
 */
#define INIT_PBRK_PATTERN { { 0 }, FALSE, NULL }

/** Compile the pattern for the needles to find using tvb_pbrk_pattern_guint8().
 */
WS_DLL_PUBLIC void tvb_pbrk_compile(tvb_pbrk_pattern* pattern, const gchar *needles);

WS_DLL_PUBLIC const guint8 *tvb_pbrk_exec(const guint8* haystack, size_t haystacklen, const tvb_pbrk_pattern* pattern, guchar *found_needle);

void ws_mempbrk_sse42_compile(tvb_pbrk_pattern* pattern, const gchar *needles);
const char *ws_mempbrk_sse42_exec(const char* haystack, size_t haystacklen, const tvb_pbrk_pattern* pattern, guchar *found_needle);

const guint8 *ws_mempbrk_exec(const guint8* haystack, size_t haystacklen, const tvb_pbrk_pattern* pattern, guchar *found_needle);


#endif /* __WS_MEMPBRK_H__ */
