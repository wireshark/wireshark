/* ws_mempbrk_int.h
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

#ifndef __WS_MEMPBRK_INT_H__
#define __WS_MEMPBRK_INT_H__

const guint8 *ws_mempbrk_portable_exec(const guint8* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, guchar *found_needle);

#ifdef HAVE_SSE4_2
void ws_mempbrk_sse42_compile(ws_mempbrk_pattern* pattern, const gchar *needles);
const char *ws_mempbrk_sse42_exec(const char* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, guchar *found_needle);
#endif

#endif /* __WS_MEMPBRK_INT_H__ */
