/* ws_mempbrk_int.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_MEMPBRK_INT_H__
#define __WS_MEMPBRK_INT_H__

const guint8 *ws_mempbrk_portable_exec(const guint8* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, guchar *found_needle);

#ifdef HAVE_SSE4_2
void ws_mempbrk_sse42_compile(ws_mempbrk_pattern* pattern, const gchar *needles);
const char *ws_mempbrk_sse42_exec(const char* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, guchar *found_needle);
#endif

#endif /* __WS_MEMPBRK_INT_H__ */
