/* ws_mempbrk.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
