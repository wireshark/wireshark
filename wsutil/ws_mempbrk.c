/* ws_mempbrk.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include "ws_mempbrk.h"
#include "ws_mempbrk_int.h"

#include <string.h>

void
ws_mempbrk_compile(ws_mempbrk_pattern* pattern, const char *needles)
{
    const char *n = needles;
    memset(pattern->patt, 0, 256);
    while (*n) {
        pattern->patt[(int)*n] = 1;
        n++;
    }

#ifdef HAVE_SSE4_2
    ws_mempbrk_sse42_compile(pattern, needles);
#endif
}


const uint8_t *
ws_mempbrk_portable_exec(const uint8_t* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, unsigned char *found_needle)
{
    const uint8_t *haystack_end = haystack + haystacklen;

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


WS_DLL_PUBLIC const uint8_t *
ws_mempbrk_exec(const uint8_t* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, unsigned char *found_needle)
{
#ifdef HAVE_SSE4_2
    if (haystacklen >= 16 && pattern->use_sse42)
        return ws_mempbrk_sse42_exec(haystack, haystacklen, pattern, found_needle);
#endif

    return ws_mempbrk_portable_exec(haystack, haystacklen, pattern, found_needle);
}

WS_DLL_PUBLIC const uint8_t *
ws_memrpbrk_exec(const uint8_t* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, unsigned char *found_needle)
{
    const uint8_t *haystack_end = haystack + haystacklen;

    while (haystack_end > haystack) {
        if (pattern->patt[*(--haystack_end)]) {
            if (found_needle)
                *found_needle = *haystack_end;
            return haystack_end;
        }
    }

    return NULL;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
