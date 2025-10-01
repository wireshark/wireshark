/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_MEMPBRK_H__
#define __WS_MEMPBRK_H__

#include <wireshark.h>

#ifdef HAVE_SSE4_2
#include <emmintrin.h>
#endif

/** The pattern object used for ws_mempbrk_exec().
 */
typedef struct {
    char patt[256];
#ifdef HAVE_SSE4_2
    bool use_sse42;
    __m128i mask;
#endif
} ws_mempbrk_pattern;

/**
 * @brief Compile the pattern for the needles to find using ws_mempbrk_exec().
 *
 * Initializes the internal representation of the search pattern using the
 * specified set of needle bytes. This enables efficient scanning of buffers
 * for any matching byte.
 *
 * @param pattern  Pointer to the pattern structure to initialize.
 * @param needles  Null-terminated string of bytes to search for.
 */
WS_DLL_PUBLIC void ws_mempbrk_compile(ws_mempbrk_pattern* pattern, const char *needles);


/**
 * @brief Scan for the needles specified by the compiled pattern.
 *
 * Searches the input buffer `haystack` for the first occurrence of any byte
 * listed in the precompiled `pattern`. If a match is found, the matched byte
 * is stored in `found_needle` (if non-NULL), and a pointer to its location
 * in `haystack` is returned. Returns NULL if no match is found.
 *
 * @param haystack       Pointer to the input buffer to search.
 * @param haystacklen    Length of the input buffer in bytes.
 * @param pattern        Precompiled pattern containing target bytes.
 * @param found_needle   Optional output pointer to receive the matched byte.
 * @return               Pointer to the first matching byte in `haystack`, or NULL if none found.
 */
WS_DLL_PUBLIC const uint8_t *ws_mempbrk_exec(const uint8_t* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, unsigned char *found_needle);


/**
 * @brief Scan for the needles specified by the compiled pattern, starting at the
 * end of the haystack and working backwards.
 *
 * Searches the input buffer `haystack` in reverse for the first occurrence of any byte
 * listed in the precompiled `pattern`. If a match is found, the matched byte is stored
 * in `found_needle` (if non-NULL), and a pointer to its location in `haystack` is returned.
 * Returns NULL if no match is found.
 *
 * @param haystack       Pointer to the input buffer to search.
 * @param haystacklen    Length of the input buffer in bytes.
 * @param pattern        Precompiled pattern containing target bytes.
 * @param found_needle   Optional output pointer to receive the matched byte.
 * @return               Pointer to the first matching byte in `haystack`, or NULL if none found.
 */
WS_DLL_PUBLIC const uint8_t *ws_memrpbrk_exec(const uint8_t* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, unsigned char *found_needle);

#endif /* __WS_MEMPBRK_H__ */
