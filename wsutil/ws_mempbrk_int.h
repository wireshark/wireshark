/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_MEMPBRK_INT_H__
#define __WS_MEMPBRK_INT_H__

/**
 * @brief Search for the first matching byte in a buffer using a precompiled pattern.
 *
 * Scans the input buffer `haystack` for the first occurrence of any byte listed
 * in the precompiled `pattern`. If a match is found, the corresponding needle byte
 * is written to `found_needle` (if non-NULL), and a pointer to the match location
 * in `haystack` is returned. If no match is found, returns NULL.
 *
 * @param haystack       Pointer to the input buffer to search.
 * @param haystacklen    Length of the input buffer in bytes.
 * @param pattern        Precompiled pattern containing target bytes.
 * @param found_needle   Optional output pointer to receive the matched byte.
 * @return               Pointer to the first matching byte in `haystack`, or NULL if none found.
 */
const uint8_t *ws_mempbrk_portable_exec(const uint8_t* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, unsigned char *found_needle);

#ifdef HAVE_SSE4_2

/**
 * @brief Compile a pattern for SSE4.2-accelerated mempbrk search.
 *
 * Prepares the internal representation of the search pattern using the
 * specified set of needle bytes. This enables optimized scanning via
 * SSE4.2 instructions.
 *
 * @param pattern  Pointer to the pattern structure to initialize.
 * @param needles  Null-terminated string of bytes to search for.
 */
void ws_mempbrk_sse42_compile(ws_mempbrk_pattern* pattern, const char *needles);

/**
 * @brief Search for the first matching byte in a buffer using SSE4.2 acceleration.
 *
 * Scans the input buffer `haystack` for the first occurrence of any byte listed
 * in the precompiled `pattern`, using SSE4.2 instructions for optimized performance.
 * If a match is found, the matched byte is stored in `found_needle` (if non-NULL),
 * and a pointer to its location in `haystack` is returned. Returns NULL if no match is found.
 *
 * @param haystack       Pointer to the input buffer to search.
 * @param haystacklen    Length of the input buffer in bytes.
 * @param pattern        Precompiled pattern containing target bytes.
 * @param found_needle   Optional output pointer to receive the matched byte.
 * @return               Pointer to the first matching byte in `haystack`, or NULL if none found.
 */
const char *ws_mempbrk_sse42_exec(const char* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, unsigned char *found_needle);
#endif

#endif /* __WS_MEMPBRK_INT_H__ */
