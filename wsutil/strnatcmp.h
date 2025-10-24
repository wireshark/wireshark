/** @file
 *
 * Original code downloaded from: http://sourcefrog.net/projects/natsort/

  strnatcmp.c -- Perform 'natural order' comparisons of strings in C.
  Copyright (C) 2000, 2004 by Martin Pool <mbp sourcefrog net>

  SPDX-License-Identifier: Zlib
 */

#ifndef STRNATCMP_H
#define STRNATCMP_H

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* CUSTOMIZATION SECTION
 *
 * You can change this typedef, but must then also change the inline
 * functions in strnatcmp.c */
typedef char nat_char;

/**
 * @brief Performs ASCII natural-order string comparison (case-sensitive).
 *
 * Compares two strings using "natural" ordering, where numeric substrings are
 * compared based on their numeric value rather than lexicographic order.
 * For example, "file2" comes before "file10".
 *
 * @param a First string to compare.
 * @param b Second string to compare.
 * @return An integer similar to strcmp():
 *         - < 0 if a < b
 *         -   0 if a == b
 *         - > 0 if a > b
 */
WS_DLL_PUBLIC int ws_ascii_strnatcmp(nat_char const *a, nat_char const *b);

/**
 * @brief Performs ASCII natural-order string comparison (case-insensitive).
 *
 * Compares two strings using "natural" ordering, ignoring case differences.
 * Numeric substrings are compared by numeric value.
 *
 * @param a First string to compare.
 * @param b Second string to compare.
 * @return An integer similar to strcasecmp():
 *         - < 0 if a < b
 *         -   0 if a == b
 *         - > 0 if a > b
 */
WS_DLL_PUBLIC int ws_ascii_strnatcasecmp(nat_char const *a, nat_char const *b);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* STRNATCMP_H */
