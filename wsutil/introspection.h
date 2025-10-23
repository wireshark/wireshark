/** @file
 * Copyright 2021, João Valverde <j@v6e.pt>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _INTROSPECTION_H_
#define _INTROSPECTION_H_

#include <stddef.h>
#include <ws_symbol_export.h>

/**
 * @struct ws_enum_t
 * @brief Represents a symbolic enumeration entry.
 *
 * Each entry maps a symbolic name to an integer value, typically used for
 * lookup tables, configuration constants, or protocol identifiers.
 */
typedef struct {
    const char *symbol; /**< The symbolic name of the enumeration entry. */
    int value;          /**< The corresponding integer value. */
} ws_enum_t;

/**
 * @brief Performs a binary search for a symbolic enumeration entry.
 *
 * Searches a sorted array of `ws_enum_t` entries for the given symbolic name.
 * The array must be sorted by the `symbol` field in ascending order for binary search to work.
 *
 * @param enums Pointer to the array of enumeration entries.
 * @param count Number of entries in the array.
 * @param needle The symbolic name to search for.
 * @return A pointer to the matching `ws_enum_t` entry, or NULL if not found.
 */
WS_DLL_PUBLIC
const ws_enum_t *ws_enums_bsearch(const ws_enum_t *enums, size_t count,
                                  const char *needle);

#endif
