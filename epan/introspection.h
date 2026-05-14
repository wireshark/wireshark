/** @file
 * Copyright 2021, João Valverde <j@v6e.pt>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <stddef.h>
#include <ws_symbol_export.h>
#include <wsutil/introspection.h>

/**
 * @brief Returns a list of all Wireshark enums.
 * It can be used by language bindings to the Wireshark API to obtain
 * the value of some magic constants. The array can be binary searched,
 * imported to a hash table, serialized, etc.
 *
 * @return an array of ws_enum_t elements. The array is sorted and
 * ends with {NULL, 0}.
 */
WS_DLL_PUBLIC
const ws_enum_t *epan_inspect_enums(void);

/**
 * @brief Returns size of enums array not including null terminator.
 *
 * @return The number of enums, excluding the null terminator.
 */
WS_DLL_PUBLIC
size_t epan_inspect_enums_count(void);

/**
 * @brief Performs a binary search in the enums for the magic constant "needle".
 *
 * @param needle The string to search for in the enumeration table.
 * @return A pointer to the matching ws_enum_t structure, or NULL if not found.
 */
WS_DLL_PUBLIC
const ws_enum_t *epan_inspect_enums_bsearch(const char *needle);
