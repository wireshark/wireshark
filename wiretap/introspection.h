/** @file
 * Copyright 2021, João Valverde <j@v6e.pt>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _WTAP_INTROSPECTION_H_
#define _WTAP_INTROSPECTION_H_

#include <stddef.h>
#include <ws_symbol_export.h>
#include <wsutil/introspection.h>

/** Returns an array of ws_enum_t elements. The array is sorted and
 * ends with {NULL, 0}.
 *
 * It can be used by language bindings to the Wireshark API to obtain
 * the value of some magic constants. The array can be binary searched,
 * imported to a hash table, serialized, etc.
 */
WS_DLL_PUBLIC
const ws_enum_t *wtap_inspect_enums(void);

/**
 * @brief Returns size of enums array not including null terminator.
 *
 * @return size_t The number of enums excluding the null terminator.
 */
WS_DLL_PUBLIC
size_t wtap_inspect_enums_count(void);

/**
 * @brief Searches for an enum entry using binary search.
 *
 * @param needle The string to search for in the enum table.
 * @return A pointer to the matching ws_enum_t structure, or NULL if not found.
 */
WS_DLL_PUBLIC
const ws_enum_t *wtap_inspect_enums_bsearch(const char *needle);

#endif
