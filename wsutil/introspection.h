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

typedef struct {
    const char *symbol;
    int value;
} ws_enum_t;


/** Performs a binary search for the magic constant "needle". */
WS_DLL_PUBLIC
const ws_enum_t *
ws_enums_bsearch(const ws_enum_t *enums, size_t count,
                            const char *needle);

#endif
