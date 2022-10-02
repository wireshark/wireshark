/*
 * Copyright 2021, João Valverde <j@v6e.pt>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include "introspection.h"
#include <string.h>
#include <stdlib.h>


static int
compare_enum(const void *needle, const void *memb)
{
    return strcmp(needle, ((const ws_enum_t *)memb)->symbol);
}

const ws_enum_t *
ws_enums_bsearch(const ws_enum_t *enums, size_t count,
                            const char *needle)
{
    return bsearch(needle, enums, count, sizeof(ws_enum_t), compare_enum);
}
