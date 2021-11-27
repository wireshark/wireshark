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

#include "introspection-enums.c"

const ws_enum_t *epan_inspect_enums(void)
{
    return all_enums;
}

static int compare_enum(const void *needle, const void *memb)
{
    return strcmp(needle, ((const ws_enum_t *)memb)->symbol);
}

size_t epan_inspect_enums_count(void)
{
    /* Exclude null terminator */
    return sizeof(all_enums)/sizeof(ws_enum_t) - 1;
}

const ws_enum_t *epan_inspect_enums_bsearch(const char *needle)
{
    return bsearch(needle, all_enums, epan_inspect_enums_count(),
                        sizeof(ws_enum_t), compare_enum);
}
