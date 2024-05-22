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

#include <wsutil/array.h>

#include "introspection-enums.c"

const ws_enum_t *epan_inspect_enums(void)
{
    return all_enums;
}

size_t epan_inspect_enums_count(void)
{
    /* Exclude null terminator */
    return array_length(all_enums) - 1;
}

const ws_enum_t *epan_inspect_enums_bsearch(const char *needle)
{
    return ws_enums_bsearch(all_enums, epan_inspect_enums_count(), needle);
}
