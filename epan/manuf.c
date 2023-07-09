/* manuf.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "manuf.h"
#include <stdlib.h>

#define MA_L 0
#define MA_M 1
#define MA_S 2

#include "manuf-data.c"

static int
compare_oui24_entry(const void *a, const void *b)
{
    return memcmp(a, ((const ws_manuf_oui24_t *)b)->oui24, 3);
}

static int
compare_oui28_entry(const void *a, const void *b)
{
    uint8_t addr[4];
    memcpy(addr, a, 4);
    addr[3] &= 0xF0;
    return memcmp(addr, ((const ws_manuf_oui28_t *)b)->oui28, 4);
}

static int
compare_oui36_entry(const void *a, const void *b)
{
    uint8_t addr[5];
    memcpy(addr, a, 5);
    addr[4] &= 0xF0;
    return memcmp(addr, ((const ws_manuf_oui36_t *)b)->oui36, 5);
}

static int
select_registry(const uint8_t addr[6])
{
    ws_manuf_registry_t *entry;

    entry = bsearch(addr, ieee_registry_table, G_N_ELEMENTS(ieee_registry_table), sizeof(ws_manuf_registry_t), compare_oui24_entry);
    if (entry)
        return entry->kind;
    return MA_L;
}


const char *
global_manuf_lookup(const uint8_t addr[6], const char **long_name_ptr)
{
    int kind = select_registry(addr);

    switch (kind) {
        case MA_L:
        {
            ws_manuf_oui24_t *oui24 = bsearch(addr, global_manuf_oui24_table, G_N_ELEMENTS(global_manuf_oui24_table), sizeof(ws_manuf_oui24_t), compare_oui24_entry);
            if (oui24) {
                if (long_name_ptr)
                    *long_name_ptr = oui24->long_name;
                return oui24->short_name;
            }
            break;
        }
        case MA_M:
        {
            ws_manuf_oui28_t *oui28 = bsearch(addr, global_manuf_oui28_table, G_N_ELEMENTS(global_manuf_oui28_table), sizeof(ws_manuf_oui28_t), compare_oui28_entry);
            if (oui28) {
                if (long_name_ptr)
                    *long_name_ptr = oui28->long_name;
                return oui28->short_name;
            }
            break;
        }
        case MA_S:
        {
            ws_manuf_oui36_t *oui36 = bsearch(addr, global_manuf_oui36_table, G_N_ELEMENTS(global_manuf_oui36_table), sizeof(ws_manuf_oui36_t), compare_oui36_entry);
            if (oui36) {
                if (long_name_ptr)
                    *long_name_ptr = oui36->long_name;
                return oui36->short_name;
            }
            break;
        }
        default:
            ws_assert_not_reached();
    }

    return NULL;
}
