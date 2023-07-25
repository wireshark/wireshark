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

void
ws_manuf_iter_init(ws_manuf_iter_t *iter)
{
    memset(iter, 0, sizeof(*iter));
}

/* Iterate between 3 registries in ascending order. */
struct ws_manuf *
ws_manuf_iter_next(ws_manuf_iter_t *iter, struct ws_manuf manuf[3])
{
    ws_manuf_oui24_t *ptr24 = NULL;
    ws_manuf_oui28_t *ptr28 = NULL;
    ws_manuf_oui36_t *ptr36 = NULL;
    struct ws_manuf *result;

    memset(manuf, 0, 3 * sizeof(struct ws_manuf));

    /* Read current positions. */
    if (iter->idx24 < G_N_ELEMENTS(global_manuf_oui24_table)) {
        ptr24 = &global_manuf_oui24_table[iter->idx24];
        memcpy(manuf[0].addr, ptr24->oui24, sizeof(ptr24->oui24));
        manuf[0].mask = 24;
        manuf[0].short_name = ptr24->short_name;
        manuf[0].long_name = ptr24->long_name;
    }
    if (iter->idx28 < G_N_ELEMENTS(global_manuf_oui28_table)) {
        ptr28 = &global_manuf_oui28_table[iter->idx28];
        memcpy(manuf[1].addr, ptr28->oui28, sizeof(ptr28->oui28));
        manuf[1].mask = 28;
        manuf[1].short_name = ptr28->short_name;
        manuf[1].long_name = ptr28->long_name;
    }
    if (iter->idx36 < G_N_ELEMENTS(global_manuf_oui36_table)) {
        ptr36 = &global_manuf_oui36_table[iter->idx36];
        memcpy(manuf[2].addr, ptr36->oui36, sizeof(ptr36->oui36));
        manuf[2].mask = 36;
        manuf[2].short_name = ptr36->short_name;
        manuf[2].long_name = ptr36->long_name;
    }

    /* Select smallest current prefix out of the 3 registries. */
    result = &manuf[0];
    if (result->long_name == NULL)
        result = &manuf[1];
    else if (memcmp(result->addr, manuf[1].addr, 6) > 0)
        result = &manuf[1];
    if (result->long_name == NULL)
        result = &manuf[2];
    else if (memcmp(result->addr, manuf[2].addr, 6) > 0)
        result = &manuf[2];

    if (result->long_name == NULL)
        return NULL;

    /* Advance iterator. */
    if (ptr24 && result->long_name == ptr24->long_name)
        iter->idx24++;
    else if (ptr28 && result->long_name == ptr28->long_name)
        iter->idx28++;
    else if (ptr36 && result->long_name == ptr36->long_name)
        iter->idx36++;
    else
        ws_assert_not_reached();

    return result;
}

void
ws_manuf_dump(FILE *fp)
{
    ws_manuf_iter_t iter;
    struct ws_manuf manuf[3];
    struct ws_manuf *ptr;

    ws_manuf_iter_init(&iter);

    while ((ptr = ws_manuf_iter_next(&iter, manuf))) {
        fprintf(fp, "%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8"/%"PRIu8"\t%s\n",
            ptr->addr[0], ptr->addr[1], ptr->addr[2], ptr->addr[3], ptr->addr[4], ptr->addr[5], ptr->mask,
            ptr->long_name);
    }
}
