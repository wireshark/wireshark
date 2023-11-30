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

// MA-L / OUI - MAC Address Block Large (24-bit prefix)
#define MA_L 0
// MA-M - MAC Address Block Medium (28-bit prefix)
#define MA_M 1
// MA-S / OUI-36 - MAC Address Block Small (36-bit prefix)
#define MA_S 2

typedef struct {
    uint8_t oui24[3];
    /* Identifies the 3-byte prefix as part of MA-M or MA-S (or MA-L if none of those). */
    uint8_t kind;
} manuf_registry_t;

typedef struct {
    uint8_t oui24[3];
    const char *short_name;
    const char *long_name;
} manuf_oui24_t;

typedef struct {
    uint8_t oui28[4];
    const char *short_name;
    const char *long_name;
} manuf_oui28_t;

typedef struct {
    uint8_t oui36[5];
    const char *short_name;
    const char *long_name;
} manuf_oui36_t;

#include "manuf-data.c"

static int
compare_oui24_registry(const void *key, const void *element)
{
    const uint8_t *addr = (const uint8_t *)key;
    const manuf_registry_t *entry = (const manuf_registry_t *)element;

    return memcmp(addr, entry->oui24, 3);
}

static int
compare_oui24_entry(const void *key, const void *element)
{
    const uint8_t *addr = (const uint8_t *)key;
    const manuf_oui24_t *oui = (const manuf_oui24_t *)element;

    return memcmp(addr, oui->oui24, 3);
}

static int
compare_oui28_entry(const void *key, const void *element)
{
    const uint8_t *addr = (const uint8_t *)key;
    const manuf_oui28_t *oui = (const manuf_oui28_t *)element;

    // The caller is expected to have masked out (addr[3] & 0xF0).
    return memcmp(addr, oui->oui28, 4);
}

static int
compare_oui36_entry(const void *key, const void *element)
{
    const uint8_t *addr = (const uint8_t *)key;
    const manuf_oui36_t *oui = (const manuf_oui36_t *)element;

    // The caller is expected to have masked out (addr[4] & 0xF0).
    return memcmp(addr, oui->oui36, 5);
}

static int
select_registry(const uint8_t addr[6])
{
    const manuf_registry_t *entry;

    entry = bsearch(addr, ieee_registry_table, G_N_ELEMENTS(ieee_registry_table), sizeof(manuf_registry_t), compare_oui24_registry);
    if (entry)
        return entry->kind;
    return MA_L;
}

static const manuf_oui24_t *
manuf_oui24_lookup(const uint8_t addr[6])
{
    return bsearch(addr, global_manuf_oui24_table,
                    G_N_ELEMENTS(global_manuf_oui24_table),
                    sizeof(manuf_oui24_t),
                    compare_oui24_entry);
}

static const manuf_oui28_t *
manuf_oui28_lookup(const uint8_t addr[6])
{
    const uint8_t addr28[6] = { addr[0], addr[1], addr[2], addr[3] & 0xF0, };
    return bsearch(addr28, global_manuf_oui28_table,
                    G_N_ELEMENTS(global_manuf_oui28_table),
                    sizeof(manuf_oui28_t),
                    compare_oui28_entry);
}

static const manuf_oui36_t *
manuf_oui36_lookup(const uint8_t addr[6])
{
    const uint8_t addr36[6] = { addr[0], addr[1], addr[2], addr[3], addr[4] & 0xF0, };
    return bsearch(addr36, global_manuf_oui36_table,
                    G_N_ELEMENTS(global_manuf_oui36_table),
                    sizeof(manuf_oui36_t),
                    compare_oui36_entry);
}

const char *
ws_manuf_lookup(const uint8_t addr[6], const char **long_name_ptr, unsigned *mask_ptr)
{
    uint8_t addr_copy[6];
    memcpy(addr_copy, addr, 6);
    /* Mask out the broadcast/multicast flag */
    addr_copy[0] &= 0xFE;

    const char *short_name = NULL, *long_name = NULL;
    unsigned mask = 0;

    switch (select_registry(addr_copy)) {
        case MA_L:
        {
            const manuf_oui24_t *ptr = manuf_oui24_lookup(addr_copy);
            if (ptr) {
                short_name = ptr->short_name;
                long_name = ptr->long_name;
                mask = 24;
            }
            break;
        }
        case MA_M:
        {
            const manuf_oui28_t *ptr = manuf_oui28_lookup(addr_copy);
            if (ptr) {
                short_name = ptr->short_name;
                long_name = ptr->long_name;
                mask = 28;
            }
            break;
        }
        case MA_S:
        {
            const manuf_oui36_t *ptr = manuf_oui36_lookup(addr_copy);
            if (ptr) {
                short_name = ptr->short_name;
                long_name = ptr->long_name;
                mask = 36;
            }
            break;
        }
        default:
            ws_assert_not_reached();
    }

    if (mask_ptr) {
        *mask_ptr = mask;
    }
    if (long_name_ptr) {
        *long_name_ptr = long_name;
    }
    return short_name;
}

const char *
ws_manuf_lookup_str(const uint8_t addr[6], const char **long_name_ptr)
{
    return ws_manuf_lookup(addr, long_name_ptr, NULL);
}

const char *
ws_manuf_lookup_oui24(const uint8_t oui[3], const char **long_name_ptr)
{
    uint8_t addr_copy[6] = {0};
    memcpy(addr_copy, oui, 3);
    /* Mask out the broadcast/multicast flag */
    addr_copy[0] &= 0xFE;

    const char *short_name = NULL, *long_name = NULL;

    switch (select_registry(addr_copy)) {
        case MA_L:
        {
            const manuf_oui24_t *ptr = manuf_oui24_lookup(addr_copy);
            if (ptr) {
                short_name = ptr->short_name;
                long_name = ptr->long_name;
            }
            break;
        }
        case MA_M:
        case MA_S:
        {
            /* XXX: These are officially registered to
             * "IEEE Registration Authority" and we could return that, but
             * we'd have to change expectatins elsewhere in the code.
             */
            break;
        }
        default:
            ws_assert_not_reached();
    }

    if (long_name_ptr) {
        *long_name_ptr = long_name;
    }
    return short_name;
}

static inline struct ws_manuf *
copy_oui24(struct ws_manuf *dst, const manuf_oui24_t *src)
{
    memcpy(dst->block, src->oui24, sizeof(src->oui24));
    dst->block[3] = 0;
    dst->block[4] = 0;
    dst->mask = 24;
    dst->short_name = src->short_name;
    dst->long_name = src->long_name;
    return dst;
}

static inline struct ws_manuf *
copy_oui28(struct ws_manuf *dst, const manuf_oui28_t *src)
{
    memcpy(dst->block, src->oui28, sizeof(src->oui28));
    dst->block[4] = 0;
    dst->mask = 28;
    dst->short_name = src->short_name;
    dst->long_name = src->long_name;
    return dst;
}

static inline struct ws_manuf *
copy_oui36(struct ws_manuf *dst, const manuf_oui36_t *src)
{
    memcpy(dst->block, src->oui36, sizeof(src->oui36));
    dst->mask = 36;
    dst->short_name = src->short_name;
    dst->long_name = src->long_name;
    return dst;
}

void
ws_manuf_iter_init(ws_manuf_iter_t *iter)
{
    iter->idx24 = 0;
    copy_oui24(&iter->buf24, &global_manuf_oui24_table[iter->idx24]);
    iter->idx28 = 0;
    copy_oui28(&iter->buf28, &global_manuf_oui28_table[iter->idx28]);
    iter->idx36 = 0;
    copy_oui36(&iter->buf36, &global_manuf_oui36_table[iter->idx36]);
}

/**
 * Iterate between 3 registries in ascending order. This is not the same as
 * fully iterating through one registry followed by another. For example, after
 * visiting "00:55:B1", it could go to  "00:55:DA:00/28", and eventually end up
 * at "00:56:2B" again.
 *
 * The "iter" structure must be zero initialized before the first iteration.
 */
bool
ws_manuf_iter_next(ws_manuf_iter_t *iter, struct ws_manuf *result)
{
    struct ws_manuf *vector[3] = { NULL, NULL, NULL };
    size_t idx = 0;
    struct ws_manuf *ptr;

    /* Read current positions. */
    if (iter->idx24 < G_N_ELEMENTS(global_manuf_oui24_table)) {
        vector[idx++] = &iter->buf24;
    }
    if (iter->idx28 < G_N_ELEMENTS(global_manuf_oui28_table)) {
        vector[idx++] = &iter->buf28;
    }
    if (iter->idx36 < G_N_ELEMENTS(global_manuf_oui36_table)) {
        vector[idx++] = &iter->buf36;
    }

    /* None remaining, we're done. */
    if (idx == 0)
        return false;

    /* Select smallest current prefix out of the 3 registries.
     * There is at least one entry and index 0 is non-empty. */
    ptr = vector[0];
    for (size_t i = 1; i < idx; i++) {
        if (vector[i] && memcmp(vector[i]->block, ptr->block, MANUF_BLOCK_SIZE) < 0) {
            ptr = vector[i];
        }
    }

    /* We have the next smallest element, return result. */
    memcpy(result, ptr, sizeof(struct ws_manuf));

    /* Advance iterator and copy new element. */
    if (ptr->mask == 24) {
        iter->idx24++;
        if (iter->idx24 < G_N_ELEMENTS(global_manuf_oui24_table)) {
            copy_oui24(&iter->buf24, &global_manuf_oui24_table[iter->idx24]);
        }
    }
    else if (ptr->mask == 28) {
        iter->idx28++;
        if (iter->idx28 < G_N_ELEMENTS(global_manuf_oui28_table)) {
            copy_oui28(&iter->buf28, &global_manuf_oui28_table[iter->idx28]);
        }
    }
    else if (ptr->mask == 36) {
        iter->idx36++;
        if (iter->idx36 < G_N_ELEMENTS(global_manuf_oui36_table)) {
            copy_oui36(&iter->buf36, &global_manuf_oui36_table[iter->idx36]);
        }
    }
    else
        ws_assert_not_reached();

    return true;
}

const char *
ws_manuf_block_str(char *buf, size_t buf_size, const struct ws_manuf *ptr)
{
    if (ptr->mask == 24) {
        /* The mask is implied as the full 24 bits when printing a traditional OUI.*/
        snprintf(buf, buf_size, "%02"PRIX8":%02"PRIX8":%02"PRIX8,
            ptr->block[0], ptr->block[1], ptr->block[2]);
    }
    else if (ptr->mask == 28) {
        snprintf(buf, buf_size, "%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8"/28",
            ptr->block[0], ptr->block[1], ptr->block[2], ptr->block[3]);
    }
    else if (ptr->mask == 36) {
        snprintf(buf, buf_size, "%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8"/36",
            ptr->block[0], ptr->block[1], ptr->block[2], ptr->block[3], ptr->block[4]);
    }
    else {
        ws_assert_not_reached();
    }

    return buf;
}

void
ws_manuf_dump(FILE *fp)
{
    ws_manuf_iter_t iter;
    struct ws_manuf item;
    char strbuf[64];

    ws_manuf_iter_init(&iter);

    while (ws_manuf_iter_next(&iter, &item)) {
        fprintf(fp, "%-17s\t%-12s\t%s\n",
            ws_manuf_block_str(strbuf, sizeof(strbuf), &item),
            item.short_name,
            item.long_name);
    }
}

size_t
ws_manuf_count(void)
{
    return G_N_ELEMENTS(global_manuf_oui24_table) +
            G_N_ELEMENTS(global_manuf_oui28_table) +
            G_N_ELEMENTS(global_manuf_oui36_table);
}
