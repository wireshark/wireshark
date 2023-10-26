/******************************************************************************
** Copyright (C) 2006-2023 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Project: OpcUa Wireshark Plugin
**
** Description: OpcUa Protocol Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

#include "opcua_keyset.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <epan/packet.h>

static struct ua_keyset *g_keysets;
static unsigned int g_num_keysets;
static bool g_sorted;

int ua_keysets_init(void)
{
    g_keysets = NULL;
    g_num_keysets = 0;
    g_sorted = false;
    return 0;
}

int ua_keysets_clear(void)
{
    if (g_keysets) {
        g_free(g_keysets);
        g_keysets = NULL;
    }
    g_num_keysets = 0;
    g_sorted = false;
    return 0;
}

/**
 * Allocates a new keyset entry.
 *
 * @return Returns pointer to new empty keyset.
 *  NULL would indicate an out of memory situation.
 */
struct ua_keyset *ua_keysets_add(void)
{
    struct ua_keyset *tmp = g_realloc(g_keysets, sizeof(*g_keysets) * (g_num_keysets + 1));
    if (tmp == NULL) return NULL; /* out of mem */
    /* realloc succeeded, assign new pointer */
    g_keysets = tmp;
    /* return new element */
    tmp = &g_keysets[g_num_keysets++];
    memset(tmp, 0, sizeof(*tmp));
    /* default to 32 byte sig_len if missing.
     * This is the most likely length for SHA256 based signatures,
     * SHA1 based signatures with 16 bytes are deprecated.
     */
    tmp->client_sig_len = 32;
    tmp->server_sig_len = 32;
    return tmp;
}

/**
 * Compare function for bsearch/qsort.
 * Sorts by keyset->id.
 */
static int keyset_compare(const void *a, const void *b)
{
    const struct ua_keyset *keyset_a = a;
    const struct ua_keyset *keyset_b = b;

    if (keyset_a->id == keyset_b->id) return 0;
    if (keyset_a->id < keyset_b->id) return -1;
    return 1;
}

/**
 * Sorts the keyset to be able to use bsearch.
 */
void ua_keysets_sort(void)
{
    if (g_num_keysets >= 2) {
        qsort(g_keysets, g_num_keysets, sizeof(struct ua_keyset), keyset_compare);
    }

    g_sorted = true;
}

/**
 * Looks up a keyset by id.
 *
 * @param id The id is 64bit value which contains the combined securechannel_id and token_id.
 *
 * @return Keyset if found, NULL if not found.
 */
struct ua_keyset *ua_keysets_lookup(uint64_t id)
{
    struct ua_keyset *tmp, key;

    if (!g_sorted) return NULL;

    key.id = id;
    tmp = bsearch(&key, g_keysets, g_num_keysets, sizeof(struct ua_keyset), keyset_compare);

    return tmp;
}

static void print_hex(unsigned char *data, unsigned int data_len)
{
    unsigned int i;

    for (i = 0; i < data_len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

/**
 * For debugging purposes only.
 */
void ua_keysets_dump(void)
{
    struct ua_keyset *tmp;
    unsigned int i;
    uint32_t channel_id, token_id;

    printf("Number of keysets: %u\n", g_num_keysets);

    for (i = 0; i < g_num_keysets; ++i) {
        tmp = &g_keysets[i];
        channel_id = (uint32_t)(tmp->id >> 32);
        token_id = (uint32_t)(tmp->id & 0xffffffff);

        printf("%u: id=%" PRIu64 ", channel_id=%u, token_id=%u\n", i, tmp->id, channel_id, token_id);

        printf("%u: client IV: ", i);
        print_hex(tmp->client_iv, sizeof(tmp->client_iv));
        printf("%u: client key(%u): ", i, tmp->client_key_len);
        print_hex(tmp->client_key, tmp->client_key_len);
        printf("%u: client sig_len(%u): ", i, tmp->client_sig_len);

        printf("%u: server IV: ", i);
        print_hex(tmp->server_iv, sizeof(tmp->server_iv));
        printf("%u: server key(%u): ", i, tmp->server_key_len);
        print_hex(tmp->server_key, tmp->server_key_len);
        printf("%u: server sig_len(%u): ", i, tmp->server_sig_len);
    }
}

