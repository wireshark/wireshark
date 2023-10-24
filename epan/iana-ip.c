/* iana-ip.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "iana-ip.h"

#include "iana-ip-data.c"

const struct ws_ipv4_special_block *
ws_ipv4_special_block_lookup(const ws_in4_addr *addr)
{
    size_t count = G_N_ELEMENTS(__ipv4_special_block);
    size_t i;
    const struct ws_ipv4_special_block *ptr;

    for (i = 0; i < count; i++) {
        ptr = &__ipv4_special_block[i];
        if (ws_ipv4_addr_and_mask_contains(&ptr->block, addr)) {
            return ptr;
        }
    }

    return NULL;
}

const struct ws_ipv6_special_block *
ws_ipv6_special_block_lookup(const ws_in6_addr *addr)
{
    size_t count = G_N_ELEMENTS(__ipv6_special_block);
    size_t i;
    const struct ws_ipv6_special_block *ptr;

    for (i = 0; i < count; i++) {
        ptr = &__ipv6_special_block[i];
        if (ws_ipv6_addr_and_prefix_contains(&ptr->block, addr)) {
            return ptr;
        }
    }

    return NULL;
}
