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

static int
compare_ipv4_block(const void *key, const void *element)
{
    const uint32_t *ipnum = key;
    const struct ws_iana_ip_special_block *ptr = element;

    uint32_t val = *ipnum & ptr->u_ip.ipv4.nmask;

    if (val < ptr->u_ip.ipv4.addr)
        return -1;
    if (val > ptr->u_ip.ipv4.addr)
        return 1;
    return 0;
}

const struct ws_iana_ip_special_block *
ws_iana_ipv4_special_block_lookup(uint32_t ipnum)
{
    return bsearch(&ipnum, __ipv4_special_block, G_N_ELEMENTS(__ipv4_special_block),
                    sizeof(struct ws_iana_ip_special_block), compare_ipv4_block);
}

static const uint8_t bitmasks[9] =
    { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };

static int
compare_ipv6_block(const void *key, const void *element)
{
    const ws_in6_addr *addr = key;
    const struct ws_iana_ip_special_block *ptr = element;
    uint32_t prefix;
    int pos = 0;
    int byte_a, byte_b;

    prefix = ptr->u_ip.ipv6.prefix;

    while (prefix >= 8) {
        byte_a = addr->bytes[pos];
        byte_b = ptr->u_ip.ipv6.addr.bytes[pos];
        if (byte_a != byte_b)
            return byte_a - byte_b;

        prefix -= 8;
        pos++;
    }

    if (prefix != 0) {
        byte_a = addr->bytes[pos] & bitmasks[prefix];
        byte_b = ptr->u_ip.ipv6.addr.bytes[pos];
        if (byte_a != byte_b)
            return byte_a - byte_b;
    }

    return 0;
}

const struct ws_iana_ip_special_block *
ws_iana_ipv6_special_block_lookup(const ws_in6_addr *addr)
{
    return bsearch(addr, __ipv6_special_block, G_N_ELEMENTS(__ipv6_special_block),
                    sizeof(struct ws_iana_ip_special_block), compare_ipv6_block);
}
