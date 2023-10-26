/* ipv4.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/ipv4.h>
#include <epan/addr_and_mask.h>

static int
compare_network(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b)
{
    uint32_t addr_a, addr_b, nmask;

    nmask = MIN(a->nmask, b->nmask);
    addr_a = a->addr & nmask;
    addr_b = b->addr & nmask;
    if (addr_a < addr_b)
        return -1;
    if (addr_a > addr_b)
        return 1;
    return 0;
}

void
ws_ipv4_addr_and_mask_init(ipv4_addr_and_mask *dst, ws_in4_addr src_addr, int src_bits)
{
    dst->addr = g_ntohl(src_addr);
    dst->nmask = ip_get_subnet_mask(src_bits);
}

bool
ws_ipv4_addr_and_mask_contains(const ipv4_addr_and_mask *ipv4, const ws_in4_addr *in_addr)
{
    ipv4_addr_and_mask addr_and_mask;

    addr_and_mask.addr = g_ntohl(*in_addr);
    addr_and_mask.nmask = ip_get_subnet_mask(32);
    return compare_network(ipv4, &addr_and_mask) == 0;
}
