/* ipv6.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/ipv6.h>


static const uint8_t bitmasks[9] =
    { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };

static int
compare_network(const ipv6_addr_and_prefix *a, const ipv6_addr_and_prefix *b)
{
    uint32_t prefix;
    int pos = 0;

    prefix = MIN(a->prefix, b->prefix);	/* MIN() like IPv4 */
    prefix = MIN(prefix, 128);		/* sanitize, max prefix is 128 */

    while (prefix >= 8) {
        int byte_a = (int) (a->addr.bytes[pos]);
        int byte_b = (int) (b->addr.bytes[pos]);

        if (byte_a != byte_b) {
            return byte_a - byte_b;
        }

        prefix -= 8;
        pos++;
    }

    if (prefix != 0) {
        int byte_a = (int) (a->addr.bytes[pos] & (bitmasks[prefix]));
        int byte_b = (int) (b->addr.bytes[pos] & (bitmasks[prefix]));

        if (byte_a != byte_b) {
            return byte_a - byte_b;
        }
    }

    return 0;
}


bool
ws_ipv6_addr_and_prefix_contains(const ipv6_addr_and_prefix *ipv6, const ws_in6_addr *in_addr)
{
    ipv6_addr_and_prefix addr_and_mask;

    addr_and_mask.addr = *in_addr;
    addr_and_mask.prefix = 128;
    return compare_network(ipv6, &addr_and_mask) == 0;
}
