/* ipv4.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "inet_cidr.h"


uint32_t
ws_ipv4_get_subnet_mask(const uint32_t mask_length)
{
	static const guint32 masks[33] = {
		0x00000000,
		0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
		0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
		0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
		0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
		0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
		0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
		0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
		0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff,
	};

	ws_assert(mask_length <= 32);

	return masks[mask_length];
}

static int
compare_ipv4(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b)
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
    dst->nmask = ws_ipv4_get_subnet_mask(src_bits);
}

bool
ws_ipv4_addr_and_mask_contains(const ipv4_addr_and_mask *ipv4, const ws_in4_addr *in_addr)
{
    ipv4_addr_and_mask addr_and_mask;

    addr_and_mask.addr = g_ntohl(*in_addr);
    addr_and_mask.nmask = ws_ipv4_get_subnet_mask(32);
    return compare_ipv4(ipv4, &addr_and_mask) == 0;
}

static const uint8_t bitmasks[9] =
    { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };

static int
compare_ipv6(const ipv6_addr_and_prefix *a, const ipv6_addr_and_prefix *b)
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
    return compare_ipv6(ipv6, &addr_and_mask) == 0;
}
