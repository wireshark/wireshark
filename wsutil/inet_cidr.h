/** @file
 * Definitions of IPv4 address-and-mask structure, which is what an
 * FT_IPV4 value is (even if there's no mask in a packet, those
 * values can be compared against an address+mask in a filter
 * expression).
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IPV4_H__
#define __IPV4_H__

#include <wireshark.h>
#include <wsutil/inet_addr.h>

typedef struct {
	guint32	addr;	/* stored in host order */
	guint32	nmask;	/* stored in host order */
} ipv4_addr_and_mask;

typedef struct {
	ws_in6_addr addr;
	guint32 prefix;
} ipv6_addr_and_prefix;

/*
 ********** IPv4 *********
 */

/**
* Returns the IPv4 subnet mask of the specified length
*
* @param mask_length the number of bits in the subnet mask (max of 32)
* @return the subnet mask of the specified length
*/
WS_DLL_PUBLIC
uint32_t
ws_ipv4_get_subnet_mask(const uint32_t mask_length);

WS_DLL_PUBLIC
void
ws_ipv4_addr_and_mask_init(ipv4_addr_and_mask *dst, ws_in4_addr src_addr, int src_bits);

WS_DLL_PUBLIC
bool
ws_ipv4_addr_and_mask_contains(const ipv4_addr_and_mask *ipv4, const ws_in4_addr *addr);

/*
 ********** IPv6 *********
 */

WS_DLL_PUBLIC
bool
ws_ipv6_addr_and_prefix_contains(const ipv6_addr_and_prefix *ipv6, const ws_in6_addr *addr);

#endif
