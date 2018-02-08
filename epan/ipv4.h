/* ipv4.h
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

#include <wsutil/inet_ipv4.h>

typedef struct {
	guint32	addr;	/* stored in host order */
	guint32	nmask;	/* stored in host order */
} ipv4_addr_and_mask;

#endif
