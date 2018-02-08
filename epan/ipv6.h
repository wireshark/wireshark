/* ipv6.h
 * Definitions of IPv6 address-and-prefix structure, which is what an
 * FT_IPV6 value is (even if there's no prefix in a packet, those
 * values can be compared against an address+prefix in a filter
 * expression).
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * Copyright 1998 Gerald Combs
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IPV6_UTILS_H__
#define __IPV6_UTILS_H__

#include <wsutil/inet_ipv6.h>

typedef struct {
	ws_in6_addr addr;
	guint32 prefix;
} ipv6_addr_and_prefix;

#endif /* __IPV6_UTILS_H__ */
