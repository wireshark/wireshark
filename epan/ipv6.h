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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __IPV6_UTILS_H__
#define __IPV6_UTILS_H__

#include <wsutil/inet_ipv6.h>

typedef struct {
	ws_in6_addr addr;
	guint32 prefix;
} ipv6_addr_and_prefix;

#endif /* __IPV6_UTILS_H__ */
