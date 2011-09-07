/* ipv6-utils.h
 * Definitions for IPv6 packet disassembly
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __IPV6_UTILS_H__
#define __IPV6_UTILS_H__

struct e_in6_addr {
	guint8   bytes[16];		/**< 128 bit IP6 address */
};

typedef struct {
	struct e_in6_addr addr;
	guint32 prefix;
} ipv6_addr;

/**
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
#define E_IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->bytes[0] == 0xfe) && (((a)->bytes[1] & 0xc0) == 0x80))
#define E_IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->bytes[0] == 0xfe) && (((a)->bytes[1] & 0xc0) == 0xc0))

/**
 * Multicast
 */
#define E_IN6_IS_ADDR_MULTICAST(a)	((a)->bytes[0] == 0xff)

#endif /* __IPV6_UTILS_H__ */
