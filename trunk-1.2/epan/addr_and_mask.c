/* addr_and_mask.c
 * Routines to fetch IPv4 and IPv6 addresses from a tvbuff and then mask
 * out bits other than those covered by a prefix length
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "tvbuff.h"
#include "addr_and_mask.h"

/*
 * These routines return the length of the address in bytes on success
 * and -1 if the prefix length is too long.
 */

int
ipv4_addr_and_mask(tvbuff_t *tvb, int offset, guint8 *addr, guint32 prefix_len)
{
	guint32 addr_len;

	if (prefix_len > 32)
		return -1;

	addr_len = (prefix_len + 7) / 8;
	memset(addr, 0, 4);
	tvb_memcpy(tvb, addr, offset, addr_len);
	if (prefix_len % 8)
		addr[addr_len - 1] &= ((0xff00 >> (prefix_len % 8)) & 0xff);
	return addr_len;
}

int
ipv6_addr_and_mask(tvbuff_t *tvb, int offset, struct e_in6_addr *addr,
    guint32 prefix_len)
{
	guint32 addr_len;

	if (prefix_len > 128)
		return -1;

	addr_len = (prefix_len + 7) / 8;
	memset(addr->bytes, 0, 16);
	tvb_memcpy(tvb, addr->bytes, offset, addr_len);
	if (prefix_len % 8) {
		addr->bytes[addr_len - 1] &=
		    ((0xff00 >> (prefix_len % 8)) & 0xff);
	}

	return addr_len;
}
