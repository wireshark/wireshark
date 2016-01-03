/* addr_and_mask.c
 * Routines to fetch IPv4 and IPv6 addresses from a tvbuff and then mask
 * out bits other than those covered by a prefix length
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "tvbuff.h"
#include "ipv6.h"
#include "addr_and_mask.h"

guint32
ip_get_subnet_mask(const guint32 mask_length)
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

	g_assert(mask_length <= 32);

	return masks[mask_length];
}

/*
 * These routines return the length of the address in bytes on success
 * and -1 if the prefix length is too long.
 */

int
tvb_get_ipv4_addr_with_prefix_len(tvbuff_t *tvb, int offset, guint8 *addr,
    guint32 prefix_len)
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
tvb_get_ipv6_addr_with_prefix_len(tvbuff_t *tvb, int offset, struct e_in6_addr *addr,
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
