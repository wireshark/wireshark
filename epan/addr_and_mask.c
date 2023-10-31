/* addr_and_mask.c
 * Routines to fetch IPv4 and IPv6 addresses from a tvbuff and then mask
 * out bits other than those covered by a prefix length
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "addr_and_mask.h"
#include <wsutil/ws_assert.h>
#include <wsutil/inet_netw.h>

/*
 * These routines return the length of the address in bytes on success
 * and -1 if the prefix length is too long.
 */

int
tvb_get_ipv4_addr_with_prefix_len(tvbuff_t *tvb, int offset, ws_in4_addr *addr,
    guint32 prefix_len)
{
	guint8 addr_len;

	if (prefix_len > 32)
		return -1;

	addr_len = (prefix_len + 7) / 8;
	*addr = 0;
	tvb_memcpy(tvb, addr, offset, addr_len);
	if (prefix_len % 8)
		((guint8*)addr)[addr_len - 1] &= ((0xff00 >> (prefix_len % 8)) & 0xff);
	return addr_len;
}

int
tvb_get_ipv6_addr_with_prefix_len(tvbuff_t *tvb, int offset, ws_in6_addr *addr,
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
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
