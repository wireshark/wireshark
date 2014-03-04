/* ipv4.c
 *
 * IPv4 address class. They understand how to take netmasks into consideration
 * during equivalence testing.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
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

#include <glib.h>
#include <stdio.h>

#include "ipv4.h"
#include "to_str.h"
#include "addr_and_mask.h"


ipv4_addr*
ipv4_addr_new(void)
{
	ipv4_addr	*ipv4;

	ipv4 = g_new(ipv4_addr, 1);
	return ipv4;
}

void
ipv4_addr_free(ipv4_addr *ipv4)
{
	g_free(ipv4);
}

void
ipv4_addr_set_host_order_addr(ipv4_addr *ipv4, const guint32 new_addr)
{
	ipv4->addr = new_addr;
}

void
ipv4_addr_set_net_order_addr(ipv4_addr *ipv4, const guint32 new_addr)
{
	ipv4->addr = g_ntohl(new_addr);
}

void
ipv4_addr_set_netmask_bits(ipv4_addr *ipv4, const guint new_nmask_bits)
{
	ipv4->nmask = ip_get_subnet_mask(new_nmask_bits);
}

guint32
ipv4_get_net_order_addr(ipv4_addr *ipv4)
{
	return g_htonl(ipv4->addr);
}

guint32
ipv4_get_host_order_addr(ipv4_addr *ipv4)
{
	return ipv4->addr;
}

/* We're assuming the buffer is at least MAX_IP_STR_LEN (16 bytes) */
void
ipv4_addr_str_buf(const ipv4_addr *ipv4, gchar *buf)
{
	guint32	ipv4_host_order = g_htonl(ipv4->addr);
	ip_to_str_buf((guint8*)&ipv4_host_order, buf, MAX_IP_STR_LEN);
}



/*
 * w.x.y.z/32 eq w.x.y.0/24    TRUE
 */

/* Returns TRUE if equal, FALSE if not */
gboolean
ipv4_addr_eq(const ipv4_addr *a, const ipv4_addr *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;
	return (val_a == val_b);
}

gboolean
ipv4_addr_gt(const ipv4_addr *a, const ipv4_addr *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;

	return (val_a > val_b);
}

gboolean
ipv4_addr_ge(const ipv4_addr *a, const ipv4_addr *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;

	return (val_a >= val_b);
}

gboolean
ipv4_addr_lt(const ipv4_addr *a, const ipv4_addr *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;

	return (val_a < val_b);
}

gboolean
ipv4_addr_le(const ipv4_addr *a, const ipv4_addr *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;

	return (val_a <= val_b);
}
