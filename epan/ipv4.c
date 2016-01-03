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


ipv4_addr_and_mask*
ipv4_addr_and_mask_new(void)
{
	ipv4_addr_and_mask	*ipv4;

	ipv4 = g_new(ipv4_addr_and_mask, 1);
	return ipv4;
}

void
ipv4_addr_and_mask_free(ipv4_addr_and_mask *ipv4)
{
	g_free(ipv4);
}

void
ipv4_addr_and_mask_set_host_order_addr(ipv4_addr_and_mask *ipv4, const guint32 new_addr)
{
	ipv4->addr = new_addr;
}

void
ipv4_addr_and_mask_set_net_order_addr(ipv4_addr_and_mask *ipv4, const guint32 new_addr)
{
	ipv4->addr = g_ntohl(new_addr);
}

void
ipv4_addr_and_mask_set_netmask_bits(ipv4_addr_and_mask *ipv4, const guint new_nmask_bits)
{
	ipv4->nmask = ip_get_subnet_mask(new_nmask_bits);
}

guint32
ipv4_get_net_order_addr(ipv4_addr_and_mask *ipv4)
{
	return g_htonl(ipv4->addr);
}

guint32
ipv4_get_host_order_addr(ipv4_addr_and_mask *ipv4)
{
	return ipv4->addr;
}

/* We're assuming the buffer is at least MAX_IP_STR_LEN (16 bytes) */
void
ipv4_addr_and_mask_str_buf(const ipv4_addr_and_mask *ipv4, gchar *buf)
{
	guint32	ipv4_host_order = g_htonl(ipv4->addr);
	ip_to_str_buf((guint8*)&ipv4_host_order, buf, MAX_IP_STR_LEN);
}



/*
 * w.x.y.z/32 eq w.x.y.0/24    TRUE
 */

/* Returns TRUE if equal, FALSE if not */
gboolean
ipv4_addr_and_mask_eq(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;
	return (val_a == val_b);
}

gboolean
ipv4_addr_and_mask_gt(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;

	return (val_a > val_b);
}

gboolean
ipv4_addr_and_mask_ge(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;

	return (val_a >= val_b);
}

gboolean
ipv4_addr_and_mask_lt(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;

	return (val_a < val_b);
}

gboolean
ipv4_addr_and_mask_le(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b)
{
	guint32	val_a, val_b, nmask;

	nmask = MIN(a->nmask, b->nmask);
	val_a = a->addr & nmask;
	val_b = b->addr & nmask;

	return (val_a <= val_b);
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
