/* ip4.h
 *
 * IPv4 address class. They understand how to take netmasks into consideration
 * during equivalence testing.
 *
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: ipv4.h,v 1.5 2000/04/12 20:24:34 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __IPV4_H__
#define __IPV4_H__

typedef struct {
	guint32	addr;	/* stored in host order */
	guint32	nmask;	/* stored in host order */
} ipv4_addr;

/* Allocate a new ipv4_addr struct, initialize it, and return pointer */
ipv4_addr* ipv4_addr_new(void);

/* Frees an ipv4 struct */
void ipv4_addr_free(ipv4_addr *ipv4);

void ipv4_addr_set_host_order_addr(ipv4_addr *ipv4, guint32 new_addr);
void ipv4_addr_set_net_order_addr(ipv4_addr *ipv4, guint32 new_addr);
void ipv4_addr_set_netmask_bits(ipv4_addr *ipv4, guint new_nmask_bits);

guint32 ipv4_get_net_order_addr(ipv4_addr *ipv4);
guint32 ipv4_get_host_order_addr(ipv4_addr *ipv4);

/* Returns a string pointer to a dotted-decimal notation representation of an IPv4
 * address. The pointer points to a internal buffer, so don't try to g_free() it */
gchar* ipv4_addr_str(ipv4_addr *ipv4);

/* Compares two ipv4_addrs, taking into account the less restrictive of the
 * two netmasks, applying that netmask to both addrs.
 */
gboolean ipv4_addr_eq(ipv4_addr *a, ipv4_addr *b);
gboolean ipv4_addr_gt(ipv4_addr *a, ipv4_addr *b);
gboolean ipv4_addr_ge(ipv4_addr *a, ipv4_addr *b);
gboolean ipv4_addr_lt(ipv4_addr *a, ipv4_addr *b);
gboolean ipv4_addr_le(ipv4_addr *a, ipv4_addr *b);

#endif
