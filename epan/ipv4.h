/* ipv4.h
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

#ifndef __IPV4_H__
#define __IPV4_H__

#include <glib.h>
#include "ws_symbol_export.h"


typedef struct {
	guint32	addr;	/* stored in host order */
	guint32	nmask;	/* stored in host order */
} ipv4_addr_and_mask;

/* Allocate a new ipv4_addr_and_mask struct, initialize it,
 * and return pointer
 */
ipv4_addr_and_mask* ipv4_addr_and_mask_new(void);

/* Frees an ipv4_addr_and_mask struct */
void ipv4_addr_and_mask_free(ipv4_addr_and_mask *ipv4);

void ipv4_addr_and_mask_set_host_order_addr(ipv4_addr_and_mask *ipv4, const guint32 new_addr);
void ipv4_addr_and_mask_set_net_order_addr(ipv4_addr_and_mask *ipv4, const guint32 new_addr);
void ipv4_addr_and_mask_set_netmask_bits(ipv4_addr_and_mask *ipv4, const guint new_nmask_bits);

WS_DLL_PUBLIC
guint32 ipv4_get_net_order_addr(ipv4_addr_and_mask *ipv4);
guint32 ipv4_get_host_order_addr(ipv4_addr_and_mask *ipv4);

/* Fills in a buffer with a dotted-decimal notation representation of an IPv4
 * address. */
void ipv4_addr_and_mask_str_buf(const ipv4_addr_and_mask *ipv4, gchar *buf);

/* Compares two ipv4_addr_and_masks, taking into account the less restrictive of the
 * two netmasks, applying that netmask to both addrs.
 */
gboolean ipv4_addr_and_mask_eq(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b);
gboolean ipv4_addr_and_mask_gt(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b);
gboolean ipv4_addr_and_mask_ge(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b);
gboolean ipv4_addr_and_mask_lt(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b);
gboolean ipv4_addr_and_mask_le(const ipv4_addr_and_mask *a, const ipv4_addr_and_mask *b);

#define ipv4_addr_and_mask_ne(a,b) !ipv4_addr_and_mask_eq((a),(b))

#endif
