/*
 * $Id: ftype-ipv4.c,v 1.3 2001/03/02 17:17:56 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ftypes-int.h>
#include "ipv4.h"
#include "resolv.h"


static void
set_integer(fvalue_t *fv, guint32 value)
{
	ipv4_addr_set_net_order_addr(&(fv->value.ipv4), value);
	ipv4_addr_set_netmask_bits(&(fv->value.ipv4), 32);
}

static gpointer
value_get(fvalue_t *fv)
{
	return &(fv->value.ipv4);
}

static gboolean
val_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	guint32	addr;

	if (!get_host_ipaddr(s, &addr)) {
		log("\"%s\" is not a valid hostname or IPv4 address.", s);
		return FALSE;
	}
	ipv4_addr_set_host_order_addr(&(fv->value.ipv4), addr);
        /*ipv4_addr_set_netmask_bits(&node->value.ipv4, nmask_bits);*/
	ipv4_addr_set_netmask_bits(&(fv->value.ipv4), 32);
	return TRUE;
}

static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_eq(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_ne(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_gt(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_gt(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_ge(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_ge(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_lt(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_lt(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_le(fvalue_t *a, fvalue_t *b)
{
	return ipv4_addr_le(&a->value.ipv4, &b->value.ipv4);
}

void
ftype_register_ipv4(void)
{

	static ftype_t ipv4_type = {
		"FT_IPv4",
		"IPv4 address",
		4,
		NULL,
		NULL,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		value_get,
		NULL,
		NULL,

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
	};

	ftype_register(FT_IPv4, &ipv4_type);
}
