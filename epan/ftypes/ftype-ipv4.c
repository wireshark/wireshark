/*
 * $Id: ftype-ipv4.c,v 1.7 2002/01/21 07:37:39 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2001 Gerald Combs
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

#include <string.h>

#include <ftypes-int.h>
#include <epan/ipv4.h>
#include <epan/resolv.h>


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
	unsigned int nmask_bits;

	char *has_slash, *s_copy = NULL;
	char *net_str, *addr_str;
	fvalue_t *nmask_fvalue;

	/* Look for CIDR: Is there a single slash in the string? */
	has_slash = strchr(s, '/');
	if (has_slash) {
		/* Make a copy of the string and use strtok() to
		 * get the address portion. */
		s_copy = g_strdup(s);
		addr_str = strtok(s_copy, "/");

		/* I just checked for slash! I shouldn't get NULL here.
		 * Double check just in case. */
		if (!addr_str) {
			log("Unexpected strtok() error parsing IP address: %s", s_copy);
			g_free(s_copy);
			return FALSE;
		}
	}
	else {
		addr_str = s;
	}

	if (!get_host_ipaddr(addr_str, &addr)) {
		log("\"%s\" is not a valid hostname or IPv4 address.", addr_str);
		if (has_slash) {
			g_free(s_copy);
		}
		return FALSE;
	}

	ipv4_addr_set_host_order_addr(&(fv->value.ipv4), addr);

	/* If CIDR, get netmask bits. */
	if (has_slash) {
		net_str = strtok(NULL, "/");
		/* I checked for slash! I shouldn't get NULL here.
		 * Double check just in case. */
		if (!net_str) {
			log("Unexpected strtok() error parsing netmask: %s", s_copy);
			g_free(s_copy);
			return FALSE;
		}

		nmask_fvalue = fvalue_from_string(FT_UINT32, net_str, log);
		g_free(s_copy);
		if (!nmask_fvalue) {
			return FALSE;
		}
		nmask_bits = fvalue_get_integer(nmask_fvalue);
		fvalue_free(nmask_fvalue);

		if (nmask_bits > 32) {
			log("Netmask bits in a CIDR IPv4 address should be <= 32, not %u",
					nmask_bits);
			return FALSE;
		}
		ipv4_addr_set_netmask_bits(&fv->value.ipv4, nmask_bits);
	}
	else {
		/* Not CIDR; mask covers entire address. */
		ipv4_addr_set_netmask_bits(&(fv->value.ipv4), 32);
	}

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

		NULL,
		NULL,
	};

	ftype_register(FT_IPv4, &ipv4_type);
}
