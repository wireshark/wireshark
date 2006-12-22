/*
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include <epan/addr_resolv.h>


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
val_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
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
			logfunc("Unexpected strtok() error parsing IP address: %s",
			    s_copy);
			g_free(s_copy);
			return FALSE;
		}
	}
	else {
		addr_str = s;
	}

	if (!get_host_ipaddr(addr_str, &addr)) {
		logfunc("\"%s\" is not a valid hostname or IPv4 address.",
		    addr_str);
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
			logfunc("Unexpected strtok() error parsing netmask: %s",
			    s_copy);
			g_free(s_copy);
			return FALSE;
		}

		/* XXX - this is inefficient */
		nmask_fvalue = fvalue_from_unparsed(FT_UINT32, net_str, FALSE, logfunc);
		g_free(s_copy);
		if (!nmask_fvalue) {
			return FALSE;
		}
		nmask_bits = fvalue_get_integer(nmask_fvalue);

		if (nmask_bits > 32) {
			logfunc("Netmask bits in a CIDR IPv4 address should be <= 32, not %u",
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

static int
val_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	/*
	 * 15 characters for "XXX.XXX.XXX.XXX".
	 */
	return 15;
}

static void
val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	ipv4_addr_str_buf(&fv->value.ipv4, buf);
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

static gboolean cmp_bytes_bitwise_and(fvalue_t *fv_a, fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;
	guint i = 0;
	unsigned char *p_a, *p_b;

	if (b->len != a->len) {
		return FALSE;
	}
	p_a = a->data;
	p_b = b->data;
	while (i < b->len) {
		if (p_a[i] & p_b[i])
			i++;
		else
			return FALSE;
	}
	return TRUE;
}

void
ftype_register_ipv4(void)
{

	static ftype_t ipv4_type = {
		FT_IPv4,			/* ftype */
		"FT_IPv4",			/* name */
		"IPv4 address",			/* pretty_name */
		4,				/* wire_size */
		NULL,				/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		val_to_repr,			/* val_to_string_repr */
		val_repr_len,			/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bytes_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};

	ftype_register(FT_IPv4, &ipv4_type);
}
