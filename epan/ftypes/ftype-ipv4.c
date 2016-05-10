/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <ftypes-int.h>
#include <epan/ipv4.h>
#include <epan/addr_resolv.h>


static void
set_uinteger(fvalue_t *fv, guint32 value)
{
	ipv4_addr_and_mask_set_net_order_addr(&(fv->value.ipv4), value);
	ipv4_addr_and_mask_set_netmask_bits(&(fv->value.ipv4), 32);
}

static gpointer
value_get(fvalue_t *fv)
{
	return &(fv->value.ipv4);
}

static gboolean
val_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	guint32	addr;
	unsigned int nmask_bits;

	const char *slash, *net_str;
	const char *addr_str;
	char *addr_str_to_free = NULL;
	fvalue_t *nmask_fvalue;

	/* Look for CIDR: Is there a single slash in the string? */
	slash = strchr(s, '/');
	if (slash) {
		/* Make a copy of the string up to but not including the
		 * slash; that's the address portion. */
		addr_str_to_free = wmem_strndup(NULL, s, slash - s);
		addr_str = addr_str_to_free;
	}
	else {
		addr_str = s;
	}

	if (!get_host_ipaddr(addr_str, &addr)) {
		if (err_msg != NULL) {
			*err_msg = g_strdup_printf("\"%s\" is not a valid hostname or IPv4 address.",
			    addr_str);
		}
		if (addr_str_to_free)
			wmem_free(NULL, addr_str_to_free);
		return FALSE;
	}

	if (addr_str_to_free)
		wmem_free(NULL, addr_str_to_free);
	ipv4_addr_and_mask_set_net_order_addr(&(fv->value.ipv4), addr);

	/* If CIDR, get netmask bits. */
	if (slash) {
		/* Skip past the slash */
		net_str = slash + 1;

		/* XXX - this is inefficient */
		nmask_fvalue = fvalue_from_unparsed(FT_UINT32, net_str, FALSE, err_msg);
		if (!nmask_fvalue) {
			return FALSE;
		}
		nmask_bits = fvalue_get_uinteger(nmask_fvalue);
		FVALUE_FREE(nmask_fvalue);

		if (nmask_bits > 32) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("Netmask bits in a CIDR IPv4 address should be <= 32, not %u",
						nmask_bits);
			}
			return FALSE;
		}
		ipv4_addr_and_mask_set_netmask_bits(&fv->value.ipv4, nmask_bits);
	}
	else {
		/* Not CIDR; mask covers entire address. */
		ipv4_addr_and_mask_set_netmask_bits(&(fv->value.ipv4), 32);
	}

	return TRUE;
}

static int
val_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_, int field_display _U_)
{
	/*
	 * 15 characters for "XXX.XXX.XXX.XXX".
	 */
	return 15;
}

static void
val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_, char *buf, unsigned int size _U_)
{
	ipv4_addr_and_mask_str_buf(&fv->value.ipv4, buf);
}

static gboolean
cmp_eq(const fvalue_t *a, const fvalue_t *b)
{
	return ipv4_addr_and_mask_eq(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_ne(const fvalue_t *a, const fvalue_t *b)
{
	return ipv4_addr_and_mask_ne(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_gt(const fvalue_t *a, const fvalue_t *b)
{
	return ipv4_addr_and_mask_gt(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_ge(const fvalue_t *a, const fvalue_t *b)
{
	return ipv4_addr_and_mask_ge(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_lt(const fvalue_t *a, const fvalue_t *b)
{
	return ipv4_addr_and_mask_lt(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_le(const fvalue_t *a, const fvalue_t *b)
{
	return ipv4_addr_and_mask_le(&a->value.ipv4, &b->value.ipv4);
}

static gboolean
cmp_bitwise_and(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	guint32		addr_a;
	guint32		addr_b;

	addr_a = fv_a->value.ipv4.addr & fv_a->value.ipv4.nmask;
	addr_b = fv_b->value.ipv4.addr & fv_b->value.ipv4.nmask;
	return ((addr_a & addr_b) != 0);
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

		NULL,				/* set_value_byte_array */
		NULL,				/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		set_uinteger,		/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};

	ftype_register(FT_IPv4, &ipv4_type);
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
