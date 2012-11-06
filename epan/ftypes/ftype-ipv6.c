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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <ftypes-int.h>
#include <epan/ipv6-utils.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>

static void
ipv6_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(!already_copied);

	memcpy(fv->value.ipv6.addr.bytes, value, FT_IPv6_LEN);
	fv->value.ipv6.prefix = 128;
}

static gboolean
ipv6_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	char *has_slash, *addr_str;
	unsigned int nmask_bits;
	fvalue_t *nmask_fvalue;

	/* Look for prefix: Is there a single slash in the string? */
	if ((has_slash = strchr(s, '/')))
		addr_str = ep_strndup(s, has_slash-s);
	else
		addr_str = s;

	if (!get_host_ipaddr6(addr_str, &(fv->value.ipv6.addr))) {
		logfunc("\"%s\" is not a valid hostname or IPv6 address.", s);
		return FALSE;
	}

	/* If prefix */
	if (has_slash) {
		/* XXX - this is inefficient */
		nmask_fvalue = fvalue_from_unparsed(FT_UINT32, has_slash+1, FALSE, logfunc);
		if (!nmask_fvalue) {
			return FALSE;
		}
		nmask_bits = fvalue_get_uinteger(nmask_fvalue);
		FVALUE_FREE(nmask_fvalue);

		if (nmask_bits > 128) {
			logfunc("Prefix in a IPv6 address should be <= 128, not %u",
					nmask_bits);
			return FALSE;
		}
		fv->value.ipv6.prefix = nmask_bits;
	} else {
		/* Not CIDR; mask covers entire address. */
		fv->value.ipv6.prefix = 128;
	}

	return TRUE;
}

static int
ipv6_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	/*
	 * 39 characters for "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX".
	 */
	return 39;
}

static void
ipv6_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	ip6_to_str_buf(&(fv->value.ipv6.addr), buf);
}

static gpointer
value_get(fvalue_t *fv)
{
	return fv->value.ipv6.addr.bytes;
}

static const guint8 bitmasks[9] = 
	{ 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };

static gint
cmp_compare(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	const ipv6_addr *a = &(fv_a->value.ipv6);
	const ipv6_addr *b = &(fv_b->value.ipv6);
	guint32	prefix;
	int pos = 0;

	prefix = MIN(a->prefix, b->prefix);	/* MIN() like IPv4 */
	prefix = MIN(prefix, 128);			/* sanitize, max prefix is 128 */

	while (prefix >= 8) {
		gint byte_a = (gint) (a->addr.bytes[pos]);
		gint byte_b = (gint) (b->addr.bytes[pos]);

		if (byte_a != byte_b)
			return byte_a - byte_b;

		prefix -= 8;
		pos++;
	}

	if (prefix != 0) {
		gint byte_a = (gint) (a->addr.bytes[pos] & (bitmasks[prefix]));
		gint byte_b = (gint) (b->addr.bytes[pos] & (bitmasks[prefix]));

		if (byte_a != byte_b)
			return byte_a - byte_b;
	}
	return 0;
}

static gboolean
cmp_eq(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	return (cmp_compare(fv_a, fv_b) == 0);
}

static gboolean
cmp_ne(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	return (cmp_compare(fv_a, fv_b) != 0);
}

static gboolean
cmp_gt(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	return (cmp_compare(fv_a, fv_b) > 0);
}

static gboolean
cmp_ge(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	return (cmp_compare(fv_a, fv_b) >= 0);
}

static gboolean
cmp_lt(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	return (cmp_compare(fv_a, fv_b) < 0);
}

static gboolean
cmp_le(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	return (cmp_compare(fv_a, fv_b) <= 0);
}

static gboolean
cmp_bitwise_and(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	const ipv6_addr *a = &(fv_a->value.ipv6);
	const ipv6_addr *b = &(fv_b->value.ipv6);
	guint32	prefix;
	int pos = 0;

	prefix = MIN(a->prefix, b->prefix);	/* MIN() like in IPv4 */
	prefix = MIN(prefix, 128);			/* sanitize, max prefix is 128 */

	while (prefix >= 8) {
		if (a->addr.bytes[pos] & b->addr.bytes[pos])
			return TRUE;

		prefix -= 8;
		pos++;
	}

	if (prefix != 0) {
		guint8 byte_a = (a->addr.bytes[pos] & (bitmasks[prefix]));
		guint8 byte_b = (b->addr.bytes[pos] & (bitmasks[prefix]));

		if (byte_a & byte_b)
			return TRUE;
	}
	return FALSE;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	/* XXX needed? ipv4 doesn't support slice() */
	guint8* data;

	data = fv->value.ipv6.addr.bytes + offset;

	g_byte_array_append(bytes, data, length);
}

void
ftype_register_ipv6(void)
{
	static ftype_t ipv6_type = {
		FT_IPv6,			/* ftype */
		"FT_IPv6",			/* name */
		"IPv6 address",			/* pretty_name */
		FT_IPv6_LEN,			/* wire_size */
		NULL,		/* new_value */
		NULL,		/* free_value */
		ipv6_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		ipv6_to_repr,			/* val_to_string_repr */
		ipv6_repr_len,			/* len_string_repr */

		ipv6_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bitwise_and,
		NULL, 				/* XXX, cmp_contains, needed? ipv4 doesn't support it */
		NULL,				/* cmp_matches */

		NULL,
		slice,
	};

	ftype_register(FT_IPv6, &ipv6_type);
}
