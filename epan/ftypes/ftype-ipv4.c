/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <ftypes-int.h>
#include <epan/ipv4.h>
#include <epan/addr_and_mask.h>
#include <epan/addr_resolv.h>

static void
set_uinteger(fvalue_t *fv, guint32 value)
{
	fv->value.ipv4.addr = g_ntohl(value);
	fv->value.ipv4.nmask = ip_get_subnet_mask(32);
}

static guint32
value_get(fvalue_t *fv)
{
	return g_htonl(fv->value.ipv4.addr);
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
	fv->value.ipv4.addr = g_ntohl(addr);

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
		fv->value.ipv4.nmask = ip_get_subnet_mask(nmask_bits);
	}
	else {
		/* Not CIDR; mask covers entire address. */
		fv->value.ipv4.nmask = ip_get_subnet_mask(32);
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

/* We're assuming the buffer is at least WS_INET_ADDRSTRLEN (16 bytes) */
static void
val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_, char *buf, unsigned int size _U_)
{
	guint32	ipv4_net_order = g_htonl(fv->value.ipv4.addr);
	ip_to_str_buf((guint8*)&ipv4_net_order, buf, WS_INET_ADDRSTRLEN);
}


/* Compares two ipv4_addr_and_masks, taking into account the less restrictive of the
 * two netmasks, applying that netmask to both addrs.
 *
 * So, for example, w.x.y.z/32 eq w.x.y.0/24 is TRUE.
 */

static gboolean
cmp_eq(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	guint32		addr_a, addr_b, nmask;

	nmask = MIN(fv_a->value.ipv4.nmask, fv_b->value.ipv4.nmask);
	addr_a = fv_a->value.ipv4.addr & nmask;
	addr_b = fv_b->value.ipv4.addr & nmask;
	return (addr_a == addr_b);
}

static gboolean
cmp_ne(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	guint32		addr_a, addr_b, nmask;

	nmask = MIN(fv_a->value.ipv4.nmask, fv_b->value.ipv4.nmask);
	addr_a = fv_a->value.ipv4.addr & nmask;
	addr_b = fv_b->value.ipv4.addr & nmask;
	return (addr_a != addr_b);
}

static gboolean
cmp_gt(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	guint32		addr_a, addr_b, nmask;

	nmask = MIN(fv_a->value.ipv4.nmask, fv_b->value.ipv4.nmask);
	addr_a = fv_a->value.ipv4.addr & nmask;
	addr_b = fv_b->value.ipv4.addr & nmask;
	return (addr_a > addr_b);
}

static gboolean
cmp_ge(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	guint32		addr_a, addr_b, nmask;

	nmask = MIN(fv_a->value.ipv4.nmask, fv_b->value.ipv4.nmask);
	addr_a = fv_a->value.ipv4.addr & nmask;
	addr_b = fv_b->value.ipv4.addr & nmask;
	return (addr_a >= addr_b);
}

static gboolean
cmp_lt(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	guint32		addr_a, addr_b, nmask;

	nmask = MIN(fv_a->value.ipv4.nmask, fv_b->value.ipv4.nmask);
	addr_a = fv_a->value.ipv4.addr & nmask;
	addr_b = fv_b->value.ipv4.addr & nmask;
	return (addr_a < addr_b);
}

static gboolean
cmp_le(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	guint32		addr_a, addr_b, nmask;

	nmask = MIN(fv_a->value.ipv4.nmask, fv_b->value.ipv4.nmask);
	addr_a = fv_a->value.ipv4.addr & nmask;
	addr_b = fv_b->value.ipv4.addr & nmask;
	return (addr_a <= addr_b);
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

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	guint8* data;
	guint32 addr = g_htonl(fv->value.ipv4.addr);
	data = ((guint8*)&addr)+offset;
	g_byte_array_append(bytes, data, length);
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

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = value_get },	/* union get_value */

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
		slice,
	};

	ftype_register(FT_IPv4, &ipv4_type);
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
