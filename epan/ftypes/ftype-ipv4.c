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
val_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
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
			*err_msg = ws_strdup_printf("\"%s\" is not a valid hostname or IPv4 address.",
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
		nmask_fvalue = fvalue_from_literal(FT_UINT32, net_str, FALSE, err_msg);
		if (!nmask_fvalue) {
			return FALSE;
		}
		nmask_bits = fvalue_get_uinteger(nmask_fvalue);
		fvalue_free(nmask_fvalue);

		if (nmask_bits > 32) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("Netmask bits in a CIDR IPv4 address should be <= 32, not %u",
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

static char *
val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	guint32	ipv4_net_order = g_htonl(fv->value.ipv4.addr);
	return ip_to_str(scope, (guint8*)&ipv4_net_order);
}


/* Compares two ipv4_addr_and_masks, taking into account the less restrictive of the
 * two netmasks, applying that netmask to both addrs.
 *
 * So, for example, w.x.y.z/32 eq w.x.y.0/24 is TRUE.
 */

static enum ft_result
cmp_order(const fvalue_t *fv_a, const fvalue_t *fv_b, int *cmp)
{
	guint32		addr_a, addr_b, nmask;

	nmask = MIN(fv_a->value.ipv4.nmask, fv_b->value.ipv4.nmask);
	addr_a = fv_a->value.ipv4.addr & nmask;
	addr_b = fv_b->value.ipv4.addr & nmask;
	if (addr_a == addr_b)
		*cmp = 0;
	else
		*cmp = addr_a < addr_b ? -1 : 1;
	return FT_OK;
}

static enum ft_result
bitwise_and(fvalue_t *dst, const fvalue_t *fv_a, const fvalue_t *fv_b, char **err_ptr _U_)
{
	dst->value.ipv4 = fv_a->value.ipv4;
	dst->value.ipv4.addr &= (fv_b->value.ipv4.addr & fv_b->value.ipv4.nmask);
	return FT_OK;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	guint8* data;
	guint32 addr = g_htonl(fv->value.ipv4.addr);
	data = ((guint8*)&addr)+offset;
	g_byte_array_append(bytes, data, length);
}

static gboolean
is_zero(const fvalue_t *fv_a)
{
	return fv_a->value.ipv4.addr == 0;
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
		NULL,				/* copy_value */
		NULL,				/* free_value */
		val_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		val_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = value_get },	/* union get_value */

		cmp_order,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		is_zero,
		NULL,
		NULL,
		slice,
		bitwise_and,
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};

	ftype_register(FT_IPv4, &ipv4_type);
}

void
ftype_register_pseudofields_ipv4(int proto)
{
	static int hf_ft_ipv4;

	static hf_register_info hf_ftypes[] = {
		{ &hf_ft_ipv4,
		    { "FT_IPv4", "_ws.ftypes.ipv4",
			FT_IPv4, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
	};

	proto_register_field_array(proto, hf_ftypes, array_length(hf_ftypes));
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
