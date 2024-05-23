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
#include <epan/addr_resolv.h>
#include <epan/to_str.h>
#include <wsutil/inet_cidr.h>
#include <wsutil/strtoi.h>

static bool
ipv6_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
	const char *slash;
	const char *addr_str;
	char *addr_str_to_free = NULL;
	uint32_t nmask_bits;
	const char *endptr;

	/* Look for prefix: Is there a single slash in the string? */
	slash = strchr(s, '/');
	if (slash) {
		/* Make a copy of the string up to but not including the
		 * slash; that's the address portion. */
		addr_str_to_free = wmem_strndup(NULL, s, slash-s);
		addr_str = addr_str_to_free;
	}
	else
		addr_str = s;

	if (!get_host_ipaddr6(addr_str, &(fv->value.ipv6.addr))) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid hostname or IPv6 address.", s);
		if (addr_str_to_free)
			wmem_free(NULL, addr_str_to_free);
		return false;
	}

	if (addr_str_to_free)
		wmem_free(NULL, addr_str_to_free);

	/* If prefix */
	if (slash) {
		if(!ws_strtou32(slash+1, &endptr, &nmask_bits) || *endptr != '\0') {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("%s in not a valid mask", slash+1);
			}
			return false;
		}
		if (nmask_bits > 128) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("Prefix in a IPv6 address should be <= 128, not %u",
						nmask_bits);
			}
			return false;
		}
		fv->value.ipv6.prefix = nmask_bits;
	} else {
		/* Not CIDR; mask covers entire address. */
		fv->value.ipv6.prefix = 128;
	}

	return true;
}

static char *
ipv6_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	char buf[WS_INET6_ADDRSTRLEN];
	char *repr;

	ip6_to_str_buf(&fv->value.ipv6.addr, buf, sizeof(buf));

	if (fv->value.ipv6.prefix != 0 && fv->value.ipv6.prefix != 128)
		repr = wmem_strdup_printf(scope, "%s/%"PRIu32, buf, fv->value.ipv6.prefix);
	else
		repr = wmem_strdup(scope, buf);

	return repr;
}

static void
ipv6_set(fvalue_t *fv, const ipv6_addr_and_prefix *value)
{
	fv->value.ipv6 = *value;
}

static const ipv6_addr_and_prefix *
ipv6_get(fvalue_t *fv)
{
	return &fv->value.ipv6;
}

static const uint8_t bitmasks[9] =
	{ 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };

static enum ft_result
cmp_order(const fvalue_t *fv_a, const fvalue_t *fv_b, int *cmp)
{
	const ipv6_addr_and_prefix *a = &(fv_a->value.ipv6);
	const ipv6_addr_and_prefix *b = &(fv_b->value.ipv6);
	uint32_t	prefix;
	int pos = 0;

	prefix = MIN(a->prefix, b->prefix);	/* MIN() like IPv4 */
	prefix = MIN(prefix, 128);		/* sanitize, max prefix is 128 */

	while (prefix >= 8) {
		int byte_a = (int) (a->addr.bytes[pos]);
		int byte_b = (int) (b->addr.bytes[pos]);

		if (byte_a != byte_b) {
			*cmp = byte_a - byte_b;
			return FT_OK;
		}

		prefix -= 8;
		pos++;
	}

	if (prefix != 0) {
		int byte_a = (int) (a->addr.bytes[pos] & (bitmasks[prefix]));
		int byte_b = (int) (b->addr.bytes[pos] & (bitmasks[prefix]));

		if (byte_a != byte_b) {
			*cmp = byte_a - byte_b;
			return FT_OK;
		}
	}
	*cmp = 0;
	return FT_OK;
}

static enum ft_result
bitwise_and(fvalue_t *dst, const fvalue_t *fv_a, const fvalue_t *fv_b, char **err_ptr _U_)
{
	const ipv6_addr_and_prefix *a = &(fv_a->value.ipv6);
	const ipv6_addr_and_prefix *b = &(fv_b->value.ipv6);
	uint32_t	prefix;
	int pos = 0;

	prefix = MIN(a->prefix, b->prefix);	/* MIN() like in IPv4 */
	prefix = MIN(prefix, 128);		/* sanitize, max prefix is 128 */

	while (prefix >= 8) {
		dst->value.ipv6.addr.bytes[pos] =
			a->addr.bytes[pos] & b->addr.bytes[pos];

		prefix -= 8;
		pos++;
	}

	if (prefix != 0) {
		dst->value.ipv6.addr.bytes[pos] =
			a->addr.bytes[pos] & b->addr.bytes[pos] & bitmasks[prefix];
	}
	return FT_OK;
}

static unsigned
len(fvalue_t *fv _U_)
{
	return FT_IPv6_LEN;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, unsigned offset, unsigned length)
{
	uint8_t* data;

	data = fv->value.ipv6.addr.bytes + offset;

	g_byte_array_append(bytes, data, length);
}

static unsigned
ipv6_hash(const fvalue_t *fv)
{
	struct _ipv6 {
		int64_t val[2];
	} *addr = (struct _ipv6 *)&fv->value.ipv6.addr;
	int64_t mask = fv->value.ipv6.prefix;

	return g_int64_hash(&addr->val[0]) ^ g_int64_hash(&addr->val[1]) ^ g_int64_hash(&mask);
}

static bool
is_zero(const fvalue_t *fv_a)
{
	ws_in6_addr zero = { 0 };
	return memcmp(&fv_a->value.ipv6.addr, &zero, sizeof(ws_in6_addr)) == 0;
}

void
ftype_register_ipv6(void)
{
	static const ftype_t ipv6_type = {
		FT_IPv6,			/* ftype */
		FT_IPv6_LEN,			/* wire_size */
		NULL,				/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		ipv6_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		NULL,				/* val_from_uinteger64 */
		NULL,				/* val_from_sinteger64 */
		NULL,				/* val_from_double */
		ipv6_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_to_double */

		{ .set_value_ipv6 = ipv6_set },	/* union set_value */
		{ .get_value_ipv6 = ipv6_get },	/* union get_value */

		cmp_order,
		NULL, 				/* XXX, cmp_contains, needed? ipv4 doesn't support it */
		NULL,				/* cmp_matches */

		ipv6_hash,
		is_zero,
		NULL,
		len,
		(FvalueSlice)slice,
		bitwise_and,
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};

	ftype_register(FT_IPv6, &ipv6_type);
}

void
ftype_register_pseudofields_ipv6(int proto)
{
	static int hf_ft_ipv6;

	static hf_register_info hf_ftypes[] = {
		{ &hf_ft_ipv6,
		    { "FT_IPv6", "_ws.ftypes.ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x00,
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
