/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <ftypes-int.h>
#include <string.h>

#include <strutil.h>
#include <wsutil/ws_assert.h>
#include <wsutil/unicode-utils.h>
#include <wsutil/strtoi.h>


static void
string_fvalue_new(fvalue_t *fv)
{
	fv->value.strbuf = NULL;
}

static void
string_fvalue_copy(fvalue_t *dst, const fvalue_t *src)
{
	dst->value.strbuf = wmem_strbuf_dup(NULL, src->value.strbuf);
}

static void
string_fvalue_free(fvalue_t *fv)
{
	wmem_strbuf_destroy(fv->value.strbuf);
}

static void
string_fvalue_set_strbuf(fvalue_t *fv, wmem_strbuf_t *value)
{
	DISSECTOR_ASSERT(value != NULL);

	/* Free up the old value, if we have one */
	string_fvalue_free(fv);

	fv->value.strbuf = value;
}

static char *
string_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	if (rtype == FTREPR_DISPLAY || rtype == FTREPR_JSON) {
		/* XXX: This escapes NUL with "\0", but JSON (neither RFC 8259 nor
		 * ECMA-404) does not allow that, it must be "\u0000".
		 */
		return ws_escape_null(scope, fv->value.strbuf->str, fv->value.strbuf->len, false);
	}
	if (rtype == FTREPR_DFILTER) {
		return ws_escape_string_len(scope, fv->value.strbuf->str, fv->value.strbuf->len, true);
	}
	ws_assert_not_reached();
}


static const wmem_strbuf_t *
value_get(fvalue_t *fv)
{
	return fv->value.strbuf;
}

static bool
val_from_string(fvalue_t *fv, const char *s, size_t len, char **err_msg _U_)
{
	/* Free up the old value, if we have one */
	string_fvalue_free(fv);

	if (len > 0)
		fv->value.strbuf = wmem_strbuf_new_len(NULL, s, len);
	else
		fv->value.strbuf = wmem_strbuf_new(NULL, s);

	return true;
}

static bool
val_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
	/* Just turn it into a string */
	/* XXX Should probably be a syntax error instead. It's more user-friendly to ask the
	 * user to be explicit about the meaning of an unquoted literal than them trying to figure out
	 * why a valid filter expression is giving wrong results. */
	return val_from_string(fv, s, 0, err_msg);
}

static bool
val_from_charconst(fvalue_t *fv, unsigned long num, char **err_msg)
{
	/* XXX Should be a syntax error if literal is also a syntax error. */

	/* Free up the old value, if we have one */
	string_fvalue_free(fv);
	fv->value.strbuf = NULL;

	if (num > UINT8_MAX) {
		if (err_msg) {
			*err_msg = ws_strdup_printf("%lu is too large for a byte value", num);
		}
		return false;
	}

	char c = (char)num;
	fv->value.strbuf = wmem_strbuf_new(NULL, NULL);
	wmem_strbuf_append_c(fv->value.strbuf, c);

	return true;
}

static unsigned
string_hash(const fvalue_t *fv)
{
	return g_str_hash(wmem_strbuf_get_str(fv->value.strbuf));
}

static bool
string_is_zero(const fvalue_t *fv)
{
	return fv->value.strbuf == NULL || fv->value.strbuf->len == 0;
}

static unsigned
len(fvalue_t *fv)
{
	/* g_utf8_strlen returns long for no apparent reason*/
	long len = g_utf8_strlen(fv->value.strbuf->str, -1);
	if (len < 0)
		return 0;
	return (unsigned)len;
}

static void
slice(fvalue_t *fv, wmem_strbuf_t *buf, unsigned offset, unsigned length)
{
	const char *str = fv->value.strbuf->str;

	/* Go to the starting offset */
	const char *p = g_utf8_offset_to_pointer(str, (long)offset);
	const char *n;
	/* Copy 'length' codepoints to dst. Skip the terminating NULL */
	while (*p != '\0' && length-- > 0) {
		n = g_utf8_next_char(p);
		/* Append n - p bytes (one codepoint)*/
		wmem_strbuf_append_len(buf, p, n - p);
		p = n;
	}
}

static enum ft_result
cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
	*cmp = wmem_strbuf_strcmp(a->value.strbuf, b->value.strbuf);
	return FT_OK;
}

static enum ft_result
cmp_contains(const fvalue_t *fv_a, const fvalue_t *fv_b, bool *contains)
{
	/* According to
	* http://www.introl.com/introl-demo/Libraries/C/ANSI_C/string/strstr.html
	* strstr() returns a non-NULL value if needle is an empty
	* string. We don't that behavior for cmp_contains. */
	if (fv_b->value.strbuf->len == 0) {
		*contains = false;
		return FT_OK;
	}

	if (wmem_strbuf_strstr(fv_a->value.strbuf, fv_b->value.strbuf)) {
		*contains = true;
	}
	else {
		*contains = false;
	}

	return FT_OK;
}

static enum ft_result
cmp_matches(const fvalue_t *fv, const ws_regex_t *regex, bool *matches)
{
	wmem_strbuf_t *buf = fv->value.strbuf;

	if (regex == NULL) {
		return FT_BADARG;
	}

	*matches = ws_regex_matches_length(regex, buf->str, buf->len);
	return FT_OK;
}

static bool
ax25_from_string(fvalue_t *fv, const char *s, size_t len, char **err_msg _U_)
{
	/* See section 3.12 "Address-Field Encoding" of the AX.25
	 * spec and
	 *
	 *   http://www.itu.int/ITU-R/terrestrial/docs/fixedmobile/fxm-art19-sec3.pdf
	 */

	if (len == 0)
		len = strlen(s);

	const char *end = s + len;
	const char *hyphen = strchr(s, '-');
	if (hyphen == NULL) {
		hyphen = end;
	}

	if (s == hyphen || (hyphen - s) > 6) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid AX.25 address, the callsign must be 1-6 alphanumeric ASCII characters.", s);
		return false;
	}
	const char *p;
	for (p = s; p != hyphen; p++) {
		if (!g_ascii_isalnum(*p)) {
			if (err_msg != NULL)
				*err_msg = ws_strdup_printf("\"%s\" is not a valid AX.25 address, the callsign must be alphanumeric ASCII characters.", s);
			return false;
		}
	}
	uint8_t ssid = 0;
	if (hyphen != end) {
		if (!ws_strtou8(hyphen + 1, NULL, &ssid)) {
			if (err_msg != NULL)
				*err_msg = ws_strdup_printf("\"%s\" is not a valid AX.25 SSID (must be a number between 0 and 15).", hyphen + 1);
			return false;
		}
		if (ssid > 15) {
			if (err_msg != NULL)
				*err_msg = ws_strdup_printf("%u is too large to be an AX.25 SSID (must be between 0 and 15)", ssid);
			return false;
		}
	}

	/* OK, it looks valid. Allow the user to enter lower-case letters. */
	char *str = g_ascii_strup(s, len);
	bool ret = val_from_string(fv, str, len, err_msg);
	g_free(str);
	return ret;
}

static bool
ax25_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
	return ax25_from_string(fv, s, 0, err_msg);
}

void
ftype_register_string(void)
{

	static const ftype_t string_type = {
		FT_STRING,			/* ftype */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		NULL,				/* val_from_uinteger64 */
		NULL,				/* val_from_sinteger64 */
		NULL,				/* val_from_double */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_to_double */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,
		cmp_matches,

		string_hash,			/* hash */
		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		(FvalueSlice)slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static const ftype_t stringz_type = {
		FT_STRINGZ,			/* ftype */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		NULL,				/* val_from_uinteger64 */
		NULL,				/* val_from_sinteger64 */
		NULL,				/* val_from_double */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_to_double */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,			/* cmp_contains */
		cmp_matches,

		string_hash,			/* hash */
		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		(FvalueSlice)slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static const ftype_t uint_string_type = {
		FT_UINT_STRING,		/* ftype */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		NULL,				/* val_from_uinteger64 */
		NULL,				/* val_from_sinteger64 */
		NULL,				/* val_from_double */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_to_double */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,			/* cmp_contains */
		cmp_matches,

		string_hash,			/* hash */
		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		(FvalueSlice)slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static const ftype_t stringzpad_type = {
		FT_STRINGZPAD,			/* ftype */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		NULL,				/* val_from_uinteger64 */
		NULL,				/* val_from_sinteger64 */
		NULL,				/* val_from_double */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_to_double */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,			/* cmp_contains */
		cmp_matches,

		string_hash,			/* hash */
		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		(FvalueSlice)slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static const ftype_t stringztrunc_type = {
		FT_STRINGZTRUNC,		/* ftype */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		NULL,				/* val_from_uinteger64 */
		NULL,				/* val_from_sinteger64 */
		NULL,				/* val_from_double */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_to_double */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,			/* cmp_contains */
		cmp_matches,

		string_hash,			/* hash */
		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		(FvalueSlice)slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static const ftype_t ax25_type = {
		FT_AX25,			/* ftype */
		FT_AX25_ADDR_LEN,		/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		ax25_from_literal,		/* val_from_literal */
		ax25_from_string,		/* val_from_string */
		NULL,				/* val_from_charconst */
		NULL,				/* val_from_uinteger64 */
		NULL,				/* val_from_sinteger64 */
		NULL,				/* val_from_double */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_to_double */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,
		cmp_matches,

		string_hash,			/* hash */
		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		(FvalueSlice)slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};


	ftype_register(FT_STRING, &string_type);
	ftype_register(FT_STRINGZ, &stringz_type);
	ftype_register(FT_UINT_STRING, &uint_string_type);
	ftype_register(FT_STRINGZPAD, &stringzpad_type);
	ftype_register(FT_STRINGZTRUNC, &stringztrunc_type);
	ftype_register(FT_AX25, &ax25_type);
}

void
ftype_register_pseudofields_string(int proto)
{
	static int hf_ft_string;
	static int hf_ft_stringz;
	static int hf_ft_uint_string;
	static int hf_ft_stringzpad;
	static int hf_ft_stringztrunc;
	static int hf_ft_ax25;

	static hf_register_info hf_ftypes[] = {
		{ &hf_ft_string,
		    { "FT_STRING", "_ws.ftypes.string",
			FT_STRING, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_stringz,
		    { "FT_STRINGZ", "_ws.ftypes.stringz",
			FT_STRINGZ, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint_string,
		    { "FT_UINT_STRING", "_ws.ftypes.uint_string",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_stringzpad,
		    { "FT_STRINGZPAD", "_ws.ftypes.stringzpad",
			FT_STRINGZPAD, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_stringztrunc,
		    { "FT_STRINGZTRUNC", "_ws.ftypes.stringztrunc",
			FT_STRINGZTRUNC, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
                { &hf_ft_ax25,
                    { "FT_AX25", "_ws.ftypes.ax25",
                        FT_AX25, BASE_NONE, NULL, 0x00,
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
