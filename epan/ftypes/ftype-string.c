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
	if (rtype == FTREPR_DISPLAY) {
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

static gboolean
val_from_string(fvalue_t *fv, const char *s, size_t len, gchar **err_msg _U_)
{
	/* Free up the old value, if we have one */
	string_fvalue_free(fv);

	if (len > 0)
		fv->value.strbuf = wmem_strbuf_new_len(NULL, s, len);
	else
		fv->value.strbuf = wmem_strbuf_new(NULL, s);
	return TRUE;
}

static gboolean
val_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg _U_)
{
	/* Just turn it into a string */
	/* XXX Should probably be a syntax error instead. It's more user-friendly to ask the
	 * user to be explicit about the meaning of an unquoted literal than them trying to figure out
	 * why a valid filter expression is giving wrong results. */
	string_fvalue_free(fv);

	fv->value.strbuf = wmem_strbuf_new(NULL, s);
	return TRUE;
}

static gboolean
val_from_charconst(fvalue_t *fv, unsigned long num, gchar **err_msg)
{
	/* XXX Should be a syntax error if literal is also a syntax error. */

	/* Free up the old value, if we have one */
	string_fvalue_free(fv);
	fv->value.strbuf = NULL;

	if (num > UINT8_MAX) {
		if (err_msg) {
			*err_msg = ws_strdup_printf("%lu is too large for a byte value", num);
		}
		return FALSE;
	}

	char c = (char)num;
	fv->value.strbuf = wmem_strbuf_new(NULL, NULL);
	wmem_strbuf_append_c(fv->value.strbuf, c);

	return TRUE;
}

static gboolean
string_is_zero(const fvalue_t *fv)
{
	return fv->value.strbuf == NULL || fv->value.strbuf->len == 0;
}

static guint
len(fvalue_t *fv)
{
	return (guint)fv->value.strbuf->len;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	guint8* data;

	data = (guint8*)fv->value.strbuf->str + offset;

	g_byte_array_append(bytes, data, length);
}

static enum ft_result
cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
	*cmp = wmem_strbuf_strcmp(a->value.strbuf, b->value.strbuf);
	return FT_OK;
}

static enum ft_result
cmp_contains(const fvalue_t *fv_a, const fvalue_t *fv_b, gboolean *contains)
{
	/* According to
	* http://www.introl.com/introl-demo/Libraries/C/ANSI_C/string/strstr.html
	* strstr() returns a non-NULL value if needle is an empty
	* string. We don't that behavior for cmp_contains. */
	if (fv_b->value.strbuf->len == 0) {
		*contains = FALSE;
		return FT_OK;
	}

	if (wmem_strbuf_strstr(fv_a->value.strbuf, fv_b->value.strbuf)) {
		*contains = TRUE;
	}
	else {
		*contains = FALSE;
	}

	return FT_OK;
}

static enum ft_result
cmp_matches(const fvalue_t *fv, const ws_regex_t *regex, gboolean *matches)
{
	wmem_strbuf_t *buf = fv->value.strbuf;

	if (regex == NULL) {
		return FT_BADARG;
	}

	*matches = ws_regex_matches_length(regex, buf->str, buf->len);
	return FT_OK;
}

void
ftype_register_string(void)
{

	static ftype_t string_type = {
		FT_STRING,			/* ftype */
		"FT_STRING",			/* name */
		"Character string",		/* pretty_name */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,
		cmp_matches,

		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static ftype_t stringz_type = {
		FT_STRINGZ,			/* ftype */
		"FT_STRINGZ",			/* name */
		"Character string",		/* pretty name */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,			/* cmp_contains */
		cmp_matches,

		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static ftype_t uint_string_type = {
		FT_UINT_STRING,		/* ftype */
		"FT_UINT_STRING",		/* name */
		"Character string",		/* pretty_name */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,			/* cmp_contains */
		cmp_matches,

		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static ftype_t stringzpad_type = {
		FT_STRINGZPAD,			/* ftype */
		"FT_STRINGZPAD",		/* name */
		"Character string",		/* pretty name */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,			/* cmp_contains */
		cmp_matches,

		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		slice,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static ftype_t stringztrunc_type = {
		FT_STRINGZTRUNC,		/* ftype */
		"FT_STRINGZTRUNC",		/* name */
		"Character string",		/* pretty name */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_copy,		/* copy_value */
		string_fvalue_free,		/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		string_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */

		{ .set_value_strbuf = string_fvalue_set_strbuf },	/* union set_value */
		{ .get_value_strbuf = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,			/* cmp_contains */
		cmp_matches,

		string_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		len,
		slice,
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
}

void
ftype_register_pseudofields_string(int proto)
{
	static int hf_ft_string;
	static int hf_ft_stringz;
	static int hf_ft_uint_string;
	static int hf_ft_stringzpad;
	static int hf_ft_stringztrunc;

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
