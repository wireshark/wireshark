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
	fv->value.string = NULL;
}

static void
string_fvalue_copy(fvalue_t *dst, const fvalue_t *src)
{
	dst->value.string = g_strdup(src->value.string);
}

static void
string_fvalue_free(fvalue_t *fv)
{
	g_free(fv->value.string);
}

static void
string_fvalue_set_string(fvalue_t *fv, const gchar *value)
{
	DISSECTOR_ASSERT(value != NULL);

	/* Free up the old value, if we have one */
	string_fvalue_free(fv);

	fv->value.string = (gchar *)g_strdup(value);
}

static char *
string_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display _U_)
{
	if (rtype == FTREPR_DISPLAY) {
		return wmem_strdup(scope, fv->value.string);
	}
	if (rtype == FTREPR_DFILTER) {
		return ws_escape_string(scope, fv->value.string, TRUE);
	}
	ws_assert_not_reached();
}


static const char *
value_get(fvalue_t *fv)
{
	return fv->value.string;
}

static gboolean
val_from_string(fvalue_t *fv, const char *s, gchar **err_msg _U_)
{
	/* Free up the old value, if we have one */
	string_fvalue_free(fv);

	fv->value.string = g_strdup(s);
	return TRUE;
}

static gboolean
val_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	/* Just turn it into a string */
	/* XXX Should probably be a syntax error instead. It's more user-friendly to ask the
	 * user to be explicit about the meaning of an unquoted literal than them trying to figure out
	 * why a valid filter expression is giving wrong results. */
	return val_from_string(fv, s, err_msg);
}

static gboolean
val_from_charconst(fvalue_t *fv, unsigned long num, gchar **err_msg)
{
	/* XXX Should be a syntax error if literal is also a syntax error. */

	/* Free up the old value, if we have one */
	string_fvalue_free(fv);
	fv->value.string = NULL;

	if (num > UINT8_MAX) {
		if (err_msg) {
			*err_msg = ws_strdup_printf("%lu is too large for a byte value", num);
		}
		return FALSE;
	}

	char c = (char)num;
	fv->value.string = g_malloc(2);
	fv->value.string[0] = c;
	fv->value.string[1] = '\0';

	return TRUE;
}

static gboolean
string_is_zero(const fvalue_t *fv)
{
	return fv->value.string == NULL || strlen(fv->value.string) == 0;
}

static guint
len(fvalue_t *fv)
{
	return (guint)strlen(fv->value.string);
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	guint8* data;

	data = fv->value.ustring + offset;

	g_byte_array_append(bytes, data, length);
}

static int
cmp_order(const fvalue_t *a, const fvalue_t *b)
{
	return strcmp(a->value.string, b->value.string);
}

static gboolean
cmp_contains(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	/* According to
	* http://www.introl.com/introl-demo/Libraries/C/ANSI_C/string/strstr.html
	* strstr() returns a non-NULL value if needle is an empty
	* string. We don't that behavior for cmp_contains. */
	if (strlen(fv_b->value.string) == 0) {
		return FALSE;
	}

	if (strstr(fv_a->value.string, fv_b->value.string)) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

static gboolean
cmp_matches(const fvalue_t *fv, const ws_regex_t *regex)
{
	char *str = fv->value.string;

	if (! regex) {
		return FALSE;
	}
	return ws_regex_matches(regex, str);
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

		{ .set_value_string = string_fvalue_set_string },	/* union set_value */
		{ .get_value_string = value_get },	/* union get_value */

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

		{ .set_value_string = string_fvalue_set_string },	/* union set_value */
		{ .get_value_string = value_get },	/* union get_value */

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

		{ .set_value_string = string_fvalue_set_string },	/* union set_value */
		{ .get_value_string = value_get },	/* union get_value */

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

		{ .set_value_string = string_fvalue_set_string },	/* union set_value */
		{ .get_value_string = value_get },	/* union get_value */

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

		{ .set_value_string = string_fvalue_set_string },	/* union set_value */
		{ .get_value_string = value_get },	/* union get_value */

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
