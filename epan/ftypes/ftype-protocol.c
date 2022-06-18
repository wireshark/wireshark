/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ftypes-int.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <string.h>
#include <wsutil/glib-compat.h>

#include <epan/exceptions.h>
#include <wsutil/ws_assert.h>

static void
value_new(fvalue_t *fv)
{
	fv->value.protocol.tvb = NULL;
	fv->value.protocol.proto_string = NULL;
	fv->value.protocol.tvb_is_private = FALSE;
	fv->value.protocol.length = -1;
}

static void
value_copy(fvalue_t *dst, const fvalue_t *src)
{
	dst->value.protocol.tvb = tvb_clone(src->value.protocol.tvb);
	dst->value.protocol.proto_string = g_strdup(src->value.protocol.proto_string);
	dst->value.protocol.tvb_is_private = TRUE;
	dst->value.protocol.length = src->value.protocol.length;
}

static void
value_free(fvalue_t *fv)
{
	if (fv->value.protocol.tvb && fv->value.protocol.tvb_is_private) {
		tvb_free_chain(fv->value.protocol.tvb);
	}
	g_free(fv->value.protocol.proto_string);
}

static void
value_set(fvalue_t *fv, tvbuff_t *value, const gchar *name, int length)
{
	if (value != NULL) {
		/* Free up the old value, if we have one */
		value_free(fv);

		/* Set the protocol description and an (optional, nullable) tvbuff. */
		fv->value.protocol.tvb = value;
		fv->value.protocol.proto_string = g_strdup(name);
	}
	fv->value.protocol.length = length;
}

static gboolean
val_from_string(fvalue_t *fv, const char *s, gchar **err_msg _U_)
{
	tvbuff_t *new_tvb;
	guint8 *private_data;

	/* Free up the old value, if we have one */
	value_free(fv);

	/* Make a tvbuff from the string. We can drop the
	 * terminating NUL. */
	private_data = (guint8 *)g_memdup2(s, (guint)strlen(s));
	new_tvb = tvb_new_real_data(private_data,
			(guint)strlen(s), (gint)strlen(s));

	/* Let the tvbuff know how to delete the data. */
	tvb_set_free_cb(new_tvb, g_free);

	/* And let us know that we need to free the tvbuff */
	fv->value.protocol.tvb_is_private = TRUE;
	/* This "field" is a value, it has no protocol description, but
	 * we might compare it to a protocol with NULL tvb.
	 * (e.g., proto_expert) */
	fv->value.protocol.tvb = new_tvb;
	fv->value.protocol.proto_string = g_strdup("");
	fv->value.protocol.length = -1;
	return TRUE;
}

static gboolean
val_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	GByteArray *bytes;
	tvbuff_t *new_tvb;

	/* Free up the old value, if we have one */
	value_free(fv);
	fv->value.protocol.tvb = NULL;
	fv->value.protocol.proto_string = NULL;
	fv->value.protocol.length = -1;

	/* Does this look like a byte string? */
	bytes = byte_array_from_literal(s, err_msg);
	if (bytes != NULL) {
		/* Make a tvbuff from the bytes */
		new_tvb = tvb_new_real_data(bytes->data, bytes->len, bytes->len);

		/* Let the tvbuff know how to delete the data. */
		tvb_set_free_cb(new_tvb, g_free);

		/* Free GByteArray, but keep data. */
		g_byte_array_free(bytes, FALSE);

		/* And let us know that we need to free the tvbuff */
		fv->value.protocol.tvb_is_private = TRUE;
		fv->value.protocol.tvb = new_tvb;

		/* This "field" is a value, it has no protocol description, but
		 * we might compare it to a protocol with NULL tvb.
		 * (e.g., proto_expert) */
		fv->value.protocol.proto_string = g_strdup("");
		return TRUE;
	}

	/* Not a byte array, forget about it. */
	return FALSE;
}

static gboolean
val_from_charconst(fvalue_t *fv, unsigned long num, gchar **err_msg)
{
	GByteArray *bytes;
	tvbuff_t *new_tvb;

	/* Free up the old value, if we have one */
	value_free(fv);
	fv->value.protocol.tvb = NULL;
	fv->value.protocol.proto_string = NULL;
	fv->value.protocol.length = -1;

	/* Does this look like a byte string? */
	bytes = byte_array_from_charconst(num, err_msg);
	if (bytes != NULL) {
		/* Make a tvbuff from the bytes */
		new_tvb = tvb_new_real_data(bytes->data, bytes->len, bytes->len);

		/* Let the tvbuff know how to delete the data. */
		tvb_set_free_cb(new_tvb, g_free);

		/* Free GByteArray, but keep data. */
		g_byte_array_free(bytes, FALSE);

		/* And let us know that we need to free the tvbuff */
		fv->value.protocol.tvb_is_private = TRUE;
		fv->value.protocol.tvb = new_tvb;

		/* This "field" is a value, it has no protocol description, but
		 * we might compare it to a protocol with NULL tvb.
		 * (e.g., proto_expert) */
		fv->value.protocol.proto_string = g_strdup("");
		return TRUE;
	}

	/* Not a byte array, forget about it. */
	return FALSE;
}

static char *
val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	guint length;
	char *volatile buf = NULL;

	if (rtype != FTREPR_DFILTER)
		return NULL;

	TRY {
		if (fv->value.protocol.length >= 0)
			length = fv->value.protocol.length;
		else
			length = tvb_captured_length(fv->value.protocol.tvb);

		if (length)
			buf = bytes_to_str_punct_maxlen(scope, tvb_get_ptr(fv->value.protocol.tvb, 0, length), length, ':', 0);
	}
	CATCH_ALL {
		/* nothing */
	}
	ENDTRY;
	return buf;
}

static tvbuff_t *
value_get(fvalue_t *fv)
{
	if (fv->value.protocol.length < 0)
		return fv->value.protocol.tvb;
	return tvb_new_subset_length_caplen(fv->value.protocol.tvb, 0, fv->value.protocol.length, fv->value.protocol.length);
}

static guint
len(fvalue_t *fv)
{
	volatile guint length = 0;

	TRY {
		if (fv->value.protocol.tvb) {
			if (fv->value.protocol.length >= 0)
				length = fv->value.protocol.length;
			else
				length = tvb_captured_length(fv->value.protocol.tvb);

		}
	}
	CATCH_ALL {
		/* nothing */
	}
	ENDTRY;

	return length;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	const guint8* data;
	volatile guint len = length;

	if (fv->value.protocol.tvb) {
		if (fv->value.protocol.length >= 0 && (guint)fv->value.protocol.length < len) {
			len = fv->value.protocol.length;
		}

		TRY {
			data = tvb_get_ptr(fv->value.protocol.tvb, offset, len);
			g_byte_array_append(bytes, data, len);
		}
		CATCH_ALL {
			/* nothing */
		}
		ENDTRY;

	}
}

static int
_tvbcmp(const protocol_value_t *a, const protocol_value_t *b)
{
	guint	a_len;
	guint	b_len;

	if (a->length < 0)
		a_len = tvb_captured_length(a->tvb);
	else
		a_len = a->length;

	if (b->length < 0)
		b_len = tvb_captured_length(b->tvb);
	else
		b_len = b->length;

	if (a_len != b_len)
		return a_len < b_len ? -1 : 1;
	return memcmp(tvb_get_ptr(a->tvb, 0, a_len), tvb_get_ptr(b->tvb, 0, a_len), a_len);
}

static int
cmp_order(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	const protocol_value_t	*a = (const protocol_value_t *)&fv_a->value.protocol;
	const protocol_value_t	*b = (const protocol_value_t *)&fv_b->value.protocol;
	volatile int		c = 0;

	TRY {
		if ((a->tvb != NULL) && (b->tvb != NULL)) {
			c = _tvbcmp(a, b);
		} else {
			c = strcmp(a->proto_string, b->proto_string);
		}
	}
	CATCH_ALL {
		/* nothing */
	}
	ENDTRY;

	return c;
}

static gboolean
cmp_contains(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	volatile gboolean contains = FALSE;

	TRY {
		/* First see if tvb exists for both sides */
		if ((fv_a->value.protocol.tvb != NULL) && (fv_b->value.protocol.tvb != NULL)) {
			if (tvb_find_tvb(fv_a->value.protocol.tvb, fv_b->value.protocol.tvb, 0) > -1) {
				contains = TRUE;
			}
		} else {
			/* Otherwise just compare strings */
			if ((strlen(fv_b->value.protocol.proto_string) != 0) &&
				strstr(fv_a->value.protocol.proto_string, fv_b->value.protocol.proto_string)) {
				contains = TRUE;
			}
		}
	}
	CATCH_ALL {
		/* nothing */
	}
	ENDTRY;

	return contains;
}

static gboolean
cmp_matches(const fvalue_t *fv, const ws_regex_t *regex)
{
	const protocol_value_t *a = (const protocol_value_t *)&fv->value.protocol;
	volatile gboolean rc = FALSE;
	const char *data = NULL; /* tvb data */
	guint32 tvb_len; /* tvb length */

	if (! regex) {
		return FALSE;
	}
	TRY {
		if (a->tvb != NULL) {
			tvb_len = tvb_captured_length(a->tvb);
			data = (const char *)tvb_get_ptr(a->tvb, 0, tvb_len);
			rc = ws_regex_matches_length(regex, data, tvb_len);
		} else {
			rc = ws_regex_matches(regex, a->proto_string);
		}
	}
	CATCH_ALL {
		rc = FALSE;
	}
	ENDTRY;
	return rc;
}

static gboolean
is_zero(const fvalue_t *fv)
{
	const protocol_value_t *a = &fv->value.protocol;
	return a->tvb == NULL && a->proto_string == NULL;
}

void
ftype_register_tvbuff(void)
{

	static ftype_t protocol_type = {
		FT_PROTOCOL,			/* ftype */
		"FT_PROTOCOL",			/* name */
		"Protocol",			/* pretty_name */
		0,				/* wire_size */
		value_new,			/* new_value */
		value_copy,			/* copy_value */
		value_free,			/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		val_to_repr,			/* val_to_string_repr */

		{ .set_value_protocol = value_set },	/* union set_value */
		{ .get_value_protocol = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,
		cmp_matches,

		is_zero,
		NULL,
		len,
		slice,
		NULL,
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};


	ftype_register(FT_PROTOCOL, &protocol_type);
}

void
ftype_register_pseudofields_tvbuff(int proto)
{
	static int hf_ft_protocol;

	static hf_register_info hf_ftypes[] = {
		{ &hf_ft_protocol,
		    { "FT_PROTOCOL", "_ws.ftypes.protocol",
			FT_PROTOCOL, BASE_NONE, NULL, 0x00,
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
