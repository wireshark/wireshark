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

#define CMP_MATCHES cmp_matches

#define tvb_is_private	fvalue_gboolean1

static void
value_new(fvalue_t *fv)
{
	fv->value.protocol.tvb = NULL;
	fv->value.protocol.proto_string = NULL;
	fv->tvb_is_private = FALSE;
}

static void
value_free(fvalue_t *fv)
{
	if (fv->value.protocol.tvb && fv->tvb_is_private) {
		tvb_free_chain(fv->value.protocol.tvb);
	}
	g_free(fv->value.protocol.proto_string);
}

static void
value_set(fvalue_t *fv, tvbuff_t *value, const gchar *name)
{
	/* Free up the old value, if we have one */
	value_free(fv);

	/* Set the protocol description and an (optional, nullable) tvbuff. */
	fv->value.protocol.tvb = value;
	fv->value.protocol.proto_string = g_strdup(name);
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
	fv->tvb_is_private = TRUE;
	/* This "field" is a value, it has no protocol description, but
	 * we might compare it to a protocol with NULL tvb.
	 * (e.g., proto_expert) */
	fv->value.protocol.tvb = new_tvb;
	fv->value.protocol.proto_string = g_strdup("");
	return TRUE;
}

static gboolean
val_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	GByteArray *bytes;
	tvbuff_t *new_tvb;

	/* Free up the old value, if we have one */
	value_free(fv);
	fv->value.protocol.tvb = NULL;
	fv->value.protocol.proto_string = NULL;

	/* Does this look like a byte string? */
	bytes = byte_array_from_unparsed(s, err_msg);
	if (bytes != NULL) {
		/* Make a tvbuff from the bytes */
		new_tvb = tvb_new_real_data(bytes->data, bytes->len, bytes->len);

		/* Let the tvbuff know how to delete the data. */
		tvb_set_free_cb(new_tvb, g_free);

		/* Free GByteArray, but keep data. */
		g_byte_array_free(bytes, FALSE);

		/* And let us know that we need to free the tvbuff */
		fv->tvb_is_private = TRUE;
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
		fv->tvb_is_private = TRUE;
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

static gpointer
value_get(fvalue_t *fv)
{
	return fv->value.protocol.tvb;
}

static guint
len(fvalue_t *fv)
{
	volatile guint length = 0;

	TRY {
		if (fv->value.protocol.tvb)
			length = tvb_captured_length(fv->value.protocol.tvb);
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

	if (fv->value.protocol.tvb) {
		TRY {
			data = tvb_get_ptr(fv->value.protocol.tvb, offset, length);
			g_byte_array_append(bytes, data, length);
		}
		CATCH_ALL {
			/* nothing */
		}
		ENDTRY;

	}
}

static int
_tvbcmp(tvbuff_t *a, tvbuff_t *b)
{
	guint	a_len = tvb_captured_length(a);
	guint	b_len = tvb_captured_length(b);

	if (a_len != b_len)
		return a_len < b_len ? -1 : 1;
	return memcmp(tvb_get_ptr(a, 0, a_len), tvb_get_ptr(b, 0, a_len), a_len);
}

static int
cmp_order(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	const protocol_value_t	*a = (const protocol_value_t *)&fv_a->value.protocol;
	const protocol_value_t	*b = (const protocol_value_t *)&fv_b->value.protocol;
	volatile int		c = 0;

	TRY {
		if ((a->tvb != NULL) && (b->tvb != NULL)) {
			c = _tvbcmp(a->tvb, b->tvb);
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

void
ftype_register_tvbuff(void)
{

	static ftype_t protocol_type = {
		FT_PROTOCOL,			/* ftype */
		"FT_PROTOCOL",			/* name */
		"Protocol",			/* pretty_name */
		0,				/* wire_size */
		value_new,			/* new_value */
		value_free,			/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		val_to_repr,			/* val_to_string_repr */

		{ .set_value_protocol = value_set },	/* union set_value */
		{ .get_value_ptr = value_get },		/* union get_value */

		cmp_order,
		NULL,				/* cmp_bitwise_and */
		cmp_contains,
		CMP_MATCHES,

		len,
		slice,

	};


	ftype_register(FT_PROTOCOL, &protocol_type);
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
