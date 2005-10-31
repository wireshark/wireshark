/*
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ftypes-int.h>
#include <string.h>

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#define CMP_MATCHES cmp_matches
#else
#define CMP_MATCHES NULL
#endif

#define tvb_is_private	fvalue_gboolean1

static void
value_new(fvalue_t *fv)
{
	fv->value.tvb = NULL;
	fv->tvb_is_private = FALSE;
}

static void
value_free(fvalue_t *fv)
{
	if (fv->value.tvb && fv->tvb_is_private) {
		tvb_free_chain(fv->value.tvb);
	}
}

static void
value_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(already_copied);

	/* Free up the old value, if we have one */
	value_free(fv);

	fv->value.tvb = value;
}

static void
free_tvb_data(void *data)
{
	g_free(data);
}

static gboolean
val_from_string(fvalue_t *fv, char *s, LogFunc logfunc _U_)
{
	tvbuff_t *new_tvb;
	guint8 *private_data;

	/* Free up the old value, if we have one */
	value_free(fv);

	/* Make a tvbuff from the string. We can drop the
	 * terminating NUL. */
	private_data = g_memdup(s, strlen(s)); 
	new_tvb = tvb_new_real_data(private_data, 
			strlen(s), strlen(s));

	/* Let the tvbuff know how to delete the data. */
	tvb_set_free_cb(new_tvb, free_tvb_data);

	/* And let us know that we need to free the tvbuff */
	fv->tvb_is_private = TRUE;
	fv->value.tvb = new_tvb;
	return TRUE;
}

static gboolean
val_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	fvalue_t *fv_bytes;
	tvbuff_t *new_tvb;
	guint8 *private_data;

	/* Free up the old value, if we have one */
	value_free(fv);

	/* Does this look like a byte string? */
	fv_bytes = fvalue_from_unparsed(FT_BYTES, s, TRUE, NULL);
	if (fv_bytes) {
		/* Make a tvbuff from the bytes */
		private_data = g_memdup(fv_bytes->value.bytes->data,
				fv_bytes->value.bytes->len);
		new_tvb = tvb_new_real_data(private_data, 
				fv_bytes->value.bytes->len,
				fv_bytes->value.bytes->len);

		/* Let the tvbuff know how to delete the data. */
		tvb_set_free_cb(new_tvb, free_tvb_data);

		/* And let us know that we need to free the tvbuff */
		fv->tvb_is_private = TRUE;
		fv->value.tvb = new_tvb;
		return TRUE;
	}
	else {
		/* Treat it as a string. */
		return val_from_string(fv, s, logfunc);
	}
	g_assert_not_reached();
}

static int
val_repr_len(fvalue_t *fv, ftrepr_t rtype)
{
	guint length;

	g_assert(rtype == FTREPR_DFILTER);
	length = tvb_length(fv->value.tvb);
	/* 3 bytes for each byte of the byte "NN:" minus 1 byte
	 * as there's no trailing ":". */
	return length * 3 - 1;
}

static void
val_to_repr(fvalue_t *fv, ftrepr_t rtype, char *buf)
{
	guint length;
	const guint8 *c;
	char *write_cursor;
	unsigned int i;

	g_assert(rtype == FTREPR_DFILTER);
	length = tvb_length(fv->value.tvb);
	c = tvb_get_ptr(fv->value.tvb, 0, length);
	write_cursor = buf;

	for (i = 0; i < length; i++) {
		if (i == 0) {
			sprintf(write_cursor, "%02x", *c++);
			write_cursor += 2;
		}
		else {
			sprintf(write_cursor, ":%02x", *c++);
			write_cursor += 3;
		}
	}
}

static gpointer
value_get(fvalue_t *fv)
{
	return fv->value.tvb;
}

static guint
len(fvalue_t *fv)
{
	if (fv->value.tvb)
		return tvb_length(fv->value.tvb);
	else
		return 0;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	const guint8* data;

	if (fv->value.tvb) {
		TRY {
			data = tvb_get_ptr(fv->value.tvb, offset, length);
			g_byte_array_append(bytes, data, length);
		}
		CATCH_ALL {
			/* nothing */
		}
		ENDTRY;

	}
}

static gboolean
cmp_contains(fvalue_t *fv_a, fvalue_t *fv_b)
{
	if (tvb_find_tvb(fv_a->value.tvb, fv_b->value.tvb, 0) > -1) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

#ifdef HAVE_LIBPCRE
static gboolean
cmp_matches(fvalue_t *fv_a, fvalue_t *fv_b)
{
	tvbuff_t *tvb = fv_a->value.tvb;
	pcre_tuple_t *pcre = fv_b->value.re;
	int options = 0;
	volatile int rc = 1;
	const char *data = NULL; /* tvb data */
	guint32 tvb_len; /* tvb length */

	/* fv_b is always a FT_PCRE, otherwise the dfilter semcheck() would have
	 * warned us. For the same reason (and because we're using g_malloc()),
	 * fv_b->value.re is not NULL.
	 */
	if (strcmp(fv_b->ftype->name, "FT_PCRE") != 0) {
		return FALSE;
	}
	if (! pcre) {
		return FALSE;
	}
	TRY {
		tvb_len = tvb_length(tvb);
		data = (const char *)tvb_get_ptr(tvb, 0, tvb_len);
		rc = pcre_exec(
			pcre->re,	/* Compiled PCRE */
			pcre->ex,	/* PCRE extra from pcre_study() */
			data,		/* The data to check for the pattern... */
			tvb_len,	/* ... and its length */
			0,		/* Start offset within data */
			options,	/* PCRE options */
			NULL,		/* We are not interested in the matched string */
			0		/* of the pattern; only in success or failure. */
			);
		/* NOTE - DO NOT g_free(data) */
	}
	CATCH_ALL {
		return FALSE;
	}
	ENDTRY;
	if (rc == 0) {
		return TRUE;
	}
	return FALSE;
}
#endif

void
ftype_register_tvbuff(void)
{

	static ftype_t protocol_type = {
		"FT_PROTOCOL",			/* name */
		"protocol",			/* pretty_name */
		0,				/* wire_size */
		value_new,			/* new_value */
		value_free,			/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		val_from_string,		/* val_from_string */
		val_to_repr,			/* val_to_string_repr */
		val_repr_len,			/* len_string_repr */

		value_set,			/* set_value */
		NULL,				/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */


		/* TODO - tvb's *can* do 'eq', etc. */

		NULL,				/* cmp_eq */
		NULL,				/* cmp_ne */
		NULL,				/* cmp_gt */
		NULL,				/* cmp_ge */
		NULL,				/* cmp_lt */
		NULL,				/* cmp_le */
		NULL,				/* cmp_bitwise_and */
		cmp_contains,
		CMP_MATCHES,

		len,
		slice,

	};


	ftype_register(FT_PROTOCOL, &protocol_type);
}
