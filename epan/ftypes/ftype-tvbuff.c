/*
 * $Id: ftype-tvbuff.c,v 1.12 2003/10/29 23:48:14 guy Exp $
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
#include <epan/gdebug.h>

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
		NULL,				/* val_to_string_repr */
		NULL,				/* len_string_repr */

		value_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		cmp_contains,			/* cmp_contains */

		len,
		slice,

	};


	ftype_register(FT_PROTOCOL, &protocol_type);
}
