/*
 * $Id: ftype-tvbuff.c,v 1.6 2002/01/21 07:37:39 guy Exp $
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
#include <epan/gdebug.h>

static void
value_new(fvalue_t *fv)
{
	fv->value.tvb = NULL;
}


static void
value_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(already_copied);
	fv->value.tvb = value;
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

void
ftype_register_tvbuff(void)
{

	static ftype_t protocol_type = {
		"FT_PROTOCOL",
		"protocol",
		0,
		value_new,
		NULL,
		NULL,

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

		len,
		slice,

	};


	ftype_register(FT_PROTOCOL, &protocol_type);
}
