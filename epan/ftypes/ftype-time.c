/*
 * $Id: ftype-time.c,v 1.3 2001/03/02 17:17:56 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
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


static void
time_fvalue_new(fvalue_t *fv)
{
	fv->value.time.tv_sec = 0;
	fv->value.time.tv_usec = 0;
}

static void
time_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(!already_copied);
	memcpy(&(fv->value.time), value, sizeof(struct timeval));
}

static gpointer
value_get(fvalue_t *fv)
{
	return &(fv->value.time);
}

void
ftype_register_time(void)
{

	static ftype_t abstime_type = {
		"FT_ABSOLUTE_TIME",
		"date/time",
		0,
		time_fvalue_new,
		NULL,
		NULL,

		time_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL
	};
	static ftype_t reltime_type = {
		"FT_RELATIVE_TIME",
		"time offset",
		0,
		time_fvalue_new,
		NULL,
		NULL,

		time_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL
	};

	ftype_register(FT_ABSOLUTE_TIME, &abstime_type);
	ftype_register(FT_RELATIVE_TIME, &reltime_type);
}
