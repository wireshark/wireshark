/*
 * $Id: ftype-time.c,v 1.4 2001/05/31 05:01:06 guy Exp $
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

#include <time.h>

#include <ftypes-int.h>

static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
	return ((a->value.time.tv_sec) ==(b->value.time.tv_sec))
	     &&((a->value.time.tv_usec)==(b->value.time.tv_usec));
}
static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
	return (a->value.time.tv_sec !=b->value.time.tv_sec)
	     ||(a->value.time.tv_usec!=b->value.time.tv_usec);
}
static gboolean
cmp_gt(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.tv_sec > b->value.time.tv_sec) {
		return TRUE;
	}
	if (a->value.time.tv_sec < b->value.time.tv_sec) {
		return FALSE;
	}

	return a->value.time.tv_usec > b->value.time.tv_usec;
}
static gboolean
cmp_ge(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.tv_sec > b->value.time.tv_sec) {
		return TRUE;
	}
	if (a->value.time.tv_sec < b->value.time.tv_sec) {
		return FALSE;
	}

	return a->value.time.tv_usec >= b->value.time.tv_usec;
}
static gboolean
cmp_lt(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.tv_sec < b->value.time.tv_sec) {
		return TRUE;
	}
	if (a->value.time.tv_sec > b->value.time.tv_sec) {
		return FALSE;
	}

	return a->value.time.tv_usec < b->value.time.tv_usec;
}
static gboolean
cmp_le(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.tv_sec < b->value.time.tv_sec) {
		return TRUE;
	}
	if (a->value.time.tv_sec > b->value.time.tv_sec) {
		return FALSE;
	}

	return a->value.time.tv_usec <= b->value.time.tv_usec;
}


static gboolean
relative_val_from_string(fvalue_t *fv, char *s, LogFunc log)
{

	if (sscanf(s,"%lu.%lu",&fv->value.time.tv_sec,&fv->value.time.tv_usec)!=2) {
		log("\"%s\" is not a valid relative time. Use \"<seconds>.<useconds>\"",s);
		return FALSE;
	}

	return TRUE;
}


static gboolean
absolute_val_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	struct tm tm;
	char *str;
	str=strptime(s,"%b %d, %Y %H:%M:%S.",&tm);
	if (!str) {
		log("\"%s\" is not a valid absolute time. Example: \"Nov 12, 1999 08:55:44.123\"",s);
		return FALSE;
	}
	fv->value.time.tv_sec = mktime(&tm);
	sscanf(str,"%lu",&fv->value.time.tv_usec);
	return TRUE;
}

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
		absolute_val_from_string,

		time_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
	};
	static ftype_t reltime_type = {
		"FT_RELATIVE_TIME",
		"time offset",
		0,
		time_fvalue_new,
		NULL,
		relative_val_from_string,

		time_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
	};

	ftype_register(FT_ABSOLUTE_TIME, &abstime_type);
	ftype_register(FT_RELATIVE_TIME, &reltime_type);
}
