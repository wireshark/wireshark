/*
 * $Id: ftype-time.c,v 1.5 2001/05/31 06:20:10 guy Exp $
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
	char    *curptr, *endptr;

	curptr = s;

	/*
	 * If it doesn't begin with ".", it should contain a seconds
	 * value.
	 */
	if (*curptr != '.') {
		/*
		 * Get the seconds value.
		 */
		fv->value.time.tv_sec = strtoul(curptr, &endptr, 10);
		if (endptr == curptr || (*endptr != '\0' && *endptr != '.')) {
			if (log != NULL)
				log("\"%s\" is not a valid time.", s);
			return FALSE;
		}
		curptr = endptr;
		if (*curptr == '.')
			curptr++;	/* skip the decimal point */
	} else {
		/*
		 * No seconds value - it's 0.
		 */
		fv->value.time.tv_sec = 0;
		curptr++;		/* skip the decimal point */
	}

	/*
	 * If there's more stuff left in the string, it should be the
	 * microseconds value.
	 */
	if (*endptr != '\0') {
		/*
		 * Get the microseconds value.
		 */
		fv->value.time.tv_usec = strtoul(curptr, &endptr, 10);
		if (endptr == curptr || *endptr != '\0') {
			if (log != NULL)
				log("\"%s\" is not a valid time.", s);
			return FALSE;
		}
	} else {
		/*
		 * No microseconds value - it's 0.
		 */
		fv->value.time.tv_usec = 0;
	}

	/*
	 * XXX - what about negative values?
	 */
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
