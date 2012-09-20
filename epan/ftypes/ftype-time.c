/*
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>

/*
 * Just make sure we include the prototype for strptime as well
 * (needed for glibc 2.2) but make sure we do this only if not
 * yet defined.
 */
#ifndef __USE_XOPEN
#  define __USE_XOPEN
#endif

#include <time.h>

#include <ftypes-int.h>

#ifdef NEED_STRPTIME_H
#include "wsutil/strptime.h"
#endif

static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
	return ((a->value.time.secs) ==(b->value.time.secs))
	     &&((a->value.time.nsecs)==(b->value.time.nsecs));
}
static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
	return (a->value.time.secs !=b->value.time.secs)
	     ||(a->value.time.nsecs!=b->value.time.nsecs);
}
static gboolean
cmp_gt(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.secs > b->value.time.secs) {
		return TRUE;
	}
	if (a->value.time.secs < b->value.time.secs) {
		return FALSE;
	}

	return a->value.time.nsecs > b->value.time.nsecs;
}
static gboolean
cmp_ge(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.secs > b->value.time.secs) {
		return TRUE;
	}
	if (a->value.time.secs < b->value.time.secs) {
		return FALSE;
	}

	return a->value.time.nsecs >= b->value.time.nsecs;
}
static gboolean
cmp_lt(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.secs < b->value.time.secs) {
		return TRUE;
	}
	if (a->value.time.secs > b->value.time.secs) {
		return FALSE;
	}

	return a->value.time.nsecs < b->value.time.nsecs;
}
static gboolean
cmp_le(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.secs < b->value.time.secs) {
		return TRUE;
	}
	if (a->value.time.secs > b->value.time.secs) {
		return FALSE;
	}

	return a->value.time.nsecs <= b->value.time.nsecs;
}


/*
 * Get a nanoseconds value, starting at "p".
 *
 * Returns true on success, false on failure.
 */
static gboolean
get_nsecs(char *startp, int *nsecs)
{
	int ndigits;
	int scale;
	char *p;
	int val;
	int digit;
	int i;

	/*
	 * How many characters are in the string?
	 */
	ndigits = (int)strlen(startp);

	/*
	 * If there are N characters in the string, the last of the
	 * characters would be the digit corresponding to 10^(9-N)
	 * nanoseconds.
	 */
	scale = 9 - ndigits;

	/*
	 * Start at the last character, and work backwards.
	 */
	p = startp + ndigits;
	val = 0;
	while (p != startp) {
		p--;

		if (!isdigit((unsigned char)*p)) {
			/*
			 * Not a digit - error.
			 */
			return FALSE;
		}
		digit = *p - '0';
		if (digit != 0) {
			/*
			 * Non-zero digit corresponding to that number
			 * of (10^scale) units.
			 *
			 * If scale is less than zero, this digit corresponds
			 * to a value less than a nanosecond, so this number
			 * isn't valid.
			 */
			if (scale < 0)
				return FALSE;
			for (i = 0; i < scale; i++)
				digit *= 10;
			val += digit;
		}
		scale++;
	}
	*nsecs = val;
	return TRUE;
}

static gboolean
relative_val_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	char    *curptr, *endptr;
        gboolean negative = FALSE;

	curptr = s;

        if(*curptr == '-') {
            negative = TRUE;
            curptr++;
        }

	/*
	 * If it doesn't begin with ".", it should contain a seconds
	 * value.
	 */
	if (*curptr != '.') {
		/*
		 * Get the seconds value.
		 */
		fv->value.time.secs = strtoul(curptr, &endptr, 10);
		if (endptr == curptr || (*endptr != '\0' && *endptr != '.'))
			goto fail;
		curptr = endptr;
		if (*curptr == '.')
			curptr++;	/* skip the decimal point */
	} else {
		/*
		 * No seconds value - it's 0.
		 */
		fv->value.time.secs = 0;
		curptr++;		/* skip the decimal point */
	}

	/*
	 * If there's more stuff left in the string, it should be the
	 * nanoseconds value.
	 */
	if (*curptr != '\0') {
		/*
		 * Get the nanoseconds value.
		 */
		if (!get_nsecs(curptr, &fv->value.time.nsecs))
			goto fail;
	} else {
		/*
		 * No nanoseconds value - it's 0.
		 */
		fv->value.time.nsecs = 0;
	}

        if(negative) {
            fv->value.time.secs = -fv->value.time.secs;
            fv->value.time.nsecs = -fv->value.time.nsecs;
        }
	return TRUE;

fail:
	if (logfunc != NULL)
		logfunc("\"%s\" is not a valid time.", s);
	return FALSE;
}


static gboolean
absolute_val_from_string(fvalue_t *fv, char *s, LogFunc logfunc)
{
	struct tm tm;
	char    *curptr;

	memset(&tm, 0, sizeof(tm));
	curptr = strptime(s,"%b %d, %Y %H:%M:%S", &tm);
	if (curptr == NULL)
		curptr = strptime(s,"%Y-%m-%dT%H:%M:%S", &tm);
	if (curptr == NULL)
		curptr = strptime(s,"%Y-%m-%d %H:%M:%S", &tm);
	if (curptr == NULL)
		curptr = strptime(s,"%Y-%m-%d %H:%M", &tm);
	if (curptr == NULL)
		curptr = strptime(s,"%Y-%m-%d %H", &tm);
	if (curptr == NULL)
		curptr = strptime(s,"%Y-%m-%d", &tm);
	if (curptr == NULL)
		goto fail;
	tm.tm_isdst = -1;	/* let the computer figure out if it's DST */
	fv->value.time.secs = mktime(&tm);
	if (*curptr != '\0') {
		/*
		 * Something came after the seconds field; it must be
		 * a nanoseconds field.
		 */
		if (*curptr != '.')
			goto fail;	/* it's not */
		curptr++;	/* skip the "." */
		if (!isdigit((unsigned char)*curptr))
			goto fail;	/* not a digit, so not valid */
		if (!get_nsecs(curptr, &fv->value.time.nsecs))
			goto fail;
	} else {
		/*
		 * No nanoseconds value - it's 0.
		 */
		fv->value.time.nsecs = 0;
	}

	if (fv->value.time.secs == -1) {
		/*
		 * XXX - should we supply an error message that mentions
		 * that the time specified might be syntactically valid
		 * but might not actually have occurred, e.g. a time in
		 * the non-existent time range after the clocks are
		 * set forward during daylight savings time (or possibly
		 * that it's in the time range after the clocks are set
		 * backward, so that there are two different times that
		 * it could be)?
		 */
		goto fail;
	}

	return TRUE;

fail:
	if (logfunc != NULL)
		logfunc("\"%s\" is not a valid absolute time. Example: \"Nov 12, 1999 08:55:44.123\" or \"2011-07-04 12:34:56\"",
		    s);
	return FALSE;
}

static gboolean
absolute_val_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	return absolute_val_from_string(fv, s, logfunc);
}

static void
time_fvalue_new(fvalue_t *fv)
{
	fv->value.time.secs = 0;
	fv->value.time.nsecs = 0;
}

static void
time_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(!already_copied);
	memcpy(&(fv->value.time), value, sizeof(nstime_t));
}

static gpointer
value_get(fvalue_t *fv)
{
	return &(fv->value.time);
}

static int
absolute_val_repr_len(fvalue_t *fv, ftrepr_t rtype _U_)
{
	gchar *rep;

	rep = abs_time_to_str(&fv->value.time, ABSOLUTE_TIME_LOCAL,
	    rtype == FTREPR_DISPLAY);
	return (int)strlen(rep) + 2;	/* 2 for opening and closing quotes */
}

static void
absolute_val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "\"%s\"",
	    abs_time_to_str(&fv->value.time, ABSOLUTE_TIME_LOCAL,
	        rtype == FTREPR_DISPLAY));
}

static int
relative_val_repr_len(fvalue_t *fv, ftrepr_t rtype _U_)
{
	gchar *rep;

	rep = rel_time_to_secs_str(&fv->value.time);
	return (int)strlen(rep);
}

static void
relative_val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	strcpy(buf, rel_time_to_secs_str(&fv->value.time));
}

void
ftype_register_time(void)
{

	static ftype_t abstime_type = {
		FT_ABSOLUTE_TIME,		/* ftype */
		"FT_ABSOLUTE_TIME",		/* name */
		"Date and time",		/* pretty_name */
		0,				/* wire_size */
		time_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		absolute_val_from_unparsed,	/* val_from_unparsed */
		absolute_val_from_string,	/* val_from_string */
		absolute_val_to_repr,		/* val_to_string_repr */
		absolute_val_repr_len,		/* len_string_repr */

		time_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,				/* cmp_bitwise_and */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL
	};
	static ftype_t reltime_type = {
		FT_RELATIVE_TIME,		/* ftype */
		"FT_RELATIVE_TIME",		/* name */
		"Time offset",			/* pretty_name */
		0,				/* wire_size */
		time_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		relative_val_from_unparsed,	/* val_from_unparsed */
		NULL,				/* val_from_string */
		relative_val_to_repr,		/* val_to_string_repr */
		relative_val_repr_len,		/* len_string_repr */

		time_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,				/* cmp_bitwise_and */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL
	};

	ftype_register(FT_ABSOLUTE_TIME, &abstime_type);
	ftype_register(FT_RELATIVE_TIME, &reltime_type);
}
