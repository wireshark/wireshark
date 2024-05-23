/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define _GNU_SOURCE
#include "config.h"
#include "ftypes-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <epan/to_str.h>
#include <wsutil/time_util.h>
#include <wsutil/ws_strptime.h>
#include <wsutil/safe-math.h>


static enum ft_result
cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
	*cmp = nstime_cmp(&(a->value.time), &(b->value.time));
	return FT_OK;
}

/*
 * Get a nanoseconds value, starting at "p".
 *
 * Returns true on success, false on failure.
 *
 * If successful endptr points to the first invalid character.
 */
static bool
get_nsecs(const char *startp, int *nsecs, const char **endptr)
{
	int ndigits = 0;
	int scale;
	const char *p;
	int val;
	int digit;
	int i;

	/*
	 * How many digits are in the string?
	 */
	for (p = startp; g_ascii_isdigit(*p); p++)
		ndigits++;

	/*
	 * If there are N characters in the string, the last of the
	 * characters would be the digit corresponding to 10^(9-N)
	 * nanoseconds.
	 */
	scale = 9 - ndigits;

	/*
	 * Start at the last character, and work backwards.
	 */
	val = 0;
	while (p != startp) {
		p--;

		if (!g_ascii_isdigit(*p)) {
			/*
			 * Not a digit - error.
			 */
			return false;
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
				return false;
			for (i = 0; i < scale; i++)
				digit *= 10;
			val += digit;
		}
		scale++;
	}
	*nsecs = val;
	if (endptr)
		*endptr = startp + ndigits;
	return true;
}

static bool
val_from_unix_time(fvalue_t *fv, const char *s)
{
	const char    *curptr;
	char *endptr;
	bool negative = false;

	curptr = s;

	if (*curptr == '-') {
		negative = true;
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
			return false;
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
		if (!get_nsecs(curptr, &fv->value.time.nsecs, NULL))
			return false;
	} else {
		/*
		 * No nanoseconds value - it's 0.
		 */
		fv->value.time.nsecs = 0;
	}

	if (negative) {
		fv->value.time.secs = -fv->value.time.secs;
		fv->value.time.nsecs = -fv->value.time.nsecs;
	}
	return true;
}

static bool
relative_val_from_uinteger64(fvalue_t *fv, const char *s _U_, uint64_t value, char **err_msg _U_)
{
	fv->value.time.secs = (time_t)value;
	fv->value.time.nsecs = 0;
	return true;
}

static bool
relative_val_from_sinteger64(fvalue_t *fv, const char *s _U_, int64_t value, char **err_msg _U_)
{
	fv->value.time.secs = (time_t)value;
	fv->value.time.nsecs = 0;
	return true;
}

static bool
relative_val_from_float(fvalue_t *fv, const char *s, double value, char **err_msg _U_)
{
	if (val_from_unix_time(fv, s))
		return true;

	double whole, fraction;

	fraction = modf(value, &whole);
	fv->value.time.secs = (time_t)whole;
	fv->value.time.nsecs = (int)(fraction * 1000000000);
	return true;
}

/*
 * Parses an absolute time value from a string. The string can have
 * a UTC time zone suffix. In that case it is interpreted in UTC. Otherwise
 * it is interpreted in local time.
 *
 * OS-dependent; e.g., on 32 bit versions of Windows when compiled to use
 * _mktime32 treats dates before January 1, 1970 as invalid.
 * (https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/mktime-mktime32-mktime64)
 */

/*
 * Timezone support:
 *
     %z    an ISO 8601, RFC-2822, or RFC-3339 time zone specification.  (A
           NetBSD extension.)  This is one of the following:
                 -   The offset from Coordinated Universal Time (`UTC') speci-
                     fied as:
                           ·   [+-]hhmm
                           ·   [+-]hh:mm
                           ·   [+-]hh
                 -   `UTC' specified as:
                           ·   UTC (`Coordinated Universal Time')
                           ·   GMT (`Greenwich Mean Time')
                           ·   UT (`Universal Time')
                           ·   Z (`Zulu Time')
                 -   A three character US time zone specified as:
                           ·   EDT
                           ·   EST
                           ·   CDT
                           ·   CST
                           ·   MDT
                           ·   MST
                           ·   PDT
                           ·   PST
                     with the first letter standing for `Eastern' (``E''),
                     `Central' (``C''), `Mountain' (``M'') or `Pacific'
                     (``P''), and the second letter standing for `Daylight'
                     (``D'' or summer) time or `Standard' (``S'') time
                 -   a single letter military or nautical time zone specified
                     as:
                           ·   ``A'' through ``I''
                           ·   ``K'' through ``Y''
                           ·   ``J'' (non-nautical local time zone)

     %Z    time zone name or no characters when time zone information is
           unavailable.  (A NetBSD extension.)
*/

/*
 * POSIX and C11 calendar time APIs are limited, poorly documented and have
 * loads of bagage and surprising behavior and quirks (most stemming from
 * the fact that the struct tm argument is sometimes both input and output).
 * See the following reference for a reliable method of handling arbitrary timezones:
 *    C: Converting struct tm times with timezone to time_t
 *    http://kbyanc.blogspot.com/2007/06/c-converting-struct-tm-times-with.html
 * Relevant excerpt:
 *    "However, if your libc implements both tm_gmtoff and timegm(3) you are
 *    in luck. You just need to use timegm(3) to get the time_t representing
 *    the time in GMT and then subtract the offset stored in tm_gmtoff.
 *    The tricky part is that calling timegm(3) will modify the struct tm,
 *    clearing the tm_gmtoff field to zero."
 */

#define EXAMPLE "Example: \"Nov 12, 1999 08:55:44.123\" or \"2011-07-04 12:34:56\""

static bool
absolute_val_from_string(fvalue_t *fv, const char *s, size_t len _U_, char **err_msg_ptr)
{
	struct tm tm;
	const char *bufptr, *curptr = NULL;
	const char *endptr;
	bool has_seconds = true;
	bool has_timezone = true;
	char *err_msg = NULL;
	struct ws_timezone zoneinfo = { 0, NULL };

	/* Try Unix time first. */
	if (val_from_unix_time(fv, s))
		return true;

	/* Try ISO 8601 format. */
	endptr = iso8601_to_nstime(&fv->value.time, s, ISO8601_DATETIME);
	/* Check whether it parsed all of the string */
	if (endptr != NULL && *endptr == '\0')
		return true;

	/* No - try other legacy formats. */
	memset(&tm, 0, sizeof(tm));
	/* Let the computer figure out if it's DST. */
	tm.tm_isdst = -1;

	/* Parse the date. ws_strptime() always uses the "C" locale. */
	bufptr = s;
	curptr = ws_strptime(bufptr, "%b %d, %Y", &tm, &zoneinfo);
	if (curptr == NULL)
		curptr = ws_strptime(bufptr,"%Y-%m-%d", &tm, &zoneinfo);
	if (curptr == NULL)
		goto fail;

	/* Parse the time, it is optional. */
	bufptr = curptr;
	curptr = ws_strptime(bufptr, " %H:%M:%S", &tm, &zoneinfo);
	if (curptr == NULL) {
		has_seconds = false;
		/* Seconds can be omitted but minutes (and hours) are required
		 * for a valid time value. */
		curptr = ws_strptime(bufptr," %H:%M", &tm, &zoneinfo);
	}
	if (curptr == NULL)
		curptr = bufptr;

	if (*curptr == '.') {
		/* Nanoseconds */
		if (!has_seconds) {
			err_msg = ws_strdup("Subsecond precision requires a seconds field.");
			goto fail;	/* Requires seconds */
		}
		curptr++;	/* skip the "." */
		if (!g_ascii_isdigit((unsigned char)*curptr)) {
			/* not a digit, so not valid */
			err_msg = ws_strdup("Subseconds value is not a number.");
			goto fail;
		}
		if (!get_nsecs(curptr, &fv->value.time.nsecs, &endptr)) {
			err_msg = ws_strdup("Subseconds value is invalid.");
			goto fail;
		}
		curptr = endptr;
	}
	else {
		/*
		 * No nanoseconds value - it's 0.
		 */
		fv->value.time.nsecs = 0;
	}

	/* Timezone */
	bufptr = curptr;
	curptr = ws_strptime(bufptr, "%n%z", &tm, &zoneinfo);
	if (curptr == NULL) {
		/* No timezone, assume localtime. */
		has_timezone = false;
		curptr = bufptr;
	}

	/* Skip whitespace */
	while (g_ascii_isspace(*curptr)) {
		curptr++;
	}

	if (*curptr != '\0') {
		err_msg = ws_strdup("Unexpected data after time value.");
		goto fail;
	}

	if (has_timezone) {
		/* Convert our calendar time (presumed in UTC, possibly with
		 * an extra timezone offset correction datum) to epoch time. */
		fv->value.time.secs = mktime_utc(&tm);
	}
	else {
		/* Convert our calendar time (in the local timezone) to epoch time. */
		fv->value.time.secs = mktime(&tm);
	}
	if (fv->value.time.secs == (time_t)-1) {
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
		err_msg = ws_strdup_printf("\"%s\" cannot be converted to a valid calendar time.", s);
		goto fail;
	}

	if (has_timezone) {
		/* Normalize to UTC with the offset we have saved. */
		fv->value.time.secs -= zoneinfo.tm_gmtoff;
	}

	return true;

fail:
	if (err_msg_ptr != NULL) {
		if (err_msg == NULL) {
			*err_msg_ptr = ws_strdup_printf("\"%s\" is not a valid absolute time. " EXAMPLE, s);
		}
		else {
			*err_msg_ptr = err_msg;
		}
	}
	else {
		g_free(err_msg);
	}

	return false;
}

static bool
absolute_val_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
	return absolute_val_from_string(fv, s, 0, err_msg);
}

static bool
absolute_val_from_uinteger64(fvalue_t *fv, const char *s, uint64_t value _U_, char **err_msg)
{
	return absolute_val_from_literal(fv, s, FALSE, err_msg);
}

static bool
absolute_val_from_sinteger64(fvalue_t *fv, const char *s, int64_t value _U_, char **err_msg)
{
	return absolute_val_from_literal(fv, s, FALSE, err_msg);
}

static bool
absolute_val_from_float(fvalue_t *fv, const char *s, double value _U_, char **err_msg)
{
	return absolute_val_from_literal(fv, s, FALSE, err_msg);
}

static void
time_fvalue_new(fvalue_t *fv)
{
	fv->value.time.secs = 0;
	fv->value.time.nsecs = 0;
}

static void
time_fvalue_copy(fvalue_t *dst, const fvalue_t *src)
{
	nstime_copy(&dst->value.time, &src->value.time);
}

static void
time_fvalue_set(fvalue_t *fv, const nstime_t *value)
{
	fv->value.time = *value;
}

static const nstime_t *
value_get(fvalue_t *fv)
{
	return &(fv->value.time);
}

static char *
abs_time_to_ftrepr_dfilter(wmem_allocator_t *scope,
			const nstime_t *nstime, bool use_utc)
{
	struct tm *tm;
	char datetime_format[128];
	char nsecs_buf[32];

	if (use_utc) {
		tm = gmtime(&nstime->secs);
		if (tm != NULL)
			strftime(datetime_format, sizeof(datetime_format), "\"%Y-%m-%d %H:%M:%S%%sZ\"", tm);
		else
			snprintf(datetime_format, sizeof(datetime_format), "Not representable");
	}
	else {
		tm = localtime(&nstime->secs);
		/* Displaying the timezone could be made into a preference. */
		if (tm != NULL)
			strftime(datetime_format, sizeof(datetime_format), "\"%Y-%m-%d %H:%M:%S%%s%z\"", tm);
		else
			snprintf(datetime_format, sizeof(datetime_format), "Not representable");
	}

	if (nstime->nsecs == 0)
		return wmem_strdup_printf(scope, datetime_format, "");

	snprintf(nsecs_buf, sizeof(nsecs_buf), ".%09d", nstime->nsecs);

	return wmem_strdup_printf(scope, datetime_format, nsecs_buf);
}

static char *
absolute_val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display)
{
	char *rep;

	if (field_display == BASE_NONE)
		field_display = ABSOLUTE_TIME_LOCAL;

	switch (rtype) {
		case FTREPR_DISPLAY:
		case FTREPR_JSON:
			rep = abs_time_to_str_ex(scope, &fv->value.time,
					field_display, ABS_TIME_TO_STR_SHOW_ZONE);
			break;

		case FTREPR_DFILTER:
			if (field_display == ABSOLUTE_TIME_UNIX) {
				rep = abs_time_to_unix_str(scope, &fv->value.time);
			}
			else {
				/* Only ABSOLUTE_TIME_LOCAL and ABSOLUTE_TIME_UTC
				 * are supported. Normalize the field_display value. */
				if (field_display != ABSOLUTE_TIME_LOCAL)
					field_display = ABSOLUTE_TIME_UTC;
				rep = abs_time_to_ftrepr_dfilter(scope, &fv->value.time, field_display != ABSOLUTE_TIME_LOCAL);
			}
			break;

		default:
			ws_assert_not_reached();
			break;
	}

	return rep;
}

static char *
relative_val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	return rel_time_to_secs_str(scope, &fv->value.time);
}

static unsigned
time_hash(const fvalue_t *fv)
{
	return nstime_hash(&fv->value.time);
}

static bool
time_is_zero(const fvalue_t *fv)
{
	return nstime_is_zero(&fv->value.time);
}

static bool
time_is_negative(const fvalue_t *fv)
{
	return fv->value.time.secs < 0;
}

static enum ft_result
time_unary_minus(fvalue_t * dst, const fvalue_t *src, char **err_ptr _U_)
{
	dst->value.time.secs = -src->value.time.secs;
	dst->value.time.nsecs = -src->value.time.nsecs;
	return FT_OK;
}

#define NS_PER_S 1000000000

static void
check_ns_wraparound(nstime_t *ns, jmp_buf env)
{
	while(ns->nsecs >= NS_PER_S || (ns->nsecs > 0 && ns->secs < 0)) {
		ws_safe_sub_jmp(&ns->nsecs, ns->nsecs, NS_PER_S, env);
		ws_safe_add_jmp(&ns->secs, ns->secs, 1, env);
	}
	while (ns->nsecs <= -NS_PER_S || (ns->nsecs < 0 && ns->secs > 0)) {
		ws_safe_add_jmp(&ns->nsecs, ns->nsecs, NS_PER_S, env);
		ws_safe_sub_jmp(&ns->secs, ns->secs, 1, env);
	}
}

static void
_nstime_add(nstime_t *res, nstime_t a, const nstime_t b, jmp_buf env)
{
	ws_safe_add_jmp(&res->secs, a.secs, b.secs, env);
	ws_safe_add_jmp(&res->nsecs, a.nsecs, b.nsecs, env);
	check_ns_wraparound(res, env);
}

static enum ft_result
time_add(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	jmp_buf env;
	if (setjmp(env) != 0) {
		*err_ptr = ws_strdup_printf("time_add: overflow");
		return FT_ERROR;
	}
	_nstime_add(&dst->value.time, a->value.time, b->value.time, env);
	return FT_OK;
}

static void
_nstime_sub(nstime_t *res, nstime_t a, const nstime_t b, jmp_buf env)
{
	ws_safe_sub_jmp(&res->secs, a.secs, b.secs, env);
	ws_safe_sub_jmp(&res->nsecs, a.nsecs, b.nsecs, env);
	check_ns_wraparound(res, env);
}

static enum ft_result
time_subtract(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	jmp_buf env;
	if (setjmp(env) != 0) {
		*err_ptr = ws_strdup_printf("time_subtract: overflow");
		return FT_ERROR;
	}
	_nstime_sub(&dst->value.time, a->value.time, b->value.time, env);
	return FT_OK;
}

static void
_nstime_mul_int(nstime_t *res, nstime_t a, int64_t val, jmp_buf env)
{
	ws_safe_mul_jmp(&res->secs, a.secs, (time_t)val, env);
	ws_safe_mul_jmp(&res->nsecs, a.nsecs, (int)val, env);
	check_ns_wraparound(res, env);
}

static void
_nstime_mul_float(nstime_t *res, nstime_t a, double val, jmp_buf env)
{
	res->secs = (time_t)(a.secs * val);
	res->nsecs = (int)(a.nsecs * val);
	check_ns_wraparound(res, env);
}

static enum ft_result
time_multiply(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	jmp_buf env;
	if (setjmp(env) != 0) {
		*err_ptr = ws_strdup_printf("time_subtract: overflow");
		return FT_ERROR;
	}

	ftenum_t ft_b = fvalue_type_ftenum(b);
	if (ft_b == FT_INT64) {
		int64_t val = fvalue_get_sinteger64((fvalue_t *)b);
		_nstime_mul_int(&dst->value.time, a->value.time, val, env);
	}
	else if (ft_b == FT_DOUBLE) {
		double val = fvalue_get_floating((fvalue_t *)b);
		_nstime_mul_float(&dst->value.time, a->value.time, val, env);
	}
	else {
		ws_critical("Invalid RHS ftype: %s", ftype_pretty_name(ft_b));
		return FT_BADARG;
	}
	return FT_OK;
}

static void
_nstime_div_int(nstime_t *res, nstime_t a, int64_t val, jmp_buf env)
{
	ws_safe_div_jmp(&res->secs, a.secs, (time_t)val, env);
	ws_safe_div_jmp(&res->nsecs, a.nsecs, (int)val, env);
}

static void
_nstime_div_float(nstime_t *res, nstime_t a, double val)
{
	res->secs = (time_t)(a.secs / val);
	res->nsecs = (int)(a.nsecs / val);
}

static enum ft_result
time_divide(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	jmp_buf env;
	if (setjmp(env) != 0) {
		*err_ptr = ws_strdup_printf("time_divide: overflow");
		return FT_ERROR;
	}

	ftenum_t ft_b = fvalue_type_ftenum(b);
	if (ft_b == FT_INT64) {
		int64_t val = fvalue_get_sinteger64((fvalue_t *)b);
		if (val == 0) {
			*err_ptr = ws_strdup_printf("time_divide: division by zero");
			return FT_ERROR;
		}
		_nstime_div_int(&dst->value.time, a->value.time, val, env);
	}
	else if (ft_b == FT_DOUBLE) {
		double val = fvalue_get_floating((fvalue_t *)b);
		if (val == 0) {
			*err_ptr = ws_strdup_printf("time_divide: division by zero");
			return FT_ERROR;
		}
		_nstime_div_float(&dst->value.time, a->value.time, val);
	}
	else {
		ws_critical("Invalid RHS ftype: %s", ftype_pretty_name(ft_b));
		return FT_BADARG;
	}
	return FT_OK;
}

void
ftype_register_time(void)
{

	static const ftype_t abstime_type = {
		FT_ABSOLUTE_TIME,		/* ftype */
		0,				/* wire_size */
		time_fvalue_new,		/* new_value */
		time_fvalue_copy,		/* copy_value */
		NULL,				/* free_value */
		absolute_val_from_literal,	/* val_from_literal */
		absolute_val_from_string,	/* val_from_string */
		NULL,				/* val_from_charconst */
		absolute_val_from_uinteger64,	/* val_from_uinteger64 */
		absolute_val_from_sinteger64,	/* val_from_sinteger64 */
		absolute_val_from_float,	/* val_from_double */
		absolute_val_to_repr,		/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_from_double */

		{ .set_value_time = time_fvalue_set },	/* union set_value */
		{ .get_value_time = value_get },	/* union get_value */

		cmp_order,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		time_hash,			/* hash */
		time_is_zero,			/* is_zero */
		time_is_negative,		/* is_negative */
		NULL,
		NULL,
		NULL,				/* bitwise_and */
		time_unary_minus,		/* unary_minus */
		time_add,			/* add */
		time_subtract,			/* subtract */
		time_multiply,			/* multiply */
		time_divide,			/* divide */
		NULL,				/* modulo */
	};
	static const ftype_t reltime_type = {
		FT_RELATIVE_TIME,		/* ftype */
		0,				/* wire_size */
		time_fvalue_new,		/* new_value */
		time_fvalue_copy,		/* copy_value */
		NULL,				/* free_value */
		NULL,				/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		relative_val_from_uinteger64,	/* val_from_uinteger64 */
		relative_val_from_sinteger64,	/* val_from_sinteger64 */
		relative_val_from_float,	/* val_from_double */
		relative_val_to_repr,		/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_from_double */

		{ .set_value_time = time_fvalue_set },	/* union set_value */
		{ .get_value_time = value_get },	/* union get_value */

		cmp_order,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		time_hash,			/* hash */
		time_is_zero,			/* is_zero */
		time_is_negative,		/* is_negative */
		NULL,
		NULL,
		NULL,				/* bitwise_and */
		time_unary_minus,		/* unary_minus */
		time_add,			/* add */
		time_subtract,			/* subtract */
		time_multiply,			/* multiply */
		time_divide,			/* divide */
		NULL,				/* modulo */
	};

	ftype_register(FT_ABSOLUTE_TIME, &abstime_type);
	ftype_register(FT_RELATIVE_TIME, &reltime_type);
}

void
ftype_register_pseudofields_time(int proto)
{
	static int hf_ft_rel_time;
	static int hf_ft_abs_time;

	static hf_register_info hf_ftypes[] = {
		{ &hf_ft_abs_time,
		    { "FT_ABSOLUTE_TIME", "_ws.ftypes.abs_time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_rel_time,
		    { "FT_RELATIVE_TIME", "_ws.ftypes.rel_time",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
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
