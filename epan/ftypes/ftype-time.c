/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "ftypes-int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <epan/to_str.h>
#include <wsutil/time_util.h>


static int
cmp_order(const fvalue_t *a, const fvalue_t *b)
{
	return nstime_cmp(&(a->value.time), &(b->value.time));
}

/*
 * Get a nanoseconds value, starting at "p".
 *
 * Returns true on success, false on failure.
 *
 * If successful endptr points to the first invalid character.
 */
static gboolean
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
	if (endptr)
		*endptr = startp + ndigits;
	return TRUE;
}

static gboolean
relative_val_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	const char    *curptr;
	char *endptr;
	gboolean negative = FALSE;

	curptr = s;

	if (*curptr == '-') {
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
		if (!get_nsecs(curptr, &fv->value.time.nsecs, NULL))
			goto fail;
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
	return TRUE;

fail:
	if (err_msg != NULL)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid time.", s);
	return FALSE;
}


/* Returns TRUE if 's' starts with an abbreviated month name. */
static gboolean
parse_month_name(const char *s, int *tm_mon)
{
	const char *months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	for (int i = 0; i < 12; i++) {
		if (g_ascii_strncasecmp(s, months[i], 3) == 0) {
			*tm_mon = i;
			return TRUE;
		}
	}
	return FALSE;
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

#define EXAMPLE "Example: \"Nov 12, 1999 08:55:44.123\" or \"2011-07-04 12:34:56\""

static gboolean
absolute_val_from_string(fvalue_t *fv, const char *s, size_t len _U_, char **err_msg_ptr)
{
	struct tm tm;
	const char *curptr = NULL;
	const char *endptr;
	gboolean has_seconds = TRUE;
	char *err_msg = NULL;

	/* Try ISO 8601 format first. */
	if (iso8601_to_nstime(&fv->value.time, s, ISO8601_DATETIME) == strlen(s))
		return TRUE;

	/* Try other legacy formats. */
	memset(&tm, 0, sizeof(tm));

	if (strlen(s) < sizeof("2000-1-1") - 1)
		goto fail;

	/* Do not use '%b' to parse the month name, it is locale-specific. */
	if (s[3] == ' ' && parse_month_name(s, &tm.tm_mon))
		curptr = ws_strptime(s + 4, "%d, %Y %H:%M:%S", &tm);

	if (curptr == NULL) {
		has_seconds = FALSE;
		curptr = ws_strptime(s,"%Y-%m-%d %H:%M", &tm);
	}
	if (curptr == NULL)
		curptr = ws_strptime(s,"%Y-%m-%d %H", &tm);
	if (curptr == NULL)
		curptr = ws_strptime(s,"%Y-%m-%d", &tm);
	if (curptr == NULL)
		goto fail;
	tm.tm_isdst = -1;	/* let the computer figure out if it's DST */

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

	/* Skip whitespace */
	while (g_ascii_isspace(*curptr)) {
		curptr++;
	}

	/* Do we have a Timezone? */
	if (strcmp(curptr, "UTC") == 0) {
		curptr += strlen("UTC");
		if (*curptr == '\0') {
			/* It's UTC */
			fv->value.time.secs = mktime_utc(&tm);
			goto done;
		}
		else {
			err_msg = ws_strdup("Unexpected data after time value.");
			goto fail;
		}
	}
	if (*curptr == '\0') {
		/* Local time */
		fv->value.time.secs = mktime(&tm);
		goto done;
	}
	else {
		err_msg = ws_strdup("Unexpected data after time value.");
		goto fail;
	}

done:
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

	return TRUE;

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

	return FALSE;
}

static gboolean
absolute_val_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	return absolute_val_from_string(fv, s, 0, err_msg);
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
	int nsecs;
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

	nsecs = nstime->nsecs;
	while (nsecs > 0 && (nsecs % 10) == 0) {
		nsecs /= 10;
	}
	snprintf(nsecs_buf, sizeof(nsecs_buf), ".%d", nsecs);

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
			rep = abs_time_to_str_ex(scope, &fv->value.time,
					field_display, ABS_TIME_TO_STR_SHOW_ZONE);
			break;

		case FTREPR_DFILTER:
			/* Only ABSOLUTE_TIME_LOCAL and ABSOLUTE_TIME_UTC
			 * are supported. Normalize the field_display value. */
			if (field_display != ABSOLUTE_TIME_LOCAL)
				field_display = ABSOLUTE_TIME_UTC;
			rep = abs_time_to_ftrepr_dfilter(scope, &fv->value.time, field_display != ABSOLUTE_TIME_LOCAL);
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

static gboolean
time_is_zero(const fvalue_t *fv)
{
	return nstime_is_zero(&fv->value.time);
}

static gboolean
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

static enum ft_result
time_add(fvalue_t * dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr _U_)
{
	nstime_sum(&dst->value.time, &a->value.time, &b->value.time);
	return FT_OK;
}

static enum ft_result
time_subtract(fvalue_t * dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr _U_)
{
	nstime_delta(&dst->value.time, &a->value.time, &b->value.time);
	return FT_OK;
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
		time_fvalue_copy,		/* copy_value */
		NULL,				/* free_value */
		absolute_val_from_literal,	/* val_from_literal */
		absolute_val_from_string,	/* val_from_string */
		NULL,				/* val_from_charconst */
		absolute_val_to_repr,		/* val_to_string_repr */

		{ .set_value_time = time_fvalue_set },	/* union set_value */
		{ .get_value_time = value_get },	/* union get_value */

		cmp_order,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		time_is_zero,			/* is_zero */
		NULL,				/* is_negative */
		NULL,
		NULL,
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};
	static ftype_t reltime_type = {
		FT_RELATIVE_TIME,		/* ftype */
		"FT_RELATIVE_TIME",		/* name */
		"Time offset",			/* pretty_name */
		0,				/* wire_size */
		time_fvalue_new,		/* new_value */
		time_fvalue_copy,		/* copy_value */
		NULL,				/* free_value */
		relative_val_from_literal,	/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		relative_val_to_repr,		/* val_to_string_repr */

		{ .set_value_time = time_fvalue_set },	/* union set_value */
		{ .get_value_time = value_get },	/* union get_value */

		cmp_order,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		time_is_zero,			/* is_zero */
		time_is_negative,		/* is_negative */
		NULL,
		NULL,
		NULL,				/* bitwise_and */
		time_unary_minus,		/* unary_minus */
		time_add,			/* add */
		time_subtract,			/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
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
